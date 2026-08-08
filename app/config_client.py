# Vendored from opteryx-config-client -- do not edit here.
# Re-sync with: opteryx-config-client/vendor.sh <this-repo>
"""Client for the Opteryx platform configuration service (config.opteryx.app).

Resolution hierarchy for every lookup:

1. The process's own environment variables — a value set in the service's
   ENVVARs always wins, so per-service overrides keep working.
2. The remote configuration document for this environment, cached for at
   most 60 seconds.
3. The ``default`` supplied by the caller.

Usage::

    from opteryx_config import get_config

    AUTH_URL = get_config("AUTH_URL", default="https://authenticate.opteryx.app")

Authentication is Google OIDC. config.opteryx.app is deployed IAM-private and
each calling service's service account holds ``roles/run.invoker``; this client
mints an identity token from the GCP metadata server (or from Application
Default Credentials when running outside Cloud Run). There is no secret to
store, distribute, or rotate.

Environment:

- ``OPTERYX_ENVIRONMENT`` — the environment (GCP project) name. Falls back to
  ``GCP_PROJECT_ID`` / ``GCP_PROJECT`` / ``GOOGLE_CLOUD_PROJECT``.
- ``CONFIG_URL`` — config service URL (default ``https://config.opteryx.app``).
- ``CONFIG_AUDIENCE`` — OIDC audience (defaults to ``CONFIG_URL``).
- ``OPTERYX_SERVICE_TOKEN`` — an explicit token that bypasses OIDC minting.
  Intended for local development and tests only.

The client is deliberately fail-open: if the config service is unreachable it
serves the last-known values (even if stale) and otherwise the caller's
default, so a config-service outage cannot take down the fleet.
"""

import base64
import binascii
import json
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, Optional

import requests

CACHE_TTL_SECONDS = 60.0
_REQUEST_TIMEOUT_SECONDS = 10.0  # generous, to allow for Cloud Run cold starts
_TOKEN_REFRESH_MARGIN_SECONDS = 300.0  # refresh 5 minutes before expiry

_UNSET = object()

ENV = "env"          # value came from the process's own environment
CONFIG = "config"    # value came from the remote configuration document
DEFAULT = "default"  # value came from the caller's fallback

logger = logging.getLogger("opteryx.config_client")


_METADATA_URL = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
_METADATA_PROJECT: Any = _UNSET  # cached; the project never changes for a process


def _metadata_project() -> Optional[str]:
    """Ask the GCP metadata server for the project id.

    Cloud Run always provides this, so a service needs no environment variable
    to identify its own environment. Mirrors the approach the services already
    use in their `secret_store` modules. The result is cached, including
    failures, so a non-GCP host pays the timeout at most once.
    """
    global _METADATA_PROJECT
    if _METADATA_PROJECT is not _UNSET:
        return _METADATA_PROJECT

    project = None
    try:
        response = requests.get(
            _METADATA_URL, headers={"Metadata-Flavor": "Google"}, timeout=0.5
        )
        if response.status_code == 200:
            project = response.text.strip() or None
    except requests.RequestException:
        project = None

    _METADATA_PROJECT = project
    return project


def _detect_environment() -> Optional[str]:
    return (
        os.environ.get("OPTERYX_ENVIRONMENT")
        or os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GCP_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or _metadata_project()
    )


def _token_expiry(token: str) -> Optional[float]:
    """Read ``exp`` from a JWT without verifying it.

    The token is one we just minted for ourselves, so this is only used to
    decide when to refresh -- never as a trust decision.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except (IndexError, KeyError, ValueError, TypeError, binascii.Error):
        return None


def _rejection_reason(response: "requests.Response") -> str:
    """Say who rejected the request and why, from the response body.

    A 401 or 403 can come from two very different places, needing different
    fixes: Cloud Run's IAM layer rejecting before the container is reached, or
    the config service's own identity verification. Cloud Run returns an HTML
    error page; the service returns JSON `{"detail": ...}`. Distinguishing them
    is the difference between fixing an IAM grant and fixing an audience.
    """
    try:
        payload = response.json()
    except ValueError:
        return "rejected before reaching the service (no JSON body)"
    if isinstance(payload, dict) and payload.get("detail"):
        return f"service said {str(payload['detail'])[:120]!r}"
    return "no detail in response"


class ConfigClient:
    """Fetches and caches an environment's configuration document."""

    def __init__(
        self,
        environment: Optional[str] = None,
        config_url: Optional[str] = None,
        audience: Optional[str] = None,
        token_provider: Optional[Callable[[], Optional[str]]] = None,
        cache_ttl: float = CACHE_TTL_SECONDS,
    ):
        self._environment = environment
        self._config_url = config_url
        self._audience = audience
        self._token_provider = token_provider
        self._cache_ttl = cache_ttl
        self._lock = threading.Lock()
        self._values: Dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._sources: Dict[str, str] = {}
        self._last_fetch_ok: Optional[bool] = None
        self._last_fetch_detail: str = "no fetch attempted"

    @property
    def environment(self) -> Optional[str]:
        return self._environment or _detect_environment()

    @property
    def config_url(self) -> str:
        configured = self._config_url or os.environ.get("CONFIG_URL", "https://config.opteryx.app")
        return configured.rstrip("/")

    @property
    def audience(self) -> str:
        return self._audience or os.environ.get("CONFIG_AUDIENCE") or self.config_url

    def set_token_provider(self, provider: Callable[[], Optional[str]]) -> None:
        """Override how tokens are obtained. Rarely needed; OIDC is automatic."""
        self._token_provider = provider

    def _mint_identity_token(self) -> Optional[str]:
        """Mint a Google OIDC identity token for the config service."""
        try:
            import google.auth.transport.requests  # type: ignore
            from google.oauth2 import id_token  # type: ignore

            return id_token.fetch_id_token(
                google.auth.transport.requests.Request(), self.audience
            )
        except Exception:
            # No metadata server and no usable ADC -- e.g. local development.
            return None

    def _current_token(self) -> Optional[str]:
        if self._token_provider is not None:
            return self._token_provider()

        override = os.environ.get("OPTERYX_SERVICE_TOKEN")
        if override:
            return override

        now = time.time()
        if self._token and now < self._token_expires_at:
            return self._token

        token = self._mint_identity_token()
        if token:
            expiry = _token_expiry(token)
            # Without a readable exp, re-mint on every fetch rather than guess.
            self._token_expires_at = (
                expiry - _TOKEN_REFRESH_MARGIN_SECONDS if expiry else 0.0
            )
            self._token = token
        return token

    def _fetch(self) -> None:
        """Refresh the cached document; on failure keep serving the last-known values."""
        environment = self.environment
        if not environment:
            self._last_fetch_ok = False
            self._last_fetch_detail = "no environment detected"
            self._fetched_at = time.monotonic()
            return

        token = self._current_token()
        if not token:
            # Not running with credentials; env vars and defaults still work.
            self._last_fetch_ok = False
            self._last_fetch_detail = "no identity token could be obtained"
            self._fetched_at = time.monotonic()
            return

        try:
            response = requests.get(
                f"{self.config_url}/v1/config/{environment}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code == 200:
                self._values = response.json().get("values", {})
                self._last_fetch_ok = True
                self._last_fetch_detail = f"ok, {len(self._values)} keys"
            elif response.status_code == 404:
                self._values = {}
                self._last_fetch_ok = True
                self._last_fetch_detail = "environment has no configuration document"
            else:
                self._last_fetch_ok = False
                self._last_fetch_detail = (
                    f"HTTP {response.status_code}: {_rejection_reason(response)}"
                )
                if response.status_code in (401, 403):
                    # Token may have gone stale; drop it so the next re-mints.
                    self._token = None
                    self._token_expires_at = 0.0
        except requests.RequestException as exc:
            # Serve stale values rather than failing the caller.
            self._last_fetch_ok = False
            self._last_fetch_detail = f"{type(exc).__name__}: {exc}"

        if not self._last_fetch_ok:
            # Logs are private, so unlike the diagnostics response these may
            # name the URL and audience -- the two things a rejection usually
            # comes down to.
            logger.warning(
                "config fetch failed: %s (environment=%s url=%s audience=%s)",
                self._last_fetch_detail,
                environment,
                self.config_url,
                self.audience,
            )
        self._fetched_at = time.monotonic()

    def _remote_values(self) -> Dict[str, Any]:
        with self._lock:
            # `_fetched_at` starts at zero, so the first lookup always fetches.
            # It is stamped on every attempt including failures, so an outage
            # is retried once per TTL rather than on every single lookup.
            if time.monotonic() - self._fetched_at >= self._cache_ttl:
                self._fetch()
            return self._values

    def _resolve(self, key: str, default: Any = None) -> tuple[Any, str]:
        """Resolve a value and report which layer of the hierarchy supplied it."""
        env_value = os.environ.get(key, _UNSET)
        if env_value is not _UNSET:
            return env_value, ENV
        remote = self._remote_values()
        if key in remote:
            return remote[key], CONFIG
        return default, DEFAULT

    def _record_source(self, key: str, source: str) -> None:
        """Log the first time a key resolves, and whenever its source changes.

        This is what makes a migration observable: once a service stops setting
        a variable in its own ENVVARs, the log line flips from `env` to
        `config`, proving the value is being served by the config service
        rather than merely fetched from it.
        """
        if self._sources.get(key) == source:
            return
        self._sources[key] = source
        logger.info("config %s resolved from %s", key, source)

    def get(self, key: str, default: Any = None) -> Any:
        """Resolve a configuration value: ENVVAR, then remote config, then default."""
        value, source = self._resolve(key, default)
        self._record_source(key, source)
        return value

    def explain(self, key: str, default: Any = None) -> Dict[str, Any]:
        """Return the value for `key` along with which layer supplied it.

        Intended for diagnostics -- during a migration, to confirm a value is
        coming from the config service rather than a lingering ENVVAR.
        """
        value, source = self._resolve(key, default)
        return {"key": key, "value": value, "source": source}

    def status(self) -> Dict[str, Any]:
        """Report how the client is configured and how the last fetch went.

        Contains no configuration values, so it is safe to expose on an
        operational diagnostics endpoint.
        """
        self._remote_values()  # ensure at least one attempt has been made
        age = None if not self._fetched_at else round(time.monotonic() - self._fetched_at, 1)
        return {
            "environment": self.environment,
            "config_url": self.config_url,
            "audience": self.audience,
            "last_fetch_ok": self._last_fetch_ok,
            "last_fetch_detail": self._last_fetch_detail,
            "keys_available": len(self._values),
            "seconds_since_fetch": age,
            "cache_ttl_seconds": self._cache_ttl,
        }

    def compare(self, key: str, default: Any = None) -> Dict[str, Any]:
        """Compare the ENVVAR and remote values for a key WITHOUT revealing them.

        Use this before removing a variable from a service's ENVVARs: when the
        key is present in config and `matches_env` is true, removing the ENVVAR
        cannot change behaviour.
        """
        remote = self._remote_values()
        env_value = os.environ.get(key, _UNSET)
        in_env = env_value is not _UNSET
        in_config = key in remote

        matches_env = None
        if in_env and in_config:
            matches_env = str(env_value) == str(remote[key])

        matches_default = None
        if in_config and default is not None:
            matches_default = str(remote[key]) == str(default)

        # What the process would use if the config service supplied nothing.
        served = self._resolve(key, default)[0]
        without_config = env_value if in_env else default
        return {
            "key": key,
            "source": self._resolve(key, default)[1],
            "in_env": in_env,
            "in_config": in_config,
            "matches_env": matches_env,
            "matches_default": matches_default,
            # True when the config service is changing what this process uses.
            "changes_behaviour": str(served) != str(without_config),
            "safe_to_remove_envvar": bool(in_config and matches_env),
        }

    def sources(self) -> Dict[str, str]:
        """Return the last known resolution source for every key looked up."""
        return dict(self._sources)

    def all(self) -> Dict[str, Any]:
        """Return the remote configuration document (env vars overlaid on top)."""
        merged = dict(self._remote_values())
        for key in merged:
            if key in os.environ:
                merged[key] = os.environ[key]
        return merged

    def refresh(self) -> None:
        """Force a refetch on the next lookup."""
        with self._lock:
            self._fetched_at = 0.0


_default_client = ConfigClient()


def get_config(key: str, default: Any = None) -> Any:
    """Resolve a configuration value using the default client."""
    return _default_client.get(key, default)


def explain_config(key: str, default: Any = None) -> Dict[str, Any]:
    """Return a value plus which layer supplied it (env / config / default)."""
    return _default_client.explain(key, default)


def config_status() -> Dict[str, Any]:
    """Report client configuration and last fetch outcome (contains no values)."""
    return _default_client.status()


def compare_config(key: str, default: Any = None) -> Dict[str, Any]:
    """Compare ENVVAR and remote values for a key without revealing them."""
    return _default_client.compare(key, default)


def config_sources() -> Dict[str, str]:
    """Return the last known resolution source for every key looked up."""
    return _default_client.sources()


def set_token_provider(provider: Callable[[], Optional[str]]) -> None:
    """Override how the default client obtains tokens. Rarely needed."""
    _default_client.set_token_provider(provider)


def refresh() -> None:
    """Force the default client to refetch on the next lookup."""
    _default_client.refresh()


__all__ = [
    "ConfigClient",
    "explain_config",
    "compare_config",
    "config_sources",
    "config_status",
    "get_config",
    "set_token_provider",
    "refresh",
    "CACHE_TTL_SECONDS",
]
