# Vendored from opteryx-config-client -- do not edit here.
# Re-sync with: opteryx-config-client/vendor.sh <this-repo>
"""Client for Opteryx platform configuration.

Configuration lives in Firestore at ``(default)/config/<environment>``, one
document per environment (in practice the GCP project the service runs in).
This client reads that document directly.

Resolution hierarchy for every lookup:

1. The process's own environment variables — a value set in the service's
   ENVVARs always wins, so per-service overrides keep working.
2. The configuration document for this environment, read at boot and cached
   for at most 5 minutes.
3. The ``default`` supplied by the caller.

Usage::

    from opteryx_config import get_config

    AUTH_URL = get_config("AUTH_URL", default="https://authenticate.opteryx.app")

Access is Firestore IAM: the service account needs read on the ``(default)``
database (``roles/datastore.viewer``). There is no token to mint, no audience
to agree on, and no intermediate service to be unavailable — the read is one
gRPC call on a client the service is already holding open.

The document is read once at import, so the first lookup does not pay for it.
Set ``OPTERYX_CONFIG_EAGER=false`` to skip that and fetch lazily instead.

Environment:

- ``OPTERYX_ENVIRONMENT`` — the environment (GCP project) name, which is the
  document id. Falls back to ``GCP_PROJECT_ID`` / ``GCP_PROJECT`` /
  ``GOOGLE_CLOUD_PROJECT``, then to the GCP metadata server.
- ``CONFIG_PROJECT`` — the GCP project whose Firestore holds the configuration
  document. Defaults to the service's own project, which is correct whenever
  the service reads the configuration for the project it runs in.
- ``OPTERYX_CONFIG_EAGER`` — set to ``false`` to skip the read at import.

The client is deliberately fail-open: if Firestore is unreachable it serves the
last-known values (even if stale) and otherwise the caller's default, so a
Firestore blip cannot take down the fleet.
"""

import logging
import os
import threading
import time
import urllib.request
from typing import Any, Callable, Dict, Optional

CACHE_TTL_SECONDS = 300.0

# Bounds the read itself. The document is read at import, so an unbounded call
# against an unreachable Firestore would hang container startup rather than
# fail open.
READ_TIMEOUT_SECONDS = 10.0

COLLECTION = "config"
DATABASE = "(default)"

_UNSET = object()

ENV = "env"          # value came from the process's own environment
CONFIG = "config"    # value came from the configuration document
DEFAULT = "default"  # value came from the caller's fallback

logger = logging.getLogger("opteryx.config_client")


_METADATA_URL = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
_METADATA_TIMEOUT_SECONDS = 0.5
# How long a failed probe is trusted before trying again. A success is cached
# for the life of the process -- the project genuinely never changes -- but a
# failure must expire: see `_metadata_project`.
_METADATA_RETRY_SECONDS = 30.0

_METADATA_PROJECT: Any = _UNSET  # cached; the project never changes for a process
_METADATA_FAILED_AT: Optional[float] = None


def reset_metadata_cache() -> None:
    """Forget the cached project id, successful or not."""
    global _METADATA_PROJECT, _METADATA_FAILED_AT
    _METADATA_PROJECT = _UNSET
    _METADATA_FAILED_AT = None


def _metadata_project() -> Optional[str]:
    """Ask the GCP metadata server for the project id.

    Cloud Run always provides this, so a service needs no environment variable
    to identify its own environment. Mirrors the approach the services already
    use in their `secret_store` modules.

    A SUCCESS is cached for the life of the process; the project never changes.
    A FAILURE is cached only for `_METADATA_RETRY_SECONDS`. It used to be cached
    forever, on the reasoning that a non-GCP host should pay the timeout at most
    once -- which is right for a host that will never have a metadata server and
    wrong for one that is merely slow to start. The first probe happens at
    import, with half a second of patience, which is the least forgiving moment
    in a container's life; one miss there and `environment` was None for that
    instance forever, every value silently fell back to an ENVVAR or a default,
    and only a new instance recovered.

    Deliberately not `google.auth.default()`: that probes the metadata server
    with a 3-second timeout and three retries, so a host with neither metadata
    nor Application Default Credentials -- CI, a fresh laptop -- blocks for
    around nine seconds. Since the document is read at import, that would be
    nine seconds of startup hang in every service that vendors this module.
    """
    global _METADATA_PROJECT, _METADATA_FAILED_AT
    if _METADATA_PROJECT is not _UNSET and _METADATA_PROJECT is not None:
        return _METADATA_PROJECT
    if _METADATA_FAILED_AT is not None and (
        time.monotonic() - _METADATA_FAILED_AT < _METADATA_RETRY_SECONDS
    ):
        return None

    project = None
    try:
        request = urllib.request.Request(
            _METADATA_URL, headers={"Metadata-Flavor": "Google"}
        )
        # Bypass any configured proxy: the metadata server is link-local, and a
        # proxy that swallows the request turns a fast miss into a slow one.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=_METADATA_TIMEOUT_SECONDS) as response:
            if response.status == 200:
                project = response.read().decode("utf-8").strip() or None
    except Exception:
        # Not on GCP, or the metadata server is unreachable.
        project = None

    _METADATA_PROJECT = project
    _METADATA_FAILED_AT = None if project else time.monotonic()
    return project


def _detect_environment() -> Optional[str]:
    return (
        os.environ.get("OPTERYX_ENVIRONMENT")
        or os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GCP_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or _metadata_project()
    )


class ConfigClient:
    """Reads and caches an environment's configuration document from Firestore."""

    def __init__(
        self,
        environment: Optional[str] = None,
        project: Optional[str] = None,
        cache_ttl: float = CACHE_TTL_SECONDS,
        client_provider: Optional[Callable[[], Any]] = None,
    ):
        self._environment = environment
        self._project = project
        self._cache_ttl = cache_ttl
        self._client_provider = client_provider
        self._lock = threading.Lock()
        self._firestore: Any = None
        self._values: Dict[str, Any] = {}
        # None, not 0.0 -- see `_remote_values`.
        self._fetched_at: Optional[float] = None
        self._sources: Dict[str, str] = {}
        self._last_fetch_ok: Optional[bool] = None
        self._last_fetch_detail: str = "no fetch attempted"

    @property
    def environment(self) -> Optional[str]:
        return self._environment or _detect_environment()

    @property
    def project(self) -> Optional[str]:
        return self._project or os.environ.get("CONFIG_PROJECT") or _metadata_project()

    def set_client_provider(self, provider: Callable[[], Any]) -> None:
        """Supply the Firestore client to read with.

        A service that already holds a ``(default)``-database client can hand it
        over rather than have this module open a second gRPC channel. The
        provider is called once and the result cached.
        """
        with self._lock:
            self._client_provider = provider
            self._firestore = None

    def _client(self) -> Any:
        """Return the Firestore client, creating and caching one if needed."""
        if self._firestore is not None:
            return self._firestore

        if self._client_provider is not None:
            self._firestore = self._client_provider()
            return self._firestore

        from google.cloud import firestore  # type: ignore

        project = self.project
        self._firestore = (
            firestore.Client(project=project, database=DATABASE)
            if project
            else firestore.Client(database=DATABASE)
        )
        return self._firestore

    def _fetch(self) -> None:
        """Refresh the cached document; on failure keep serving the last-known values."""
        environment = self.environment
        if not environment:
            self._last_fetch_ok = False
            self._last_fetch_detail = "no environment detected"
            self._fetched_at = time.monotonic()
            return

        try:
            snapshot = (
                self._client()
                .collection(COLLECTION)
                .document(environment)
                .get(timeout=READ_TIMEOUT_SECONDS)
            )
        except Exception as exc:
            # Serve stale values rather than failing the caller. `_values` is
            # deliberately left untouched.
            self._last_fetch_ok = False
            self._last_fetch_detail = f"{type(exc).__name__}: {exc}"
            # Drop the client so a broken channel is rebuilt on the next attempt.
            self._firestore = None
        else:
            if snapshot.exists:
                values = (snapshot.to_dict() or {}).get("values", {})
                self._values = values if isinstance(values, dict) else {}
                self._last_fetch_ok = True
                self._last_fetch_detail = f"ok, {len(self._values)} keys"
            else:
                # NOT `last_fetch_ok = True`. The gRPC call succeeded, but the
                # caller's question is "is my configuration in effect", and the
                # answer here is no. Reporting success meant a wrong database or
                # a mistyped document id logged nothing, `status()` said the read
                # was fine, and the service served defaults indefinitely while
                # looking healthy. The two likeliest misconfigurations were the
                # two least visible.
                self._values = {}
                self._last_fetch_ok = False
                # Wording deliberately unchanged. Consumers allowlist this exact
                # string as safe to echo (see register.opteryx's `_redact`), and
                # the document path is already available as structured fields on
                # `status()` - putting it in here too would both break those
                # allowlists and push a project name into a field they redact
                # precisely to keep project names out.
                self._last_fetch_detail = "environment has no configuration document"

        if not self._last_fetch_ok:
            logger.warning(
                "config fetch failed: %s (environment=%s project=%s)",
                self._last_fetch_detail,
                environment,
                self.project,
            )
        self._fetched_at = time.monotonic()

    def _remote_values(self) -> Dict[str, Any]:
        with self._lock:
            # `is None` means never fetched. This used to be `_fetched_at = 0.0`
            # and arithmetic alone, on the reasoning that "starts at zero, so the
            # first lookup always fetches" -- which holds only if
            # `time.monotonic()` returns something larger than the TTL. Python
            # documents its reference point as undefined, and a fresh container
            # sandbox starts it near zero, so for the first `cache_ttl` seconds
            # of a container's life the subtraction stayed under the threshold,
            # no read was ever attempted, and the client served an empty
            # document while reporting no error.
            #
            # `_fetched_at` is stamped on every attempt including failures, so an
            # outage is retried once per TTL rather than on every single lookup.
            if (
                self._fetched_at is None
                or time.monotonic() - self._fetched_at >= self._cache_ttl
            ):
                self._fetch()
            return self._values

    def prime(self) -> None:
        """Read the document now, so the first lookup does not pay for it.

        Called at import. Failures are swallowed -- the client is fail-open, and
        a service must still start when Firestore is unreachable.
        """
        try:
            self._remote_values()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("config prime failed: %s", exc)

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
        `config`, proving the value is being served by the configuration
        document rather than merely readable from it.
        """
        if self._sources.get(key) == source:
            return
        self._sources[key] = source
        logger.info("config %s resolved from %s", key, source)

    def get(self, key: str, default: Any = None) -> Any:
        """Resolve a configuration value: ENVVAR, then config document, then default."""
        value, source = self._resolve(key, default)
        self._record_source(key, source)
        return value

    def explain(self, key: str, default: Any = None) -> Dict[str, Any]:
        """Return the value for `key` along with which layer supplied it.

        Intended for diagnostics -- during a migration, to confirm a value is
        coming from the configuration document rather than a lingering ENVVAR.
        """
        value, source = self._resolve(key, default)
        return {"key": key, "value": value, "source": source}

    def status(self) -> Dict[str, Any]:
        """Report how the client is configured and how the last read went.

        Contains no configuration values, so it is safe to expose on an
        operational diagnostics endpoint.
        """
        self._remote_values()  # ensure at least one attempt has been made
        # `is None`, so an age of exactly 0.0 is not reported as "never fetched".
        age = (
            None if self._fetched_at is None else round(time.monotonic() - self._fetched_at, 1)
        )
        return {
            "environment": self.environment,
            "project": self.project,
            "database": DATABASE,
            "collection": COLLECTION,
            "last_fetch_ok": self._last_fetch_ok,
            "last_fetch_detail": self._last_fetch_detail,
            "keys_available": len(self._values),
            "seconds_since_fetch": age,
            "cache_ttl_seconds": self._cache_ttl,
        }

    def compare(self, key: str, default: Any = None) -> Dict[str, Any]:
        """Compare the ENVVAR and config values for a key WITHOUT revealing them.

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

        # What the process would use if the config document supplied nothing.
        served = self._resolve(key, default)[0]
        without_config = env_value if in_env else default
        return {
            "key": key,
            "source": self._resolve(key, default)[1],
            "in_env": in_env,
            "in_config": in_config,
            "matches_env": matches_env,
            "matches_default": matches_default,
            # True when the config document is changing what this process uses.
            "changes_behaviour": str(served) != str(without_config),
            "safe_to_remove_envvar": bool(in_config and matches_env),
        }

    def sources(self) -> Dict[str, str]:
        """Return the last known resolution source for every key looked up."""
        return dict(self._sources)

    def all(self) -> Dict[str, Any]:
        """Return the configuration document (env vars overlaid on top)."""
        merged = dict(self._remote_values())
        for key in merged:
            if key in os.environ:
                merged[key] = os.environ[key]
        return merged

    def refresh(self) -> None:
        """Force a reread on the next lookup.

        Also forgets a failed metadata probe: an environment that could not be
        detected is one of the reasons a caller reaches for this, and resetting
        only the document timer would leave it undetectable.
        """
        reset_metadata_cache()
        with self._lock:
            # None, not 0.0 -- resetting to 0.0 left this unable to force
            # anything at all for the first `cache_ttl` seconds of a container.
            self._fetched_at = None


_default_client = ConfigClient()


def get_config(key: str, default: Any = None) -> Any:
    """Resolve a configuration value using the default client."""
    return _default_client.get(key, default)


def explain_config(key: str, default: Any = None) -> Dict[str, Any]:
    """Return a value plus which layer supplied it (env / config / default)."""
    return _default_client.explain(key, default)


def config_status() -> Dict[str, Any]:
    """Report client configuration and last read outcome (contains no values)."""
    return _default_client.status()


def compare_config(key: str, default: Any = None) -> Dict[str, Any]:
    """Compare ENVVAR and config values for a key without revealing them."""
    return _default_client.compare(key, default)


def config_sources() -> Dict[str, str]:
    """Return the last known resolution source for every key looked up."""
    return _default_client.sources()


def set_client_provider(provider: Callable[[], Any]) -> None:
    """Supply the Firestore client the default client should read with."""
    _default_client.set_client_provider(provider)


def refresh() -> None:
    """Force the default client to reread on the next lookup."""
    _default_client.refresh()


def prime() -> None:
    """Read the configuration document now rather than on first lookup."""
    _default_client.prime()


# Read at import, so the cost lands in container startup -- where Cloud Run
# grants a CPU boost -- instead of on whichever request arrives first.
if os.environ.get("OPTERYX_CONFIG_EAGER", "true").strip().lower() != "false":
    prime()


__all__ = [
    "ConfigClient",
    "explain_config",
    "compare_config",
    "config_sources",
    "config_status",
    "get_config",
    "set_client_provider",
    "refresh",
    "prime",
    "reset_metadata_cache",
    "CACHE_TTL_SECONDS",
    "COLLECTION",
    "DATABASE",
]
