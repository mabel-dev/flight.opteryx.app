"""JWT verification for Flight calls.

Ported from odata.opteryx's `app/auth/deps.py`, with FastAPI's
`HTTPException`/`Header` swapped for the transport-agnostic `AuthError` and a
plain `Optional[str]` parameter.

Every call must carry a valid bearer token issued by the configured
authority (`AUTH_URL` / `JWT_ISSUER`). There is no anonymous access and no
Basic-auth fallback: Flight SQL JDBC/ODBC drivers authenticate with a bearer
token. `app.flight.auth_middleware` calls `require_bearer_token` directly.

Hardening relative to the odata.opteryx original:

* Only asymmetric signature algorithms are accepted. The algorithm named in
  the token header is never trusted on its own, so a token cannot ask to be
  verified as HMAC against a public key, or as `none`.
* Google-issued OIDC tokens are not accepted. odata.opteryx takes them from
  Cloud Tasks; nothing calls this service that way, and accepting them meant
  any Google account could authenticate whenever the JWKS fetch failed.
* Work done before the signature is checked is bounded. The `kid` is only
  looked up in Secret Manager when it names a date a signing key could
  plausibly carry, and the JWKS document is cached rather than fetched on
  every call, so unauthenticated traffic cannot turn into unbounded
  Secret Manager or network calls.
"""

import datetime
import re
import threading
import time
from typing import Any
from typing import Dict
from typing import Optional

import requests
from google.api_core import exceptions as gcp_exceptions
from jose import JWTError
from jose import jwt as jose_jwt
from opteryx_shared_services.config import get_config
from opteryx_shared_services.logging import get_logger

from app.auth.errors import AuthError
from app.secret_store import load_public_key

logger = get_logger()

# Asymmetric algorithms only. HS* would let a public key be used as an HMAC
# secret; `none` would skip verification altogether.
ALLOWED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
)

# Signing keys are named by the day they were minted (`YYYYMMDD`) and expire
# after a few days, so only a small window of dates can name a live key.
_KID_PATTERN = re.compile(r"^\d{8}$")
_KID_MAX_AGE_DAYS = 7
_KID_MAX_FUTURE_DAYS = 1

# JWKS caching: reuse a fetched document for this long, and never refetch
# more often than the minimum interval, even for a `kid` the cached document
# does not contain.
_JWKS_TTL_SECONDS = 300
_JWKS_MIN_REFETCH_SECONDS = 30

_jwks_lock = threading.Lock()
_jwks_cache: Dict[str, Any] = {"url": None, "doc": None, "fetched_at": 0.0}


def _fetch_jwks(auth_url: str, timeout: float = 2.0) -> Optional[dict]:
    """Fetch JWKS from the auth server using optional discovery.
    Falls back to `/.well-known/jwks.json`. Returns dict or None.
    """
    try:
        discovery = requests.get(
            f"{auth_url.rstrip('/')}/.well-known/openid-configuration", timeout=timeout
        )
        if discovery.status_code == 200:
            jwks_uri = discovery.json().get("jwks_uri")
            if jwks_uri:
                r = requests.get(jwks_uri, timeout=timeout)
                if r.status_code == 200:
                    return r.json()
    except (requests.RequestException, ValueError):
        pass
    try:
        r = requests.get(f"{auth_url.rstrip('/')}/.well-known/jwks.json", timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except (requests.RequestException, ValueError):
        pass
    return None


def _jwks_has_kid(doc: Optional[dict], kid: Optional[str]) -> bool:
    if not doc or not kid:
        return bool(doc)
    return any(key.get("kid") == kid for key in doc.get("keys", []) or [])


def _get_jwks(auth_url: str, kid: Optional[str]) -> Optional[dict]:
    """Return the JWKS document for `auth_url`, cached.

    Refetches when the cache is stale, or when it lacks `kid` (a key rotated
    in since the last fetch) -- but in either case at most once per
    `_JWKS_MIN_REFETCH_SECONDS`, so a stream of tokens with made-up `kid`
    values costs one fetch per interval rather than one per call.
    """
    now = time.monotonic()
    with _jwks_lock:
        cached = _jwks_cache["doc"] if _jwks_cache["url"] == auth_url else None
        age = now - _jwks_cache["fetched_at"]
        fresh = cached is not None and age < _JWKS_TTL_SECONDS
        if fresh and _jwks_has_kid(cached, kid):
            return cached
        if cached is not None and age < _JWKS_MIN_REFETCH_SECONDS:
            return cached
        if cached is None and _jwks_cache["url"] == auth_url and age < _JWKS_MIN_REFETCH_SECONDS:
            # A recent fetch failed; don't hammer the auth server.
            return None

        doc = _fetch_jwks(auth_url)
        _jwks_cache["url"] = auth_url
        _jwks_cache["fetched_at"] = now
        if doc is not None:
            _jwks_cache["doc"] = doc
            return doc
        # Keep serving the last good document through a transient failure.
        if cached is None:
            _jwks_cache["doc"] = None
        return cached


def _plausible_dated_kid(kid: Optional[str]) -> bool:
    """True when `kid` is a `YYYYMMDD` date a live signing key could carry."""
    if not kid or not _KID_PATTERN.match(kid):
        return False
    try:
        kid_date = datetime.datetime.strptime(kid, "%Y%m%d").date()
    except ValueError:
        return False
    today = datetime.datetime.now(tz=datetime.timezone.utc).date()
    return (
        today - datetime.timedelta(days=_KID_MAX_AGE_DAYS)
        <= kid_date
        <= today + datetime.timedelta(days=_KID_MAX_FUTURE_DAYS)
    )


def _normalize_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize JWT claims to consistent structure.

    Ensures all claims have:
    - identity: extracted from sub/email/preferred_username
    - billing_account: from the billing_account claim, falling back to sub

    The `policies` claim is left as the token carried it (wrapped in a list if
    it is a single value); converting it is the job of `app.auth.permissions`.
    """
    from app.auth.permissions import billing_account_from_claims

    identity = claims.get("sub") or claims.get("email") or claims.get("preferred_username")
    if identity:
        claims["identity"] = identity

    # Who pays for this caller's usage. Not the same as identity. Resolving in place is
    # idempotent: the resolver reads this same key off the raw token first.
    claims["billing_account"] = billing_account_from_claims(claims)

    policies = claims.get("policies")
    if policies and not isinstance(policies, list):
        claims["policies"] = [policies]

    return claims


def require_bearer_token(authorization: Optional[str]) -> Dict[str, Any]:
    """Require and verify a bearer JWT, returning its normalized claims.

    Verifies the signature (with an allow-listed asymmetric algorithm), the
    validity window, and the `iss`/`aud` claims against the configured
    authority. The public key is looked up in the secret store by `kid`
    first, then in the auth server's (cached) JWKS.

    Blocking network I/O happens synchronously here via `requests` --
    PyArrow's `FlightServerBase` dispatches each RPC to its own worker
    thread, so a slow auth call stalls only that call, not the whole server.
    """
    if not (authorization and authorization.lower().startswith("bearer ")):
        raise AuthError(401, "Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise AuthError(401, "Missing bearer token")

    auth_url = get_config("AUTH_URL", "https://authenticate.opteryx.app")
    issuer = get_config("JWT_ISSUER", auth_url)
    audience = get_config("DATA_AUDIENCE", "opteryx")

    try:
        headers = jose_jwt.get_unverified_header(token)
        claims_unverified = jose_jwt.get_unverified_claims(token)
    except JWTError as exc:
        raise AuthError(401, "Invalid token") from exc

    alg = headers.get("alg")
    kid = headers.get("kid")
    if alg not in ALLOWED_ALGORITHMS:
        logger.info(f"token rejected: disallowed alg={alg!r}")
        raise AuthError(401, "Invalid token")

    # Cheap rejection before any key lookup. Signature verification below
    # checks these again against the verified claims.
    iss = claims_unverified.get("iss")
    aud = claims_unverified.get("aud")
    aud_ok = aud == audience or (isinstance(aud, list) and audience in aud)
    if iss != issuer or not aud_ok:
        logger.info(
            f"token claims mismatch; iss={iss} aud={aud} expected_iss={issuer} expected_aud={audience}"
        )
        raise AuthError(401, "Invalid token claims")

    key: Any = None
    if _plausible_dated_kid(kid):
        try:
            key = load_public_key(kid)
        except (RuntimeError, gcp_exceptions.GoogleAPIError):  # pragma: no cover - best effort
            key = None
    if not key:
        key = _get_jwks(auth_url, kid)
    if not key:
        # A token we hold no key for is indistinguishable from a forged one, so
        # it is refused as unauthenticated. Not 503: that would let any made-up
        # `kid` provoke a "server error" a driver retries instead of re-prompting.
        logger.warning(f"No verification key for kid={kid!r} (secret store and JWKS)")
        raise AuthError(401, "Invalid token")

    options = {"require_exp": True, "require_iss": True, "verify_nbf": True, "verify_iat": True}
    try:
        claims = jose_jwt.decode(
            token,
            key,
            algorithms=[alg],
            options=options,
            issuer=issuer,
            audience=audience,
        )
    except JWTError as exc:
        logger.info(f"Token verification failed: {exc}")
        raise AuthError(401, "Invalid token") from exc

    return _normalize_claims(claims)
