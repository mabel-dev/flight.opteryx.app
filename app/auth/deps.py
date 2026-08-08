"""JWT verification for Flight calls.

Ported from odata.opteryx's `app/auth/deps.py`. The JWT verification logic
(`require_bearer_token`) is pure — no FastAPI dependency — so it carries over
unchanged apart from swapping `HTTPException`/`Header` for the
transport-agnostic `AuthError` and a plain `Optional[str]` parameter.

`require_authentication` doesn't carry over: it takes a FastAPI `Request`
(to stash `request.state.claims`), supports a Basic-auth fallback (v1 has
none here — Flight SQL JDBC/ODBC drivers authenticate via bearer token, not
HTTP Basic), and — unlike this service — lets a call with no `Authorization`
header through as anonymous. flight.opteryx deliberately does not offer that:
every call must carry a valid bearer token, full stop. `app.flight.auth_middleware`
calls `require_bearer_token` directly for this reason; there is no
Flight-specific wrapper here to carry that anonymous-tolerant behavior,
because there isn't any.
"""

from typing import Any
from typing import Dict
from typing import Optional

import requests
from google.api_core import exceptions as gcp_exceptions
from google.auth.transport import requests as google_auth_requests
from google.oauth2 import id_token as google_id_token
from jose import JWTError
from jose import jwt as jose_jwt
from app.logging import get_logger

from app.auth.errors import AuthError
from app.config_client import get_config
from app.secret_store import load_public_key


def _fetch_jwks(auth_url: str, timeout: float = 2.0):
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
    except requests.RequestException:
        pass
    try:
        r = requests.get(f"{auth_url.rstrip('/')}/.well-known/jwks.json", timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except requests.RequestException:
        pass
    return None


logger = get_logger()


def _normalize_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize JWT claims to consistent structure.

    Ensures all claims have:
    - identity: extracted from sub/email/preferred_username
    - billing_account: from the billing_account claim, falling back to sub
    - permissions: list of tuples [(role, workspace), ...]

    Args:
        claims: Raw JWT claims

    Returns:
        dict: Normalized claims with consistent structure
    """
    from app.auth.permissions import billing_account_from_claims

    # Extract identity from standard JWT claims
    identity = claims.get("sub") or claims.get("email") or claims.get("preferred_username")

    if identity:
        claims["identity"] = identity

    # Who pays for this caller's usage. Not the same as identity. Resolving in place is
    # idempotent: the resolver reads this same key off the raw token first.
    claims["billing_account"] = billing_account_from_claims(claims)

    # "policies" claim may be present in tokens and encodes what a user can access.
    # We will NOT write or rely on a separate "permissions" claim (that was incorrect).
    # Leave policies untouched and do not mutate the claims with derived permission keys.
    # Any conversion/formatting should be done by helpers when needed.

    # Do NOT touch or create a "permissions" key here.

    # Ensure policies, if present, are a list; otherwise leave as-is
    policies = claims.get("policies")
    if policies and not isinstance(policies, list):
        # If policies is a single dict/tuple, wrap it for convenience
        claims["policies"] = [policies]

    return claims


def require_bearer_token(authorization: Optional[str]) -> Dict[str, Any]:
    """Require and verify a bearer JWT.

    This function verifies the JWT's signature, ensures the token is within its
    validity window and checks the `iss` claim against a configured authority.
    The verification uses `app.secret_store.load_key(kid)` first (dev-friendly),
    and falls back to fetching JWKS from `AUTH_URL` when needed.
    Returns the decoded claims on success.

    Blocking network I/O (secret-store lookups, JWKS fetch/discovery, Google
    OIDC verification) happens synchronously here via `requests` — PyArrow's
    `FlightServerBase` dispatches each RPC to its own worker thread, so a
    slow auth call stalls only that call, not the whole server.
    """
    if not (authorization and authorization.lower().startswith("bearer ")):
        raise AuthError(401, "Missing bearer token")
    token = authorization.split(" ", 1)[1]

    # Resolve expected values from environment
    auth_url = get_config("AUTH_URL", "https://authenticate.opteryx.app")
    issuer = get_config("JWT_ISSUER", auth_url)
    audience = get_config("DATA_AUDIENCE", "opteryx")

    try:
        headers = jose_jwt.get_unverified_header(token)
    except JWTError as exc:
        raise AuthError(401, "Invalid token header") from exc
    alg = headers.get("alg")
    kid = headers.get("kid")

    # Check issuer/audience in the token claims (unverified) first
    try:
        claims_unverified = jose_jwt.get_unverified_claims(token)
    except JWTError as exc:
        raise AuthError(401, "Invalid token claims") from exc
    iss = claims_unverified.get("iss")
    aud = claims_unverified.get("aud")
    # Accept either the configured issuer (users/auth) OR Google OIDC issuer
    google_issuers = ("https://accounts.google.com", "accounts.google.com")
    if iss in google_issuers:
        # defer audience validation to Google's verification below (TASKS_OIDC_AUDIENCE)
        pass
    else:
        if iss != issuer or aud != audience:
            logger.info(
                f"token claims mismatch; iss={iss} aud={aud} expected_iss={issuer} expected_aud={audience}"
            )
            raise AuthError(401, "Invalid token claims")

    # Best-effort: try fetching the public key via the secret store first
    try:
        # First attempt strict date-based public load
        pub_key = load_public_key(kid)
    except (
        RuntimeError,
        gcp_exceptions.GoogleAPIError,
    ):  # pragma: no cover - best-effort fallback
        pub_key = None

    options = {"require_exp": True, "require_iss": True, "verify_nbf": True, "verify_iat": True}

    # If we got a public key from the secret store, use it directly
    if pub_key:
        try:
            claims = jose_jwt.decode(
                token,
                pub_key,
                algorithms=[alg] if alg else None,
                options=options,
                issuer=issuer,
                audience=audience,
            )
            # Normalize claims structure
            return _normalize_claims(claims)
        except JWTError as exc:
            logger.info(f"Token verification failed with secret store key: {exc}")
            raise AuthError(401, "Invalid token") from exc

    # Otherwise, attempt JWKS fallback
    jwks = _fetch_jwks(auth_url)
    if jwks:
        try:
            claims = jose_jwt.decode(
                token,
                jwks,
                algorithms=[alg] if alg else None,
                options=options,
                issuer=issuer,
                audience=audience,
            )
            # Normalize claims structure
            return _normalize_claims(claims)
        except JWTError as exc:
            logger.info(f"Token verification failed using remote JWKS: {exc}")
            raise AuthError(401, "Invalid token") from exc
    # If we reach here, JWT signature verification via local key or JWKS failed.
    # Fall through to try Google OIDC validation below if available.

    # Accept Google-signed OIDC tokens (used by Cloud Tasks OIDC) if library is available
    if not pub_key and iss in ("https://accounts.google.com", "accounts.google.com"):
        # Use google_auth library to verify token and audience and issuer
        expected_aud = get_config("TASKS_OIDC_AUDIENCE")
        try:
            google_claims = google_id_token.verify_oauth2_token(
                token, google_auth_requests.Request(), audience=expected_aud
            )
        except Exception as exc:  # pragma: no cover - library dependent
            logger.info(f"Google token verification failed: {exc}")
            raise AuthError(401, "Invalid Google ID token") from exc

        # Optionally restrict to invoker SA
        invoker_sa = get_config("TASKS_OIDC_SA")
        if invoker_sa and google_claims.get("email") != invoker_sa:
            raise AuthError(403, "Forbidden caller")
        # Accept Google claims as valid
        return _normalize_claims(google_claims)

    raise AuthError(401, "Invalid token")
