"""Per-call claims resolution for Flight.

Flight has no per-request HTTP headers in the FastAPI sense; instead each
call carries gRPC metadata, surfaced to a `ServerMiddleware` via
`start_call(info, headers)`. `headers` is a dict of lower-cased header name
-> list of string values (mirrors pyarrow's own middleware tests).

Every command handler fetches claims via
`context.get_middleware("auth").claims` instead of a FastAPI dependency.
Registered on the server as `middleware={"auth": ClaimsMiddlewareFactory()}`.

Unlike odata.opteryx (and unlike this service's own earlier v1 draft), a
call with no `authorization` metadata at all is NOT let through as
anonymous — `require_bearer_token` already rejects a missing/empty value
with `AuthError(401, "Missing bearer token")`, so calling it directly here
is sufficient to require a valid credential on every single Flight call.
"""

from __future__ import annotations

import pyarrow.flight as fl

from app.auth.deps import require_bearer_token
from app.auth.errors import AuthError

# AuthError.status_code -> the FlightError subclass that best represents it.
# 401/403 are both "the server refused to act on this identity"; Flight only
# distinguishes unauthenticated (no/invalid credentials) from unauthorized
# (valid credentials, insufficient rights) — AuthError doesn't carry that
# distinction today, so both map to FlightUnauthenticatedError. Anything else
# (503 from the external auth service, etc.) is a server-side failure.
_UNAUTHENTICATED_STATUS_CODES = (401, 403)


def _flight_error_for(exc: AuthError) -> fl.FlightError:
    if exc.status_code in _UNAUTHENTICATED_STATUS_CODES:
        return fl.FlightUnauthenticatedError(exc.detail)
    return fl.FlightServerError(exc.detail)


class ClaimsMiddleware(fl.ServerMiddleware):
    """Carries the resolved claims for one RPC."""

    def __init__(self, claims: dict) -> None:
        self.claims = claims


class ClaimsMiddlewareFactory(fl.ServerMiddlewareFactory):
    """Resolves and verifies the caller's bearer token once per call."""

    def start_call(self, info, headers) -> ClaimsMiddleware:
        auth_values = headers.get("authorization", [])
        authorization = auth_values[0] if auth_values else None
        try:
            claims = require_bearer_token(authorization)
        except AuthError as exc:
            raise _flight_error_for(exc) from exc
        return ClaimsMiddleware(claims)


def claims_from_context(context: fl.ServerCallContext) -> dict:
    """Fetch the claims resolved by `ClaimsMiddlewareFactory` for this call.

    Every Flight method handler (`get_flight_info`, `do_get`, `do_action`,
    ...) receives a fresh `ServerCallContext`; this is the one place that
    knows the middleware is registered under the key `"auth"`.
    """
    middleware = context.get_middleware("auth")
    if middleware is None:
        # The auth middleware factory is always registered by app.flight.server
        # (see FlightServerBase(middleware={"auth": ClaimsMiddlewareFactory()})),
        # so this can only happen if a handler is invoked outside that server.
        raise fl.FlightUnauthenticatedError("No auth middleware registered for this call")
    return middleware.claims
