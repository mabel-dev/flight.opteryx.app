"""Transport-agnostic auth error.

`app.auth.deps` and `app.auth.external_auth` are ported from odata.opteryx,
where auth failures are raised as FastAPI `HTTPException`s. Flight has no
HTTP status codes, so those call sites raise `AuthError` instead; the Flight
transport layer (`app.flight.auth_middleware`) is the single place that maps
`AuthError.status_code` onto the matching `pyarrow.flight` error class.
"""

from __future__ import annotations


class AuthError(Exception):
    """Raised by auth helpers on any authentication/authorization failure.

    `status_code` mirrors the HTTP status the odata.opteryx equivalent would
    have raised (401, 403, 503, ...) so the Flight layer can pick the closest
    matching `FlightError` subclass without the auth logic itself knowing
    anything about Flight.
    """

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
