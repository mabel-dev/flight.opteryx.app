import pyarrow.flight as fl
import pytest

from app.auth.deps import require_bearer_token
from app.auth.errors import AuthError
from app.flight.auth_middleware import ClaimsMiddlewareFactory
from app.flight.auth_middleware import _flight_error_for


def test_missing_authorization_is_rejected():
    # No anonymous access, unlike odata.opteryx: a call with no Authorization
    # metadata at all must be rejected, not let through with anonymous claims.
    with pytest.raises(AuthError) as exc_info:
        require_bearer_token(None)
    assert exc_info.value.status_code == 401


def test_non_bearer_value_is_rejected():
    with pytest.raises(AuthError) as exc_info:
        require_bearer_token("Basic dXNlcjpwYXNz")
    assert exc_info.value.status_code == 401


def test_malformed_bearer_is_rejected():
    with pytest.raises(AuthError) as exc_info:
        require_bearer_token("Bearer not-a-real-jwt")
    assert exc_info.value.status_code == 401


def test_auth_error_401_maps_to_unauthenticated():
    assert isinstance(_flight_error_for(AuthError(401, "no")), fl.FlightUnauthenticatedError)


def test_auth_error_403_maps_to_unauthenticated():
    assert isinstance(_flight_error_for(AuthError(403, "no")), fl.FlightUnauthenticatedError)


def test_auth_error_503_maps_to_server_error():
    assert isinstance(_flight_error_for(AuthError(503, "down")), fl.FlightServerError)


class _FakeCallInfo:
    pass


def test_middleware_factory_rejects_missing_authorization():
    # No anonymous access: a call with no auth metadata at all must be
    # rejected at start_call, not let through with anonymous claims.
    factory = ClaimsMiddlewareFactory()
    with pytest.raises(fl.FlightUnauthenticatedError):
        factory.start_call(_FakeCallInfo(), {})


def test_middleware_factory_uses_first_authorization_value():
    factory = ClaimsMiddlewareFactory()
    with pytest.raises(fl.FlightUnauthenticatedError):
        factory.start_call(_FakeCallInfo(), {"authorization": ["Bearer garbage"]})
