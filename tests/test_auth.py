import pyarrow.flight as fl
import pytest

from app.auth.deps import require_flight_authentication
from app.auth.errors import AuthError
from app.flight.auth_middleware import ClaimsMiddlewareFactory
from app.flight.auth_middleware import _flight_error_for


def test_anonymous_call_is_let_through():
    claims = require_flight_authentication(None)
    assert claims == {"identity": None, "policies": [], "billing_account": None}


def test_non_bearer_value_is_rejected():
    with pytest.raises(AuthError) as exc_info:
        require_flight_authentication("Basic dXNlcjpwYXNz")
    assert exc_info.value.status_code == 401


def test_malformed_bearer_is_rejected():
    with pytest.raises(AuthError) as exc_info:
        require_flight_authentication("Bearer not-a-real-jwt")
    assert exc_info.value.status_code == 401


def test_auth_error_401_maps_to_unauthenticated():
    assert isinstance(_flight_error_for(AuthError(401, "no")), fl.FlightUnauthenticatedError)


def test_auth_error_403_maps_to_unauthenticated():
    assert isinstance(_flight_error_for(AuthError(403, "no")), fl.FlightUnauthenticatedError)


def test_auth_error_503_maps_to_server_error():
    assert isinstance(_flight_error_for(AuthError(503, "down")), fl.FlightServerError)


class _FakeCallInfo:
    pass


def test_middleware_factory_lets_anonymous_calls_through():
    factory = ClaimsMiddlewareFactory()
    middleware = factory.start_call(_FakeCallInfo(), {})
    assert middleware.claims == {"identity": None, "policies": [], "billing_account": None}


def test_middleware_factory_uses_first_authorization_value():
    factory = ClaimsMiddlewareFactory()
    with pytest.raises(fl.FlightUnauthenticatedError):
        factory.start_call(_FakeCallInfo(), {"authorization": ["Bearer garbage"]})
