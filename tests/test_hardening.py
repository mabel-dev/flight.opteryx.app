"""Regression tests for the auth and ticket hardening done before the repo
went public: algorithm allow-listing, no Google OIDC fallback, bounded
pre-verification work, tickets bound to their caller and their token's expiry.
"""

import base64
import json
import time

import pyarrow.flight as fl
import pytest

from app.auth import deps
from app.auth.errors import AuthError
from app.flight import tickets
from app.flight.server import OpteryxFlightServer
from tests.helpers import create_prepared_statement
from tests.helpers import prepared_query_descriptor
from tests.helpers import statement_query_descriptor

ISSUER = "https://authenticate.opteryx.app"


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _unsigned(header: dict, claims: dict) -> str:
    """A syntactically valid JWT with the given header; the signature is junk."""
    return f"{_b64({'typ': 'JWT', **header})}.{_b64(claims)}.c2ln"


def _claims(**overrides):
    claims = {"iss": ISSUER, "aud": "opteryx", "sub": "u", "exp": int(time.time()) + 600}
    claims.update(overrides)
    return claims


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    calls = {"secret_store": 0, "jwks": 0}

    def fake_load_public_key(kid):
        calls["secret_store"] += 1
        return None

    def fake_fetch_jwks(auth_url, timeout=2.0):
        calls["jwks"] += 1
        return None

    monkeypatch.setattr(deps, "load_public_key", fake_load_public_key)
    monkeypatch.setattr(deps, "_fetch_jwks", fake_fetch_jwks)
    monkeypatch.setitem(deps._jwks_cache, "url", None)
    monkeypatch.setitem(deps._jwks_cache, "doc", None)
    monkeypatch.setitem(deps._jwks_cache, "fetched_at", 0.0)
    return calls


@pytest.mark.parametrize("alg", ["HS256", "none", "None", None])
def test_symmetric_and_none_algorithms_are_refused(alg, _no_network):
    header = {"alg": alg} if alg is not None else {}
    with pytest.raises(AuthError) as exc:
        deps.require_bearer_token(f"Bearer {_unsigned(header, _claims())}")
    assert exc.value.status_code == 401
    assert _no_network == {"secret_store": 0, "jwks": 0}


def test_google_issued_tokens_are_refused_without_any_key_lookup(_no_network):
    token = _unsigned({"alg": "RS256", "kid": "abc"}, _claims(iss="https://accounts.google.com"))
    with pytest.raises(AuthError) as exc:
        deps.require_bearer_token(f"Bearer {token}")
    assert exc.value.status_code == 401
    assert _no_network == {"secret_store": 0, "jwks": 0}


@pytest.mark.parametrize("kid", ["not-a-date", "19990101", "../../etc", "", None])
def test_implausible_kid_skips_the_secret_store(kid, _no_network):
    header = {"alg": "RS256"}
    if kid is not None:
        header["kid"] = kid
    with pytest.raises(AuthError):
        deps.require_bearer_token(f"Bearer {_unsigned(header, _claims())}")
    assert _no_network["secret_store"] == 0


def test_todays_kid_is_looked_up(_no_network):
    kid = time.strftime("%Y%m%d", time.gmtime())
    with pytest.raises(AuthError):
        deps.require_bearer_token(f"Bearer {_unsigned({'alg': 'RS256', 'kid': kid}, _claims())}")
    assert _no_network["secret_store"] == 1


def test_token_with_no_known_key_is_unauthenticated_not_a_server_error(_no_network):
    token = _unsigned({"alg": "RS256", "kid": "made-up"}, _claims())
    with pytest.raises(AuthError) as exc:
        deps.require_bearer_token(f"Bearer {token}")
    assert exc.value.status_code == 401


def test_jwks_failures_are_not_refetched_on_every_call(_no_network):
    token = _unsigned({"alg": "RS256", "kid": "made-up"}, _claims())
    for _ in range(20):
        with pytest.raises(AuthError):
            deps.require_bearer_token(f"Bearer {token}")
    assert _no_network["jwks"] == 1


# -- tickets ------------------------------------------------------------


def test_ticket_does_not_outlive_its_token():
    handle = tickets.encode_statement_handle("SELECT 1", {"identity": "u", "exp": time.time() - 1})
    with pytest.raises(tickets.InvalidTicket):
        tickets.decode_statement_handle(handle)


def test_prepared_handle_does_not_outlive_its_token():
    handle = tickets.encode_prepared_handle("SELECT 1", {"identity": "u", "exp": time.time() - 1})
    with pytest.raises(tickets.InvalidTicket):
        tickets.decode_prepared_handle(handle)


def test_ticket_without_exp_still_decodes():
    handle = tickets.encode_statement_handle("SELECT 1", {"identity": "u"})
    assert tickets.decode_statement_handle(handle)[0] == "SELECT 1"


@pytest.fixture()
def two_user_server(monkeypatch):
    users = {
        "Bearer alice": {"identity": "alice", "policies": [{"pattern": "*", "role": "owner"}]},
        "Bearer bob": {"identity": "bob", "policies": [{"pattern": "*", "role": "owner"}]},
    }

    def fake(authorization):
        if authorization in users:
            return dict(users[authorization])
        raise AuthError(401, "Invalid token")

    monkeypatch.setattr("app.flight.auth_middleware.require_bearer_token", fake)
    server = OpteryxFlightServer(location="grpc://localhost:0")
    client = fl.FlightClient(f"grpc://localhost:{server.port}")
    try:
        yield client
    finally:
        client.close()
        server.shutdown()
        server.wait()


def _opts(name):
    return fl.FlightCallOptions(headers=[(b"authorization", f"Bearer {name}".encode())])


def test_statement_ticket_is_refused_for_another_caller(two_user_server):
    client = two_user_server
    info = client.get_flight_info(statement_query_descriptor("SELECT 1 AS x"), _opts("alice"))
    ticket = info.endpoints[0].ticket

    with pytest.raises(fl.FlightUnauthorizedError):
        client.do_get(ticket, _opts("bob")).read_all()

    assert client.do_get(ticket, _opts("alice")).read_all().num_rows == 1


def test_prepared_handle_is_refused_for_another_caller(two_user_server):
    client = two_user_server
    result = create_prepared_statement(client, "SELECT 1 AS x", _opts("alice"))
    descriptor = prepared_query_descriptor(result.prepared_statement_handle)

    with pytest.raises(fl.FlightUnauthorizedError):
        client.get_flight_info(descriptor, _opts("bob"))

    info = client.get_flight_info(descriptor, _opts("alice"))
    with pytest.raises(fl.FlightUnauthorizedError):
        client.do_get(info.endpoints[0].ticket, _opts("bob")).read_all()
