import pyarrow.flight as fl
import pytest

from app.auth.errors import AuthError
from app.flight.server import OpteryxFlightServer

# A fixed stand-in bearer token the round-trip tests authenticate with.
# app.auth.deps.require_bearer_token does real network I/O (JWKS fetch,
# GCP secret-store lookup, Google OIDC verification) that this test
# environment has none of, so `flight_server` stubs it to accept exactly
# this one token -- everything else, including no token at all, is still
# rejected for real, so these tests still exercise actual request-time auth
# enforcement (see test_query_roundtrip.py's test_unauthenticated_call_is_rejected).
TEST_TOKEN = "test-token"
TEST_CLAIMS = {
    "identity": "test-user",
    "policies": [{"pattern": "*", "role": "owner"}],
    "billing_account": "test-account",
}


@pytest.fixture(autouse=True)
def _no_real_firestore(monkeypatch):
    """No billing read or write reaches a real Firestore unless a test installs a fake.

    `app.core._get_firestore_client` builds a real client from local
    credentials, and the query path both reads account documents and WRITES
    usage counters (opteryx_shared_services.billing.allowance) - against production, from a
    developer's machine. Returning None makes every billing read fail open, as
    it does when Firestore is down; tests that need Firestore patch it again.
    (`app.flight.metadata` binds its own reference at import and is not
    affected.)
    """
    monkeypatch.setattr("app.core._get_firestore_client", lambda *a, **k: None)


@pytest.fixture(autouse=True)
def _platform_operational(monkeypatch):
    """The platform maintenance switch reads no real Firestore: it is `operational`.

    Every query and metadata RPC checks `opteryx_shared_services.platform_mode`,
    whose default reader would otherwise go to the real config document. A
    reader over a document with no `platform_mode` field is the switch turned
    off. tests/test_platform_mode.py installs its own to change the mode.
    """
    from opteryx_shared_services import platform_mode

    class _NoSwitch:
        exists = False

        def collection(self, name):
            return self

        def document(self, environment):
            return self

        def get(self, timeout=None):
            return self

    monkeypatch.delenv(platform_mode.ENV_OVERRIDE, raising=False)
    monkeypatch.setattr(
        platform_mode,
        "_default",
        platform_mode.PlatformMode(
            environment="test", client_provider=_NoSwitch, promoted=lambda k, v: False
        ),
    )


@pytest.fixture()
def flight_server(monkeypatch):
    def _fake_require_bearer_token(authorization):
        if authorization == f"Bearer {TEST_TOKEN}":
            return dict(TEST_CLAIMS)
        raise AuthError(401, "Invalid token")

    # Patched where it's looked up (app.flight.auth_middleware imports it by
    # name), not where it's defined -- patching app.auth.deps.require_bearer_token
    # would leave auth_middleware's already-bound reference untouched.
    monkeypatch.setattr(
        "app.flight.auth_middleware.require_bearer_token", _fake_require_bearer_token
    )

    server = OpteryxFlightServer(location="grpc://localhost:0")
    client = fl.FlightClient(f"grpc://localhost:{server.port}")
    try:
        yield server, client
    finally:
        client.close()
        server.shutdown()
        server.wait()


@pytest.fixture()
def auth_options() -> fl.FlightCallOptions:
    """FlightCallOptions carrying the one bearer token `flight_server` accepts."""
    return fl.FlightCallOptions(headers=[(b"authorization", f"Bearer {TEST_TOKEN}".encode())])
