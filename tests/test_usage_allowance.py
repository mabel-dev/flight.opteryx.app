"""The free tier's daily allowance, enforced on Flight SQL queries.

The rule is `opteryx_shared_services.billing.allowance`; jobs and
Flight count onto the same `billing_accounts/{account}/usage/{YYYYMMDD}`
counters. Flight has no 402, so a refusal is opteryx's `PermissionsError`,
which the server maps to `FlightUnauthorizedError` with the message intact.
"""

import datetime

import opteryx.exceptions as opteryx_exceptions
import pyarrow as pa
import pyarrow.flight as fl
import pytest
from google.cloud.firestore_v1.transforms import Increment

from opteryx_shared_services.billing import accounts
from opteryx_shared_services.billing import allowance as ua
from app.flight import query
from tests.helpers import statement_query_descriptor

UTC = datetime.timezone.utc
NOON = datetime.datetime(2026, 11, 10, 12, tzinfo=UTC)
GB = ua.BYTES_PER_GIGABYTE
INDIVIDUAL = ua.STANDARD_CARDS[ua.STANDARD_INDIVIDUAL]


# --- the shared rule, as Flight calls it -----------------------------------


@pytest.mark.parametrize(
    "plan, usage, reason",
    [
        ("free", ua.Usage(queries=99), None),
        ("free", ua.Usage(queries=100), ua.REASON_QUERIES),
        ("free", ua.Usage(bytes_processed=int(0.99 * GB)), None),
        ("free", ua.Usage(bytes_processed=GB), ua.REASON_PROCESSED),
        ("payg", ua.Usage(queries=10_000), None),
        ("house", ua.Usage(queries=10_000), None),
    ],
)
def test_decide_matches_jobs(plan, usage, reason):
    refusal = ua.decide(plan, INDIVIDUAL, usage, NOON)
    assert (refusal.reason if refusal else None) == reason


# --- a path-keyed Firestore -----------------------------------------------------


class _Snap:
    def __init__(self, data):
        self._data, self.exists = data, data is not None

    def to_dict(self):
        return dict(self._data) if self._data is not None else None


class _Doc:
    def __init__(self, fs, path):
        self._fs, self._path = fs, path

    def collection(self, name):
        return _Coll(self._fs, self._path + (name,))

    def get(self):
        self._fs.reads.append("/".join(self._path))
        if self._fs.fail:
            raise RuntimeError("firestore unavailable")
        return _Snap(self._fs.docs.get(self._path))

    def set(self, doc, merge=False):
        current = dict(self._fs.docs.get(self._path) or {}) if merge else {}
        for key, value in doc.items():
            current[key] = current.get(key, 0) + value._value if isinstance(value, Increment) else value
        self._fs.docs[self._path] = current


class _Coll:
    def __init__(self, fs, path):
        self._fs, self._path = fs, path

    def document(self, key):
        return _Doc(self._fs, self._path + (key,))


class _Firestore:
    def __init__(self):
        self.docs, self.reads, self.fail = {}, [], False

    def collection(self, name):
        return _Coll(self, (name,))

    def usage(self, account):
        return self.docs.get(("billing_accounts", account, "usage", ua.usage_day()), {})

    def set_usage(self, account, **doc):
        self.docs[("billing_accounts", account, "usage", ua.usage_day())] = doc


class _Morsel:
    def materialize(self):
        pass

    def to_arrow(self):
        return pa.table({"x": [1]})


class _Session:
    def __init__(self, billing_bytes):
        self.telemetry = {"billing_bytes": billing_bytes}
        self.executed = 0

    def execute_to_morsels(self, sql, **kwargs):
        self.executed += 1
        yield _Morsel()


@pytest.fixture
def env(monkeypatch):
    accounts.clear_cache()
    ua.clear_cache()
    fs = _Firestore()
    config = {}
    session = _Session(billing_bytes=40_000_000)
    monkeypatch.setattr("app.core._get_firestore_client", lambda *a, **k: fs)
    monkeypatch.setattr(query, "get_config", lambda key, default=None: config.get(key, default))
    monkeypatch.setattr(query, "session_for_claims", lambda claims: session)
    yield fs, config, session
    accounts.clear_cache()
    ua.clear_cache()


CLAIMS = {"identity": "alice", "billing_account": "alice"}


def _run(claims=CLAIMS):
    return list(query._execute_to_tables("SELECT 1", claims))


def test_under_the_allowance_runs_is_counted_and_settles_bytes(env):
    fs, _, session = env
    fs.set_usage("alice", queries=3, bytes_processed=100)

    assert len(_run()) == 1

    assert session.executed == 1
    assert fs.usage("alice")["queries"] == 4
    assert fs.usage("alice")["bytes_processed"] == 100 + 40_000_000


def test_at_the_query_allowance_is_refused_before_running(env):
    fs, _, session = env
    fs.set_usage("alice", queries=100)

    with pytest.raises(opteryx_exceptions.PermissionsError, match="Daily query allowance used"):
        _run()

    assert session.executed == 0
    assert fs.usage("alice")["queries"] == 100, "a refused query is not counted"


def test_at_the_data_allowance_is_refused(env):
    fs, _, _ = env
    fs.set_usage("alice", bytes_processed=GB)

    with pytest.raises(opteryx_exceptions.PermissionsError, match="Daily data allowance used"):
        _run()


def test_a_payg_account_is_never_metered(env):
    fs, _, session = env
    fs.docs[("billing_accounts", "acct_1")] = {"plan": "payg", "payment_method": {"last4": "4242"}}
    fs.set_usage("acct_1", queries=10_000)

    _run({"identity": "alice", "billing_account": "acct_1"})

    assert session.executed == 1
    assert not any("/usage/" in path for path in fs.reads)
    assert fs.usage("acct_1") == {"queries": 10_000}


def test_shadow_mode_runs_and_counts(env):
    fs, config, session = env
    config["BILLING_ALLOWANCE_MODE"] = "shadow"
    fs.set_usage("alice", queries=100)

    _run()

    assert session.executed == 1
    assert fs.usage("alice")["queries"] == 101


def test_off_mode_does_not_meter(env):
    fs, config, _ = env
    config["BILLING_ALLOWANCE_MODE"] = "off"
    fs.set_usage("alice", queries=100)

    _run()

    assert fs.usage("alice") == {"queries": 100}


def test_an_unreadable_counter_fails_open(env):
    fs, _, session = env
    fs.fail = True

    _run()

    assert session.executed == 1


def test_a_query_that_fails_part_way_is_counted_without_bytes(env, monkeypatch):
    fs, _, _ = env

    class Failing(_Session):
        def execute_to_morsels(self, sql, **kwargs):
            raise opteryx_exceptions.SqlError("boom")
            yield  # pragma: no cover

    monkeypatch.setattr(query, "session_for_claims", lambda claims: Failing(40_000_000))

    with pytest.raises(opteryx_exceptions.SqlError):
        _run()

    assert fs.usage("alice") == {"queries": 1, "updated_at": fs.usage("alice")["updated_at"]}


# --- through the server -------------------------------------------------------


def test_the_refusal_reaches_a_flight_client_as_unauthorized(flight_server, auth_options, monkeypatch):
    """End to end: the server's error mapping keeps the allowance message."""
    _, client = flight_server
    fs = _Firestore()
    fs.set_usage("test-account", queries=100)
    accounts.clear_cache()
    ua.clear_cache()
    monkeypatch.setattr("app.core._get_firestore_client", lambda *a, **k: fs)

    with pytest.raises(fl.FlightUnauthorizedError, match="Daily query allowance used"):
        client.get_flight_info(statement_query_descriptor("SELECT name FROM $planets"), auth_options)

    accounts.clear_cache()
