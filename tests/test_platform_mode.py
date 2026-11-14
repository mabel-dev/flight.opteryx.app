"""The platform maintenance switch (opteryx_shared_services.platform_mode).

For flight: `operational` allows everything, `read_only` allows reads and
refuses writes, and `reject` and `queue` refuse everything -- flight answers
synchronously and has nowhere to hold work. A refusal is
`FlightUnavailableError`.

Every RPC that runs a query or reads the catalog checks the switch at the
point of acting, on every call. These tests swap the module's default reader
for one over a fake Firestore client with no cache, so a mode changed between
two calls must be seen by the second -- and nothing reaches real Firestore.
"""

import pyarrow.flight as fl
import pytest

from app.flight import metadata
from app.flight import server
from app.flight.proto import FlightSql_pb2 as fsql
from opteryx_shared_services import platform_mode as pm
from tests.helpers import command_descriptor
from tests.helpers import create_prepared_statement
from tests.helpers import prepared_query_descriptor
from tests.helpers import statement_query_descriptor

READ_SQL = "SELECT id FROM $planets"
WRITE_SQL = "INSERT INTO $planets (id) VALUES (99)"

# Metadata commands, including the catalog-backed ones: a refusal must come
# before any of them is computed, so the catalog-backed ones are safe to send
# here (see `_catalog_must_not_be_read`).
METADATA_COMMANDS = [
    fsql.CommandGetSqlInfo(),
    fsql.CommandGetTableTypes(),
    fsql.CommandGetCatalogs(),
    fsql.CommandGetDbSchemas(),
    fsql.CommandGetTables(),
]


class _Snap:
    def __init__(self, data):
        self._data, self.exists = data, True

    def to_dict(self):
        return self._data


class _Config:
    """A fake `(default)/config/<environment>` document holding `platform_mode`."""

    def __init__(self):
        self.mode = pm.OPERATIONAL
        self.reads = 0

    def collection(self, name):
        return self

    def document(self, environment):
        return self

    def get(self, timeout=None):
        self.reads += 1
        return _Snap({"platform_mode": {"mode": self.mode}})


@pytest.fixture
def switch(monkeypatch):
    monkeypatch.delenv(pm.ENV_OVERRIDE, raising=False)
    config = _Config()
    reader = pm.PlatformMode(
        environment="x",
        client_provider=lambda: config,
        cache_ttl=0,
        promoted=lambda k, v: False,
    )
    monkeypatch.setattr(pm, "_default", reader)
    return config


@pytest.fixture
def _catalog_must_not_be_read(monkeypatch):
    def _refuse(*args, **kwargs):
        raise AssertionError("the catalog was read while the platform was paused")

    for name in ("get_catalogs", "get_db_schemas", "get_tables"):
        monkeypatch.setattr(metadata, name, _refuse)


def _run(client, descriptor, options):
    info = client.get_flight_info(descriptor, options)
    return client.do_get(info.endpoints[0].ticket, options).read_all()


# -- operational -------------------------------------------------------------


def test_operational_allows_a_query(flight_server, auth_options, switch):
    _, client = flight_server
    assert _run(client, statement_query_descriptor(READ_SQL), auth_options).num_rows == 9


def test_operational_allows_metadata(flight_server, auth_options, switch):
    _, client = flight_server
    table = _run(client, command_descriptor(fsql.CommandGetTableTypes()), auth_options)
    assert table.column("table_type").to_pylist() == ["TABLE", "VIEW"]


def test_operational_does_not_parse_the_statement(flight_server, auth_options, switch, monkeypatch):
    # The normal path must pay nothing for the switch beyond the check itself.
    def _no_parse(sql):
        raise AssertionError("analyze_query was called while operational")

    monkeypatch.setattr(server.opteryx, "analyze_query", _no_parse)
    _, client = flight_server
    assert _run(client, statement_query_descriptor(READ_SQL), auth_options).num_rows == 9


# -- read_only ---------------------------------------------------------------


def test_read_only_allows_a_query(flight_server, auth_options, switch):
    switch.mode = pm.READ_ONLY
    _, client = flight_server
    assert _run(client, statement_query_descriptor(READ_SQL), auth_options).num_rows == 9


def test_read_only_allows_a_prepared_query(flight_server, auth_options, switch):
    switch.mode = pm.READ_ONLY
    _, client = flight_server
    result = create_prepared_statement(client, READ_SQL, auth_options)
    table = _run(client, prepared_query_descriptor(result.prepared_statement_handle), auth_options)
    assert table.num_rows == 9


def test_read_only_allows_metadata(flight_server, auth_options, switch):
    switch.mode = pm.READ_ONLY
    _, client = flight_server
    table = _run(client, command_descriptor(fsql.CommandGetTableTypes()), auth_options)
    assert table.num_rows == 2


def test_read_only_refuses_a_write_statement(flight_server, auth_options, switch):
    # Refused by the switch, before opteryx sees it -- not by the connector's
    # own read-only error (tests/test_read_only.py), which would say "does not support".
    switch.mode = pm.READ_ONLY
    _, client = flight_server
    with pytest.raises(fl.FlightUnavailableError, match="read-only maintenance"):
        client.get_flight_info(statement_query_descriptor(WRITE_SQL), auth_options)
    with pytest.raises(fl.FlightUnavailableError, match="read-only maintenance"):
        create_prepared_statement(client, WRITE_SQL, auth_options)


@pytest.mark.parametrize(
    "sql, operation",
    [
        ("SELECT 1", pm.READ),
        ("SHOW TABLES", pm.READ),
        ("INSERT INTO a.b SELECT 1", pm.WRITE),
        ("CREATE TABLE a.b AS SELECT 1", pm.WRITE),
        ("DROP TABLE a.b", pm.WRITE),
        ("ANALYZE TABLE a.b", pm.WRITE),
        ("this is not sql", pm.WRITE),
    ],
)
def test_statements_are_classified_when_not_operational(switch, sql, operation):
    switch.mode = pm.READ_ONLY
    assert server._statement_operation(sql) == operation


# -- reject / queue ----------------------------------------------------------


@pytest.mark.parametrize("mode", [pm.REJECT, pm.QUEUE])
def test_paused_refuses_a_query(flight_server, auth_options, switch, mode):
    switch.mode = mode
    _, client = flight_server
    with pytest.raises(fl.FlightUnavailableError, match="paused for maintenance"):
        client.get_flight_info(statement_query_descriptor(READ_SQL), auth_options)


@pytest.mark.parametrize("mode", [pm.REJECT, pm.QUEUE])
def test_paused_refuses_a_prepared_statement(flight_server, auth_options, switch, mode):
    switch.mode = mode
    _, client = flight_server
    with pytest.raises(fl.FlightUnavailableError, match="paused for maintenance"):
        create_prepared_statement(client, READ_SQL, auth_options)


@pytest.mark.parametrize("mode", [pm.REJECT, pm.QUEUE])
@pytest.mark.parametrize("command", METADATA_COMMANDS, ids=lambda c: type(c).__name__)
def test_paused_refuses_metadata(
    flight_server, auth_options, switch, _catalog_must_not_be_read, mode, command
):
    switch.mode = mode
    _, client = flight_server
    with pytest.raises(fl.FlightUnavailableError, match="paused for maintenance"):
        client.get_flight_info(command_descriptor(command), auth_options)


@pytest.mark.parametrize(
    "descriptor",
    [statement_query_descriptor(READ_SQL), command_descriptor(fsql.CommandGetTableTypes())],
    ids=["statement", "metadata"],
)
def test_do_get_is_gated_on_its_own(flight_server, auth_options, switch, descriptor):
    # A ticket issued while operational is not a pass through a pause that
    # began after it was issued: DoGet checks the switch again.
    _, client = flight_server
    info = client.get_flight_info(descriptor, auth_options)
    switch.mode = pm.REJECT
    with pytest.raises(fl.FlightUnavailableError, match="paused for maintenance"):
        client.do_get(info.endpoints[0].ticket, auth_options).read_all()


def test_prepared_do_get_is_gated_on_its_own(flight_server, auth_options, switch):
    _, client = flight_server
    result = create_prepared_statement(client, READ_SQL, auth_options)
    info = client.get_flight_info(
        prepared_query_descriptor(result.prepared_statement_handle), auth_options
    )
    switch.mode = pm.QUEUE
    with pytest.raises(fl.FlightUnavailableError):
        client.get_flight_info(
            prepared_query_descriptor(result.prepared_statement_handle), auth_options
        )
    with pytest.raises(fl.FlightUnavailableError):
        client.do_get(info.endpoints[0].ticket, auth_options).read_all()


def test_refusal_carries_retry_after(flight_server, auth_options, switch):
    switch.mode = pm.REJECT
    _, client = flight_server
    with pytest.raises(fl.FlightUnavailableError) as exc_info:
        client.get_flight_info(statement_query_descriptor(READ_SQL), auth_options)
    assert f"Retry after {pm.DEFAULT_RETRY_AFTER_SECONDS}s" in str(exc_info.value)


# -- re-read on every call ---------------------------------------------------


def test_mode_is_reread_on_every_call(flight_server, auth_options, switch):
    _, client = flight_server
    descriptor = statement_query_descriptor(READ_SQL)

    assert _run(client, descriptor, auth_options).num_rows == 9

    switch.mode = pm.REJECT
    with pytest.raises(fl.FlightUnavailableError):
        client.get_flight_info(descriptor, auth_options)

    switch.mode = pm.OPERATIONAL
    assert _run(client, descriptor, auth_options).num_rows == 9


def test_checked_at_call_time_not_at_import(flight_server, auth_options, switch, monkeypatch):
    # Every call reads `platform_mode.current` exactly once, looked up on the
    # module each time -- so nothing can have captured the mode at import or
    # startup, and one snapshot decides both classification and refusal.
    calls = []
    real_current = pm.current
    monkeypatch.setattr(pm, "current", lambda: calls.append(1) or real_current())
    _, client = flight_server

    _run(client, statement_query_descriptor(READ_SQL), auth_options)
    _run(client, command_descriptor(fsql.CommandGetTableTypes()), auth_options)

    # GetFlightInfo + DoGet, twice.
    assert len(calls) == 4
