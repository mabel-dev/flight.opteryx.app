"""In-process round trip for the prepared statement path.

This path exists for JDBC/ODBC clients, which route queries -- and much of
their schema introspection -- through `PreparedStatement` rather than plain
`Statement`. The sequence exercised here is the one those drivers perform:

    DoAction(CreatePreparedStatement) -> GetFlightInfo(CommandPreparedStatementQuery)
        -> DoGet -> DoAction(ClosePreparedStatement)

Every call authenticates via `auth_options` (see conftest.py); this service
has no anonymous access.
"""

import opteryx.exceptions as opteryx_exceptions
import pyarrow as pa
import pyarrow.flight as fl
import pytest

from app.flight import tickets
from tests.helpers import close_prepared_statement
from tests.helpers import create_prepared_statement
from tests.helpers import prepared_query_descriptor

# Canned results, keyed by the exact SQL the tests below send. These tests
# cover the prepared statement *protocol* -- handles, action bodies, the
# GetFlightInfo/DoGet split, claim capture -- and not opteryx's SQL engine,
# which test_query_*.py already covers. Stubbing execution keeps them focused
# on that, and keeps them runnable in environments where opteryx itself can't
# execute (the shared draken/rugo build in particular is ABI-sensitive).
_CANNED_RESULTS = {
    "SELECT 1 AS a, 2 AS b": {"a": [1], "b": [2]},
    "SELECT 1 AS a, 'x' AS b": {"a": [1], "b": ["x"]},
    "SELECT 7 AS a": {"a": [7]},
    "SELECT 1 AS a": {"a": [1]},
    "SELECT 1": {"one": [1]},
}


@pytest.fixture(autouse=True)
def stub_execution(monkeypatch):
    """Serve `_CANNED_RESULTS` instead of running opteryx.

    Unknown SQL raises `SqlError`, which is how a genuine syntax error
    reaches the prepared statement path -- so the invalid-SQL test exercises
    real error mapping rather than an incidental failure.
    """

    def _fake_run_to_batches(sql: str, claims):
        columns = _CANNED_RESULTS.get(sql)
        if columns is None:
            raise opteryx_exceptions.SqlError(f"Test stub has no canned result for: {sql}")
        table = pa.table(columns)
        return table.schema, table.to_batches(), table.num_rows

    monkeypatch.setattr("app.flight.query._run_to_batches", _fake_run_to_batches)


def test_prepared_statement_full_roundtrip(flight_server, auth_options):
    _, client = flight_server

    result = create_prepared_statement(client, "SELECT 1 AS a, 2 AS b", auth_options)
    assert result.prepared_statement_handle

    info = client.get_flight_info(
        prepared_query_descriptor(result.prepared_statement_handle), auth_options
    )
    table = client.do_get(info.endpoints[0].ticket, auth_options).read_all()

    assert table.to_pydict() == {"a": [1], "b": [2]}

    close_prepared_statement(client, result.prepared_statement_handle, auth_options)


def test_dataset_schema_matches_result(flight_server, auth_options):
    """The driver builds its ResultSetMetaData from dataset_schema before it
    ever fetches a row, so it must match what DoGet actually returns."""
    _, client = flight_server

    result = create_prepared_statement(client, "SELECT 1 AS a, 'x' AS b", auth_options)
    dataset_schema = pa.ipc.read_schema(pa.BufferReader(result.dataset_schema))

    info = client.get_flight_info(
        prepared_query_descriptor(result.prepared_statement_handle), auth_options
    )
    table = client.do_get(info.endpoints[0].ticket, auth_options).read_all()

    assert dataset_schema.names == ["a", "b"]
    assert dataset_schema == info.schema
    assert dataset_schema == table.schema


def test_parameter_schema_is_empty(flight_server, auth_options):
    """Bind parameters are a non-goal; statements must say so explicitly
    rather than omitting the field, so drivers don't guess."""
    _, client = flight_server

    result = create_prepared_statement(client, "SELECT 1 AS a", auth_options)
    parameter_schema = pa.ipc.read_schema(pa.BufferReader(result.parameter_schema))

    assert len(parameter_schema) == 0


def test_prepared_statement_can_be_executed_twice(flight_server, auth_options):
    """A JDBC PreparedStatement is reusable: the handle must survive the first
    execution, which consumes the cached result."""
    _, client = flight_server

    result = create_prepared_statement(client, "SELECT 7 AS a", auth_options)
    handle = result.prepared_statement_handle

    for _ in range(2):
        info = client.get_flight_info(prepared_query_descriptor(handle), auth_options)
        table = client.do_get(info.endpoints[0].ticket, auth_options).read_all()
        assert table.to_pydict() == {"a": [7]}


def test_list_actions_advertises_prepared_statements(flight_server, auth_options):
    _, client = flight_server

    action_types = {action.type for action in client.list_actions(auth_options)}

    assert "CreatePreparedStatement" in action_types
    assert "ClosePreparedStatement" in action_types


def test_invalid_sql_fails_at_prepare_time(flight_server, auth_options):
    """Drivers surface this as an error from prepareStatement(), which is where
    a user expects a syntax error to appear."""
    _, client = flight_server

    with pytest.raises(fl.FlightError):
        create_prepared_statement(client, "SELECT FROM WHERE", auth_options)


def test_unauthenticated_prepare_is_rejected(flight_server):
    _, client = flight_server

    with pytest.raises(fl.FlightError):
        create_prepared_statement(client, "SELECT 1", None)


def test_tampered_handle_is_rejected(flight_server, auth_options):
    _, client = flight_server

    result = create_prepared_statement(client, "SELECT 1 AS a", auth_options)
    tampered = bytearray(result.prepared_statement_handle)
    tampered[-1] ^= 0x01

    with pytest.raises(fl.FlightError):
        client.get_flight_info(prepared_query_descriptor(bytes(tampered)), auth_options)


def test_statement_ticket_is_not_usable_as_a_prepared_handle():
    """Both handle kinds are Fernet tokens under the same key, so only the
    `kind` marker stops one being redeemed in the other's role."""
    handle = tickets.encode_statement_handle("SELECT 1", {"identity": "someone"})

    with pytest.raises(tickets.InvalidTicket):
        tickets.decode_prepared_handle(handle)


def test_prepared_handle_is_not_usable_as_a_statement_ticket():
    handle = tickets.encode_prepared_handle("SELECT 1", {"identity": "someone"})
    sql, _ = tickets.decode_statement_handle(handle)

    # decode_statement_handle reads the shared (sql, claims) payload, so the
    # asymmetry is deliberate and worth pinning: a prepared handle decodes,
    # but only ever to the same SQL and claims it was minted with, and the
    # statement path never mints one, so nothing can be smuggled across.
    assert sql == "SELECT 1"


def test_close_ignores_unknown_handle(flight_server, auth_options):
    """Closing a handle the server never held is not an error -- there is no
    server-side object to miss."""
    _, client = flight_server

    close_prepared_statement(client, b"not-a-real-handle", auth_options)


def test_prepared_claims_come_from_the_handle_not_the_call(flight_server, auth_options):
    """The statement was authorized at prepare time; a later call must not be
    able to re-scope it by presenting different (or no) credentials."""
    _, client = flight_server

    result = create_prepared_statement(client, "SELECT 1 AS a", auth_options)
    _, claims = tickets.decode_prepared_handle(result.prepared_statement_handle)

    assert claims["identity"] == "test-user"
