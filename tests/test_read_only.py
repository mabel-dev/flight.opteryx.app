"""The read-only guarantee.

flight.opteryx is a read-only service. That is asserted in the README, in
docs/design.md, and -- to every JDBC/ODBC client that asks -- in the
`FLIGHT_SQL_SERVER_READ_ONLY` SqlInfo code this server answers `True` to.
Nothing in this repo previously tested that the guarantee actually holds,
so a write that got through would have been caught by nobody.

There are three separate doors a write could come in through, and each one
is closed by a different mechanism. All three are tested here:

  1. **The Flight SQL write commands.** `CommandStatementUpdate`,
     `CommandPreparedStatementUpdate`, `CommandStatementIngest` and
     `CommandStatementSubstraitPlan` are the spec's own mutation verbs. They
     are closed structurally: `app.flight.server._ALL_COMMAND_TYPES` simply
     does not list them, so `_unpack_command` refuses the descriptor before
     any claims, SQL or catalog are involved.

  2. **DoPut.** The bulk-ingestion RPC. Closed by an explicit check in
     `OpteryxFlightServer.do_put`, which accepts *only* a
     `CommandPreparedStatementQuery` descriptor (drivers send an empty
     parameter batch there as part of their execute path) and rejects
     everything else.

  3. **Write SQL smuggled through `CommandStatementQuery`.** This is the
     open door in the sense that matters: there is NO statement-level
     rejection anywhere in this repository. `CommandStatementQuery(query=...)`
     is passed verbatim to opteryx, and the refusal comes from opteryx-core's
     connector layer raising `ReadOnlyConnectorError`. These tests pin that
     behaviour end-to-end so that an opteryx-core upgrade which relaxed it
     would fail here rather than in production.

     Note what this does NOT cover, and see the module summary reported
     alongside this change: DDL/DCL verbs (`GRANT`, `REVOKE`, `DROP
     WORKSPACE`, `CREATE TABLE ... AS`) do not go through a connector, so
     `ReadOnlyConnectorError` never fires for them. They are dispatched into
     opteryx and refused -- if at all -- by catalog state and the engine's
     own permission capability, not by anything this service does.
"""

import pyarrow as pa
import pyarrow.flight as fl
import pytest

from app.flight.proto import FlightSql_pb2 as fsql
from tests.helpers import command_descriptor
from tests.helpers import create_prepared_statement
from tests.helpers import prepared_query_descriptor
from tests.helpers import statement_query_descriptor

# Statements that name a real, resolvable relation. `$planets` is one of
# opteryx's built-in sample datasets, so the refusal below is a genuine
# read-only refusal and not "the table does not exist" wearing a disguise --
# the distinction the whole guarantee rests on.
WRITE_STATEMENTS = [
    "INSERT INTO $planets (id) VALUES (99)",
    "UPDATE $planets SET id = 1",
    "DELETE FROM $planets WHERE id = 1",
    "DROP TABLE $planets",
]

# The Flight SQL command messages that mutate. Each is a message this
# server's vendored proto knows about but deliberately does not dispatch.
WRITE_COMMANDS = [
    fsql.CommandStatementUpdate(query="DELETE FROM $planets"),
    fsql.CommandPreparedStatementUpdate(prepared_statement_handle=b"whatever"),
    fsql.CommandStatementIngest(table="victims"),
    fsql.CommandStatementSubstraitPlan(),
]


# -- 1. the spec's write commands -------------------------------------------


@pytest.mark.parametrize("command", WRITE_COMMANDS, ids=lambda c: type(c).__name__)
def test_write_commands_are_refused_at_get_flight_info(flight_server, auth_options, command):
    _, client = flight_server
    with pytest.raises(fl.FlightError) as exc_info:
        client.get_flight_info(command_descriptor(command), auth_options)
    # Refused for being an unsupported *command*, not for anything about its
    # contents -- i.e. refused before the SQL inside it was ever looked at.
    assert "Unsupported or unrecognized command type" in str(exc_info.value)


@pytest.mark.parametrize("command", WRITE_COMMANDS, ids=lambda c: type(c).__name__)
def test_write_commands_are_refused_at_get_schema(flight_server, auth_options, command):
    # GetSchema shares get_flight_info's dispatch, so it must refuse the same
    # set. Worth asserting separately: a driver probing a table's shape goes
    # through GetSchema, and a divergence here would be a second front door.
    #
    # Caught as `ArrowException`, not `FlightError`: pyarrow's GetSchema
    # client wrapper flattens a server-raised FlightServerError into a bare
    # ArrowException, losing the Flight status class on the way back. That is
    # a pyarrow limitation, not this service's -- the message survives, so
    # that is what is asserted on.
    _, client = flight_server
    with pytest.raises(pa.ArrowException) as exc_info:
        client.get_schema(command_descriptor(command), auth_options)
    assert "Unsupported or unrecognized command type" in str(exc_info.value)


def test_write_commands_are_not_in_the_dispatch_table():
    # The structural half of the guarantee, asserted directly against the
    # table rather than through a client, so the reason a write command is
    # refused stays visible if the error text ever changes.
    from app.flight import server

    for command in WRITE_COMMANDS:
        assert type(command) not in server._ALL_COMMAND_TYPES


# -- 2. DoPut ----------------------------------------------------------------


def _put(client, descriptor, options):
    schema = pa.schema([pa.field("a", pa.int64())])
    writer, _ = client.do_put(descriptor, schema, options)
    try:
        writer.write_table(pa.table({"a": [1, 2, 3]}, schema=schema))
        writer.done_writing()
    finally:
        writer.close()


def test_do_put_with_a_statement_descriptor_is_refused(flight_server, auth_options):
    _, client = flight_server
    with pytest.raises(fl.FlightError) as exc_info:
        _put(client, statement_query_descriptor("SELECT 1"), auth_options)
    assert "read-only" in str(exc_info.value)


def test_do_put_with_a_path_descriptor_is_refused(flight_server, auth_options):
    # A path descriptor is how a client asks to write to a named table. There
    # is no ingestion path in this service, so this must be refused too --
    # and refused on the read-only check, not by falling off the end of
    # `_unpack_command` with a confusing protobuf error.
    _, client = flight_server
    with pytest.raises(fl.FlightError) as exc_info:
        _put(client, fl.FlightDescriptor.for_path("some", "table"), auth_options)
    assert "read-only" in str(exc_info.value)


def test_do_put_accepts_only_the_prepared_statement_parameter_stream(flight_server, auth_options):
    # The one descriptor DoPut tolerates, and the reason it does: drivers
    # send a (schema-only or empty) parameter batch as part of executing a
    # PreparedStatement. The rows must be discarded, never ingested.
    _, client = flight_server
    result = create_prepared_statement(client, "SELECT 1 AS a", auth_options)
    _put(client, prepared_query_descriptor(result.prepared_statement_handle), auth_options)

    # The three rows written above must not have become data: re-running the
    # statement returns exactly what the SQL says, and nothing else.
    info = client.get_flight_info(
        prepared_query_descriptor(result.prepared_statement_handle), auth_options
    )
    table = client.do_get(info.endpoints[0].ticket, auth_options).read_all()
    assert table.to_pydict() == {"a": [1]}


# -- 3. write SQL through CommandStatementQuery ------------------------------


@pytest.mark.parametrize("sql", WRITE_STATEMENTS)
def test_write_sql_is_refused_end_to_end(flight_server, auth_options, sql):
    # The caller here holds `owner` on `*` (see conftest.TEST_CLAIMS), which
    # is the strongest possible grant. The refusal must therefore come from
    # the service being read-only, not from the caller being under-privileged.
    _, client = flight_server
    with pytest.raises(fl.FlightError) as exc_info:
        client.get_flight_info(statement_query_descriptor(sql), auth_options)
    assert "does not support" in str(exc_info.value)


@pytest.mark.parametrize("sql", WRITE_STATEMENTS)
def test_write_sql_is_refused_through_the_prepared_statement_path(
    flight_server, auth_options, sql
):
    # Prepared statements are a second, independent execution path into
    # opteryx (ActionCreatePreparedStatement -> _execute_for_prepared_handle).
    # JDBC and ODBC clients route nearly everything through it, so a
    # read-only guarantee that held only for plain statements would be no
    # guarantee at all in practice.
    _, client = flight_server
    with pytest.raises(fl.FlightError) as exc_info:
        create_prepared_statement(client, sql, auth_options)
    assert "does not support" in str(exc_info.value)


def test_read_sql_against_the_same_relation_still_works(flight_server, auth_options):
    # The control for the two tests above: `$planets` really is reachable, so
    # their refusals are about the verb and not about the relation.
    _, client = flight_server
    info = client.get_flight_info(
        statement_query_descriptor("SELECT id FROM $planets"), auth_options
    )
    table = client.do_get(info.endpoints[0].ticket, auth_options).read_all()
    assert table.num_rows == 9


# -- the advertised contract -------------------------------------------------


def test_server_advertises_itself_as_read_only(flight_server, auth_options):
    # A client that asks "may I write?" must be told no. Drivers use this to
    # decide whether to offer editing UI at all, so the advert has to agree
    # with the behaviour tested above.
    _, client = flight_server
    descriptor = command_descriptor(
        fsql.CommandGetSqlInfo(info=[fsql.FLIGHT_SQL_SERVER_READ_ONLY])
    )
    info = client.get_flight_info(descriptor, auth_options)
    table = client.do_get(info.endpoints[0].ticket, auth_options).read_all()

    assert table.column("info_name").to_pylist() == [fsql.FLIGHT_SQL_SERVER_READ_ONLY]
    assert table.column("value").to_pylist() == [True]


def test_no_write_capable_action_is_advertised(flight_server, auth_options):
    # ListActions is the discovery surface for DoAction. Flight SQL's
    # write-adjacent actions (transactions, savepoints, Substrait plans)
    # must not appear: advertising one would invite a client to try it.
    _, client = flight_server
    action_types = {action.type for action in client.list_actions(auth_options)}
    assert action_types == {"CreatePreparedStatement", "ClosePreparedStatement"}


def test_unknown_action_is_refused(flight_server, auth_options):
    _, client = flight_server
    with pytest.raises(fl.FlightError) as exc_info:
        list(client.do_action(fl.Action("BeginTransaction", b""), auth_options))
    assert "Unsupported action type" in str(exc_info.value)
