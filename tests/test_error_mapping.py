"""How failures reach the client as Flight status codes.

A JDBC/ODBC driver's retry and reconnect behaviour is driven entirely by the
Flight status class it gets back, so the mapping matters as much as the
message. `app.flight.server._map_opteryx_exception` is the single place that
decides it, and it was previously untested.

The mapping is deliberately coarse -- see `_map_opteryx_exception`'s own
docstring: pyarrow's Python Flight bindings expose no INVALID_ARGUMENT
equivalent, so a client-fixable SQL error and a server-side failure both
arrive as `FlightServerError`. That is a known limitation, not a bug, and
these tests pin it so a pyarrow upgrade that DID expose a richer vocabulary
shows up as a failure worth acting on rather than passing unnoticed.
"""

import opteryx.exceptions as opteryx_exceptions
import pyarrow.flight as fl
import pytest

from app.auth.errors import AuthError
from app.flight import tickets
from app.flight.proto import FlightSql_pb2 as fsql
from app.flight.server import _map_opteryx_exception
from tests.helpers import command_descriptor
from tests.helpers import statement_query_descriptor


# -- the mapping function itself ---------------------------------------------


def test_permissions_error_maps_to_unauthorized():
    # The one distinction the mapping does draw, and the important one:
    # "you are not allowed to do that" must not look like "the server broke",
    # or a driver will retry a refusal forever.
    mapped = _map_opteryx_exception(opteryx_exceptions.PermissionsError("nope"))
    assert isinstance(mapped, fl.FlightUnauthorizedError)
    assert "nope" in str(mapped)


@pytest.mark.parametrize(
    "exc",
    [
        opteryx_exceptions.SqlError("bad sql"),
        opteryx_exceptions.UnsupportedSyntaxError("bad syntax"),
        opteryx_exceptions.DatasetNotFoundError("nosuch"),
        opteryx_exceptions.ColumnNotFoundError("nocolumn"),
        opteryx_exceptions.ReadOnlyConnectorError("read only"),
        RuntimeError("something else"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_everything_else_maps_to_server_error(exc):
    mapped = _map_opteryx_exception(exc)
    assert isinstance(mapped, fl.FlightServerError)
    assert not isinstance(mapped, fl.FlightUnauthorizedError)


def test_the_original_message_always_survives():
    # The status code is coarser than ideal, so the message is the only thing
    # telling the user why their query was rejected. It must not be swallowed.
    for exc in (
        opteryx_exceptions.SqlError("column WIDGET does not exist"),
        opteryx_exceptions.PermissionsError("no grant on acme.hr"),
    ):
        assert str(exc) in str(_map_opteryx_exception(exc))


def test_read_only_refusals_are_not_reported_as_permission_errors():
    # `ReadOnlyConnectorError` is a DatabaseError, not a PermissionsError, so
    # it falls through to FlightServerError. Pinned deliberately: a client
    # must not be told it merely lacks a grant when the service will never
    # accept the statement from anyone.
    mapped = _map_opteryx_exception(opteryx_exceptions.ReadOnlyConnectorError("no writes"))
    assert not isinstance(mapped, fl.FlightUnauthorizedError)


# -- auth failures -----------------------------------------------------------


def test_auth_failure_is_unauthenticated_not_a_server_error(flight_server):
    # Distinct from FlightUnauthorizedError above: this is "we do not know who
    # you are", which is what makes a driver re-prompt for credentials.
    _, client = flight_server
    with pytest.raises(fl.FlightUnauthenticatedError):
        client.get_flight_info(statement_query_descriptor("SELECT 1"))


def test_auth_error_status_codes_map_as_documented():
    from app.flight.auth_middleware import _flight_error_for

    assert isinstance(_flight_error_for(AuthError(401, "x")), fl.FlightUnauthenticatedError)
    assert isinstance(_flight_error_for(AuthError(403, "x")), fl.FlightUnauthenticatedError)
    # 503 is the external auth service being down -- a server-side failure the
    # client may usefully retry, unlike a credential problem.
    error = _flight_error_for(AuthError(503, "auth down"))
    assert isinstance(error, fl.FlightServerError)
    assert not isinstance(error, fl.FlightUnauthenticatedError)


# -- bad input at the wire level ---------------------------------------------


def test_invalid_sql_is_refused_with_its_reason(flight_server, auth_options):
    _, client = flight_server
    with pytest.raises(fl.FlightError) as exc_info:
        client.get_flight_info(statement_query_descriptor("SELECT FROM WHERE"), auth_options)
    assert "Invalid query" in str(exc_info.value)


# Not tested here: what a client gets for a relation that does not exist.
# Resolving an unknown three-part name sends opteryx to the catalog, which
# means a real Firestore client and a real GCP credential exchange -- this
# test was written, observed reaching oauth2.googleapis.com, and removed. It
# needs the catalog connector faked, which is the same missing fixture that
# leaves the GetCatalogs/GetDbSchemas/GetTables Firestore path untested; see
# the gaps reported alongside this change.


def test_garbage_descriptor_is_refused_not_crashed(flight_server, auth_options):
    _, client = flight_server
    descriptor = fl.FlightDescriptor.for_command(b"\xff\xfe not a protobuf at all")
    with pytest.raises(fl.FlightError) as exc_info:
        client.get_flight_info(descriptor, auth_options)
    assert "Malformed command descriptor" in str(exc_info.value)


def test_empty_descriptor_is_refused(flight_server, auth_options):
    _, client = flight_server
    with pytest.raises(fl.FlightError):
        client.get_flight_info(fl.FlightDescriptor.for_command(b""), auth_options)


def test_unknown_command_type_is_refused(flight_server, auth_options):
    # A Flight SQL command this server does not implement (cross-references,
    # primary keys, XDBC type info -- all things a driver may probe for).
    _, client = flight_server
    for command in (
        fsql.CommandGetPrimaryKeys(),
        fsql.CommandGetImportedKeys(),
        fsql.CommandGetCrossReference(),
        fsql.CommandGetXdbcTypeInfo(),
    ):
        with pytest.raises(fl.FlightError) as exc_info:
            client.get_flight_info(command_descriptor(command), auth_options)
        assert "Unsupported or unrecognized command type" in str(exc_info.value)


# -- tickets -----------------------------------------------------------------


def test_garbage_ticket_is_refused(flight_server, auth_options):
    _, client = flight_server
    with pytest.raises(fl.FlightError) as exc_info:
        client.do_get(fl.Ticket(b"not-a-ticket-at-all"), auth_options)
    assert "Invalid or expired" in str(exc_info.value)


def test_a_tampered_statement_ticket_is_refused(flight_server, auth_options):
    # The property the whole ticket design rests on: a client must not be able
    # to edit the SQL or the claims inside a ticket it was legitimately issued.
    _, client = flight_server
    info = client.get_flight_info(statement_query_descriptor("SELECT 1 AS a"), auth_options)
    ticket = info.endpoints[0].ticket.ticket

    flipped = bytearray(ticket)
    flipped[-1] ^= 0x01
    with pytest.raises(fl.FlightError):
        client.do_get(fl.Ticket(bytes(flipped)), auth_options)


def test_an_expired_ticket_is_refused(monkeypatch):
    # TTL enforcement, tested at the ticket layer rather than through a client
    # so the clock does not have to be waited out.
    # A negative TTL, not 0: Fernet expires a token when
    # `timestamp + ttl < now`, so a ttl of 0 leaves a just-minted token valid
    # for the remainder of its issuing second and the test would be a
    # coin-flip on clock granularity.
    handle = tickets.encode_statement_handle("SELECT 1", {"identity": "u"})
    monkeypatch.setenv("FLIGHT_TICKET_TTL_SECONDS", "-1")
    with pytest.raises(tickets.InvalidTicket):
        tickets.decode_statement_handle(handle)

    # And the same handle is still good under the real TTL, so the test above
    # is about expiry and not about the handle being broken.
    monkeypatch.setenv("FLIGHT_TICKET_TTL_SECONDS", "300")
    assert tickets.decode_statement_handle(handle)[0] == "SELECT 1"


def test_claims_come_from_the_ticket_not_from_the_do_get_call(flight_server, auth_options):
    """A statement ticket carries the claims that were live when it was minted.

    `do_get` deliberately ignores whatever Authorization metadata accompanies
    it (see `app.flight.server`'s module docstring). The prepared-statement
    half of this is covered in test_prepared_statement.py; this is the plain
    statement half, which was not.
    """
    server, client = flight_server
    info = client.get_flight_info(statement_query_descriptor("SELECT 1 AS a"), auth_options)
    ticket = info.endpoints[0].ticket

    sql, claims = tickets.decode_statement_handle(
        _statement_handle_from_ticket(ticket.ticket)
    )
    assert sql == "SELECT 1 AS a"
    assert claims["identity"] == "test-user"

    # The cached result is consumed by the first DoGet; a second one
    # re-executes from the ticket, still under the ticket's own claims.
    assert client.do_get(ticket, auth_options).read_all().to_pydict() == {"a": [1]}
    assert client.do_get(ticket, auth_options).read_all().to_pydict() == {"a": [1]}


def _statement_handle_from_ticket(ticket_bytes: bytes) -> bytes:
    from google.protobuf import any_pb2

    any_msg = any_pb2.Any()
    any_msg.ParseFromString(ticket_bytes)
    statement = fsql.TicketStatementQuery()
    any_msg.Unpack(statement)
    return statement.statement_handle
