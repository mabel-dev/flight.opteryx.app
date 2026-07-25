"""Flight SQL command dispatch.

**Why this hand-dispatches instead of subclassing a high-level Flight SQL
server base** (the design's "First implementation task"): the pinned
PyArrow build (25.0.0) was inspected directly (`dir(pyarrow.flight)`) and
exposes only base Flight primitives (`FlightServerBase`, `FlightDescriptor`,
`FlightInfo`, `FlightEndpoint`, `Ticket`, `GeneratorStream`,
`RecordBatchStream`, `ServerMiddleware(Factory)`, ...) — no class or method
with `Sql` in its name anywhere in the module. There is no high-level Flight
SQL server base to subclass in this environment. This is option 2 from
`docs/design.md`: `descriptor.command` is unpacked by hand as a
`google.protobuf.Any` against the Flight SQL protobuf message definitions,
which PyArrow does *not* bundle either (no `flight_sql*` files anywhere
under the installed `pyarrow` package) — they're vendored at
`app/flight/proto/FlightSql_pb2.py`, compiled from the upstream
`format/FlightSql.proto` and stamped for the protobuf runtime version this
project actually installs (protobuf 6.x, matching odata.opteryx's pin, so
the two services can keep sharing a Firestore/GCS dependency stack without
a protobuf version conflict).

**Ticket design**: `GetFlightInfo` executes eagerly (see
`app.flight.query.ResultCache`) and mints a ticket carrying an encrypted
`(sql, claims)` — or, for metadata commands, `(command, params, claims)` —
handle. Critically, `DoGet` uses the claims embedded in *that* ticket, not
whatever `Authorization` metadata happens to be present on the `DoGet` call
itself: the result being streamed back was already computed (or will be
re-computed on a cache miss) under the claims that were live when
`GetFlightInfo` ran, and using different, possibly-anonymous claims at
`DoGet` time would silently hand a caller data that was authorized for
someone else. Every call (including `DoGet`) still goes through
`ClaimsMiddlewareFactory`, but only to gate that the call is
structurally valid — same anonymous-tolerant policy as odata.opteryx.
"""

from __future__ import annotations

from typing import Optional

import opteryx.exceptions as opteryx_exceptions
import pyarrow as pa
import pyarrow.flight as fl
from google.protobuf import any_pb2

from app.flight import metadata
from app.flight import query
from app.flight import tickets
from app.flight.auth_middleware import ClaimsMiddlewareFactory
from app.flight.auth_middleware import claims_from_context
from app.flight.proto import FlightSql_pb2 as fsql
from app.logging import get_logger

logger = get_logger()

_METADATA_COMMAND_TYPES = (
    fsql.CommandGetSqlInfo,
    fsql.CommandGetCatalogs,
    fsql.CommandGetDbSchemas,
    fsql.CommandGetTables,
    fsql.CommandGetTableTypes,
)
_ALL_COMMAND_TYPES = (fsql.CommandStatementQuery,) + _METADATA_COMMAND_TYPES


def _unpack_command(command_bytes: bytes):
    """Unpack a `FlightDescriptor.command` (serialized `google.protobuf.Any`)
    into the matching Flight SQL command message, or raise if it's neither
    a known Flight SQL command nor parseable at all."""
    any_msg = any_pb2.Any()
    try:
        any_msg.ParseFromString(command_bytes)
    except Exception as exc:
        raise fl.FlightServerError(f"Malformed command descriptor: {exc}") from exc

    for message_cls in _ALL_COMMAND_TYPES:
        if any_msg.Is(message_cls.DESCRIPTOR):
            command = message_cls()
            any_msg.Unpack(command)
            return command

    raise fl.FlightServerError(f"Unsupported or unrecognized command type: {any_msg.type_url}")


def _map_opteryx_exception(exc: Exception) -> fl.FlightError:
    """Map opteryx's exception hierarchy onto the closest available
    `pyarrow.flight` error class. PyArrow's Python Flight bindings don't
    expose a full gRPC status vocabulary (no INVALID_ARGUMENT-equivalent),
    so SQL/type errors -- 400-equivalent, client-fixable -- fall back to
    `FlightServerError` like any other server-side failure; the original
    message is preserved so the client still sees why the query was
    rejected even though the status code itself is coarser than ideal.
    """
    if isinstance(exc, opteryx_exceptions.PermissionsError):
        return fl.FlightUnauthorizedError(str(exc))
    return fl.FlightServerError(str(exc))


class OpteryxFlightServer(fl.FlightServerBase):
    def __init__(self, location: Optional[str] = None, **kwargs):
        middleware = kwargs.pop("middleware", {})
        middleware.setdefault("auth", ClaimsMiddlewareFactory())
        super().__init__(location, middleware=middleware, **kwargs)
        self._location = location

    # -- GetFlightInfo --------------------------------------------------

    def get_flight_info(self, context: fl.ServerCallContext, descriptor: fl.FlightDescriptor) -> fl.FlightInfo:
        claims = claims_from_context(context)
        command = _unpack_command(descriptor.command)

        if isinstance(command, fsql.CommandStatementQuery):
            schema, ticket_bytes = self._prepare_statement_query(command, claims)
        else:
            schema, ticket_bytes = self._prepare_metadata_command(command, claims)

        endpoint = fl.FlightEndpoint(ticket=fl.Ticket(ticket_bytes), locations=[])
        return fl.FlightInfo(schema, descriptor, [endpoint], total_records=-1, total_bytes=-1)

    def get_schema(self, context: fl.ServerCallContext, descriptor: fl.FlightDescriptor) -> pa.Schema:
        # Same work as get_flight_info (opteryx has no plan-only path that
        # yields a result schema without executing -- see docs/design.md,
        # "Query execution & streaming design"), so this necessarily costs a
        # full GetFlightInfo-equivalent execution too.
        return self.get_flight_info(context, descriptor).schema

    def _prepare_statement_query(self, command: "fsql.CommandStatementQuery", claims: dict):
        sql = command.query
        handle = tickets.encode_statement_handle(sql, claims)
        try:
            schema = query.RESULT_CACHE.execute_and_cache(handle, sql, claims)
        except (opteryx_exceptions.SqlError, opteryx_exceptions.IncompatibleTypesError) as exc:
            raise fl.FlightServerError(f"Invalid query: {exc}") from exc
        except opteryx_exceptions.PermissionsError as exc:
            raise fl.FlightUnauthorizedError(str(exc)) from exc
        except Exception as exc:
            logger.error(f"Error executing statement query: {exc}")
            raise _map_opteryx_exception(exc) from exc

        ticket_msg = fsql.TicketStatementQuery(statement_handle=handle)
        any_msg = any_pb2.Any()
        any_msg.Pack(ticket_msg)
        return schema, any_msg.SerializeToString()

    def _prepare_metadata_command(self, command, claims: dict):
        table = _execute_metadata_command(command, claims)
        handle = tickets.encode_metadata_ticket(command, claims)
        query.RESULT_CACHE.put_table(handle, table)
        return table.schema, handle

    # -- DoGet ------------------------------------------------------------

    def do_get(self, context: fl.ServerCallContext, ticket: fl.Ticket) -> fl.FlightDataStream:
        ticket_bytes = ticket.ticket

        # A CommandStatementQuery ticket is a serialized Any(TicketStatementQuery);
        # anything else is one of our own opaque metadata-command handles (see
        # tickets.encode_metadata_ticket) -- try the spec'd shape first, and
        # treat any parse failure (metadata tickets are Fernet ciphertext, not
        # valid protobuf) as "not a statement ticket" rather than an error.
        any_msg = any_pb2.Any()
        is_statement_ticket = False
        try:
            any_msg.ParseFromString(ticket_bytes)
            is_statement_ticket = any_msg.Is(fsql.TicketStatementQuery.DESCRIPTOR)
        except Exception:
            is_statement_ticket = False

        if is_statement_ticket:
            ticket_stmt = fsql.TicketStatementQuery()
            any_msg.Unpack(ticket_stmt)
            return self._do_get_statement_query(ticket_stmt.statement_handle)

        return self._do_get_metadata(ticket_bytes)

    def _do_get_statement_query(self, handle: bytes) -> fl.FlightDataStream:
        try:
            sql, claims = tickets.decode_statement_handle(handle)
        except tickets.InvalidTicket as exc:
            raise fl.FlightServerError(f"Invalid or expired ticket: {exc}") from exc

        try:
            entry = query.RESULT_CACHE.get_or_execute(handle, sql, claims)
        except (opteryx_exceptions.SqlError, opteryx_exceptions.IncompatibleTypesError) as exc:
            raise fl.FlightServerError(f"Invalid query: {exc}") from exc
        except opteryx_exceptions.PermissionsError as exc:
            raise fl.FlightUnauthorizedError(str(exc)) from exc
        except Exception as exc:
            logger.error(f"Error executing statement query on DoGet: {exc}")
            raise _map_opteryx_exception(exc) from exc

        return fl.RecordBatchStream(pa.Table.from_batches(entry.batches, schema=entry.schema))

    def _do_get_metadata(self, handle: bytes) -> fl.FlightDataStream:
        try:
            command, claims = tickets.decode_metadata_ticket(handle)
        except tickets.InvalidTicket as exc:
            raise fl.FlightServerError(f"Invalid or expired ticket: {exc}") from exc

        entry = query.RESULT_CACHE.pop(handle)
        if entry is not None:
            return fl.RecordBatchStream(pa.Table.from_batches(entry.batches, schema=entry.schema))

        # Cache miss (different instance, or TTL expired): metadata commands are
        # cheap and idempotent, so just recompute rather than fail the call.
        table = _execute_metadata_command(command, claims)
        return fl.RecordBatchStream(table)

    # -- DoAction / ListActions -------------------------------------------
    # v1 has no CommandPreparedStatementQuery, DoPut ingestion, or
    # transactions (see docs/design.md, "Non-goals (v1)"), so there are no
    # custom Flight SQL actions to register; the base class's default
    # (NotImplementedError -> UNIMPLEMENTED) is correct as-is.


def _execute_metadata_command(command, claims: dict) -> pa.Table:
    if isinstance(command, fsql.CommandGetSqlInfo):
        info = list(command.info) if command.info else None
        return metadata.get_sql_info(info)
    if isinstance(command, fsql.CommandGetCatalogs):
        return metadata.get_catalogs(claims)
    if isinstance(command, fsql.CommandGetDbSchemas):
        catalog = command.catalog if command.HasField("catalog") else None
        pattern = (
            command.db_schema_filter_pattern if command.HasField("db_schema_filter_pattern") else None
        )
        return metadata.get_db_schemas(claims, catalog, pattern)
    if isinstance(command, fsql.CommandGetTables):
        catalog = command.catalog if command.HasField("catalog") else None
        db_schema_pattern = (
            command.db_schema_filter_pattern if command.HasField("db_schema_filter_pattern") else None
        )
        table_name_pattern = (
            command.table_name_filter_pattern
            if command.HasField("table_name_filter_pattern")
            else None
        )
        table_types = list(command.table_types) if command.table_types else None
        return metadata.get_tables(
            claims, catalog, db_schema_pattern, table_name_pattern, table_types, command.include_schema
        )
    if isinstance(command, fsql.CommandGetTableTypes):
        return metadata.get_table_types()
    raise fl.FlightServerError(f"Unsupported metadata command: {type(command).__name__}")
