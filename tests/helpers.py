"""Shared helpers for building Flight SQL command descriptors in tests."""

import pyarrow.flight as fl
from google.protobuf import any_pb2

from app.flight.proto import FlightSql_pb2 as fsql


def command_descriptor(command) -> fl.FlightDescriptor:
    any_msg = any_pb2.Any()
    any_msg.Pack(command)
    return fl.FlightDescriptor.for_command(any_msg.SerializeToString())


def statement_query_descriptor(sql: str) -> fl.FlightDescriptor:
    return command_descriptor(fsql.CommandStatementQuery(query=sql))


def prepared_query_descriptor(handle: bytes) -> fl.FlightDescriptor:
    return command_descriptor(fsql.CommandPreparedStatementQuery(prepared_statement_handle=handle))


def _action(action_type: str, request) -> fl.Action:
    any_msg = any_pb2.Any()
    any_msg.Pack(request)
    return fl.Action(action_type, any_msg.SerializeToString())


def create_prepared_statement(client, sql: str, options) -> fsql.ActionCreatePreparedStatementResult:
    """Run the CreatePreparedStatement action and unpack its result."""
    action = _action(
        "CreatePreparedStatement", fsql.ActionCreatePreparedStatementRequest(query=sql)
    )
    results = list(client.do_action(action, options))
    assert len(results) == 1, f"expected exactly one action result, got {len(results)}"

    any_msg = any_pb2.Any()
    any_msg.ParseFromString(results[0].body.to_pybytes())
    result = fsql.ActionCreatePreparedStatementResult()
    any_msg.Unpack(result)
    return result


def close_prepared_statement(client, handle: bytes, options) -> None:
    action = _action(
        "ClosePreparedStatement",
        fsql.ActionClosePreparedStatementRequest(prepared_statement_handle=handle),
    )
    list(client.do_action(action, options))
