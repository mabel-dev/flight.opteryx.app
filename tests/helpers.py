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
