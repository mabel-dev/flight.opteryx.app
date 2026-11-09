#!/usr/bin/env python3
"""Smoke test a deployed flight.opteryx with a real bearer token.

Covers the paths a JDBC/ODBC client uses on connect and query: a statement
query, the metadata commands, and the prepared statement round trip. With a
second token for a *different* identity it also checks that one caller's
ticket and prepared handle are refused for the other.

Usage:
    FLIGHT_TOKEN=... python examples/smoke_test.py
    FLIGHT_TOKEN=... FLIGHT_TOKEN_OTHER=... python examples/smoke_test.py
    python examples/smoke_test.py --url grpc://localhost:8815

Exits non-zero if any check fails.
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyarrow as pa
import pyarrow.flight as fl
from google.protobuf import any_pb2

from app.flight.proto import FlightSql_pb2 as fsql

DEFAULT_SERVER_URL = "grpc+tls://flight.opteryx.app:443"


def _options(token: str) -> fl.FlightCallOptions:
    return fl.FlightCallOptions(headers=[(b"authorization", f"Bearer {token}".encode())])


def _descriptor(command) -> fl.FlightDescriptor:
    any_msg = any_pb2.Any()
    any_msg.Pack(command)
    return fl.FlightDescriptor.for_command(any_msg.SerializeToString())


def _fetch(client, descriptor, opts) -> pa.Table:
    info = client.get_flight_info(descriptor, opts)
    return client.do_get(info.endpoints[0].ticket, opts).read_all()


def _action(client, action_type: str, request, opts):
    any_msg = any_pb2.Any()
    any_msg.Pack(request)
    return list(client.do_action(fl.Action(action_type, any_msg.SerializeToString()), opts))


def _prepare(client, sql: str, opts) -> fsql.ActionCreatePreparedStatementResult:
    results = _action(
        client, "CreatePreparedStatement", fsql.ActionCreatePreparedStatementRequest(query=sql), opts
    )
    any_msg = any_pb2.Any()
    any_msg.ParseFromString(results[0].body.to_pybytes())
    result = fsql.ActionCreatePreparedStatementResult()
    any_msg.Unpack(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=os.environ.get("FLIGHT_SERVER_URL", DEFAULT_SERVER_URL))
    parser.add_argument("--token", default=os.environ.get("FLIGHT_TOKEN"))
    parser.add_argument("--other-token", default=os.environ.get("FLIGHT_TOKEN_OTHER"))
    args = parser.parse_args()
    if not args.token:
        parser.error("a token is required: pass --token or set FLIGHT_TOKEN")

    client = fl.FlightClient(args.url)
    opts = _options(args.token)
    failures = 0

    def check(name, fn):
        nonlocal failures
        try:
            detail = fn()
            print(f"PASS  {name}" + (f"  ({detail})" if detail else ""))
        except Exception as exc:  # noqa: BLE001 - report every failure and keep going
            failures += 1
            print(f"FAIL  {name}: {type(exc).__name__}: {str(exc).splitlines()[0][:160]}")
            if os.environ.get("SMOKE_VERBOSE"):
                traceback.print_exc()

    def statement():
        table = _fetch(client, _descriptor(fsql.CommandStatementQuery(query="SELECT * FROM $planets")), opts)
        assert table.num_rows == 9, f"expected 9 planets, got {table.num_rows}"
        return f"{table.num_rows} rows, {table.num_columns} columns"

    def sql_info():
        return f"{_fetch(client, _descriptor(fsql.CommandGetSqlInfo()), opts).num_rows} info rows"

    def catalogs():
        return f"{_fetch(client, _descriptor(fsql.CommandGetCatalogs()), opts).num_rows} catalogs"

    def schemas():
        return f"{_fetch(client, _descriptor(fsql.CommandGetDbSchemas()), opts).num_rows} schemas"

    def tables():
        return f"{_fetch(client, _descriptor(fsql.CommandGetTables()), opts).num_rows} tables"

    def table_types():
        types = _fetch(client, _descriptor(fsql.CommandGetTableTypes()), opts).column(0).to_pylist()
        assert set(types) == {"TABLE", "VIEW"}, types
        return ", ".join(types)

    def prepared():
        result = _prepare(client, "SELECT id, name FROM $planets", opts)
        handle = result.prepared_statement_handle
        descriptor = _descriptor(fsql.CommandPreparedStatementQuery(prepared_statement_handle=handle))
        first = _fetch(client, descriptor, opts)
        second = _fetch(client, descriptor, opts)  # re-execute the same handle
        assert first.num_rows == second.num_rows == 9, (first.num_rows, second.num_rows)
        _action(
            client,
            "ClosePreparedStatement",
            fsql.ActionClosePreparedStatementRequest(prepared_statement_handle=handle),
            opts,
        )
        return "prepare, execute twice, close"

    def write_refused():
        try:
            _fetch(client, _descriptor(fsql.CommandStatementQuery(query="DROP TABLE $planets")), opts)
        except fl.FlightError as exc:
            return f"refused: {str(exc).splitlines()[0][:60]}"
        raise AssertionError("DROP TABLE was accepted")

    check("statement query", statement)
    check("GetSqlInfo", sql_info)
    check("GetCatalogs", catalogs)
    check("GetDbSchemas", schemas)
    check("GetTables", tables)
    check("GetTableTypes", table_types)
    check("prepared statement", prepared)
    check("write SQL refused", write_refused)

    if args.other_token:
        other = _options(args.other_token)

        def ticket_bound():
            info = client.get_flight_info(
                _descriptor(fsql.CommandStatementQuery(query="SELECT 1 AS x")), opts
            )
            try:
                client.do_get(info.endpoints[0].ticket, other).read_all()
            except fl.FlightUnauthorizedError:
                return "other identity refused"
            raise AssertionError("another identity redeemed this caller's ticket")

        def handle_bound():
            handle = _prepare(client, "SELECT 1 AS x", opts).prepared_statement_handle
            descriptor = _descriptor(fsql.CommandPreparedStatementQuery(prepared_statement_handle=handle))
            try:
                client.get_flight_info(descriptor, other)
            except fl.FlightUnauthorizedError:
                return "other identity refused"
            raise AssertionError("another identity executed this caller's prepared statement")

        check("ticket bound to caller", ticket_bound)
        check("prepared handle bound to caller", handle_bound)
    else:
        print("SKIP  caller-binding checks (set FLIGHT_TOKEN_OTHER to a different identity's token)")

    print(f"\n{'all checks passed' if not failures else f'{failures} check(s) failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
