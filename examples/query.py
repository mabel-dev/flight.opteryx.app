#!/usr/bin/env python3
"""Example Arrow Flight SQL client for flight.opteryx.

Demonstrates the two-step Flight SQL request pattern this service implements
(see docs/design.md, "Command surface"): `GetFlightInfo` first, to get the
result schema and an opaque per-query ticket, then `DoGet` with that ticket
to stream the actual Arrow data.

This talks to the *server's* protocol directly via `pyarrow.flight` -- it is
not how a real BI tool would connect (those use the upstream Flight SQL
JDBC/ADBC drivers, which speak this same wire protocol but hide the
GetFlightInfo/DoGet split behind a normal SQL API). It exists to make the
protocol concrete, and as a smoke test you can run against a live
deployment.

Usage:
    python examples/query.py "SELECT * FROM \\$planets LIMIT 5" --token "$FLIGHT_TOKEN"
    python examples/query.py "SELECT 1" --url grpc+tls://flight.opteryx.app:443 --token "$FLIGHT_TOKEN"

A token is required -- unlike odata.opteryx, this service has no anonymous
access (see docs/design.md, "Auth design"). Get one via the client_credentials
grant (see README.md, "Local development") and set it as FLIGHT_TOKEN.

Environment variables (used when the matching flag is omitted):
    FLIGHT_SERVER_URL   Same as --url. Defaults to grpc+tls://flight.opteryx.app:443.
    FLIGHT_TOKEN        Same as --token. A bearer JWT; required.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyarrow as pa
import pyarrow.flight as fl
from google.protobuf import any_pb2

from app.flight.proto import FlightSql_pb2 as fsql

DEFAULT_SERVER_URL = "grpc+tls://flight.opteryx.app:443"


def run_query(url: str, sql: str, token: str | None = None) -> pa.Table:
    """Execute `sql` against a flight.opteryx server and return the result as
    a `pyarrow.Table`.
    """
    client = fl.FlightClient(url)

    options = None
    if token:
        options = fl.FlightCallOptions(headers=[(b"authorization", f"Bearer {token}".encode())])

    command = fsql.CommandStatementQuery(query=sql)
    any_command = any_pb2.Any()
    any_command.Pack(command)
    descriptor = fl.FlightDescriptor.for_command(any_command.SerializeToString())

    # Step 1: GetFlightInfo -- returns the result schema and a ticket for DoGet.
    info = client.get_flight_info(descriptor, options)

    # Step 2: DoGet -- redeem the ticket for the actual Arrow data.
    reader = client.do_get(info.endpoints[0].ticket, options)
    return reader.read_all()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a SQL query against flight.opteryx")
    parser.add_argument("sql", help="SQL query to execute")
    parser.add_argument(
        "--url",
        default=os.environ.get("FLIGHT_SERVER_URL", DEFAULT_SERVER_URL),
        help=f"Flight SQL server URL (default: {DEFAULT_SERVER_URL})",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("FLIGHT_TOKEN"),
        help="Bearer JWT (required -- no anonymous access; see README.md)",
    )
    args = parser.parse_args()

    if not args.token:
        print(
            "Error: --token (or $FLIGHT_TOKEN) is required -- this service has no "
            "anonymous access. See README.md, \"Local development\", for how to get one.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    try:
        table = run_query(args.url, args.sql, args.token)
    except fl.FlightError as exc:
        print(f"Query failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(table)
    print(f"\n({table.num_rows} row{'s' if table.num_rows != 1 else ''})")


if __name__ == "__main__":
    main()
