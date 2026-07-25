# flight.opteryx

Arrow Flight SQL server for [Opteryx](https://opteryx.io), so ODBC/JDBC-capable
tools (BI tools, SQL IDEs, notebook drivers) can connect using the standard
Arrow Flight SQL JDBC driver / ADBC ODBC driver instead of a bespoke client.
Deployed as a Cloud Run service, sibling to `odata.opteryx`.

This is a read-only service: `CommandStatementQuery` plus the metadata calls
(`GetSqlInfo`, `GetCatalogs`, `GetDbSchemas`, `GetTables`, `GetTableTypes`) a
JDBC/ODBC driver needs on connect. No writes, no prepared statements, no
transactions in v1 — see [docs/design.md](docs/design.md) for the full
rationale and non-goals.

## How it works

Flight SQL's request shape is always two calls:

1. **`GetFlightInfo`** — send a command (a SQL query, or a metadata request);
   get back the result schema and an opaque `Ticket`.
2. **`DoGet`** — redeem that ticket to stream the actual Arrow data.

This server implements that dispatch by hand rather than subclassing a
high-level Flight SQL base class: the pinned PyArrow build (25.0.0) doesn't
expose one (`pyarrow.flight` has no `*Sql*`-named class), and doesn't bundle
the Flight SQL protobuf definitions either. Those are vendored at
[app/flight/proto/FlightSql_pb2.py](app/flight/proto/FlightSql_pb2.py),
compiled from the upstream `format/FlightSql.proto` and stamped for the
protobuf runtime version this project (and `odata.opteryx`) actually installs.
`app/flight/server.py` unpacks each `FlightDescriptor.command` as a
`google.protobuf.Any` and dispatches on the unpacked type.

## Repo layout

```
app/
  main.py                    # process entrypoint -- starts the Flight gRPC server directly
  logging.py, core.py, secret_store.py   # copied from odata.opteryx, unchanged
  auth/
    deps.py                    # bearer-JWT verification (ported from odata.opteryx)
    external_auth.py             # basic-auth -> JWT exchange (ported)
    permissions.py                 # JWT claims -> Opteryx access_policies/visibility_filters (unchanged)
    errors.py                        # transport-agnostic AuthError, mapped to Flight errors at the edge
  flight/
    server.py                  # FlightServerBase subclass -- command dispatch
    auth_middleware.py           # ServerMiddleware resolving claims from gRPC call headers
    query.py                       # CommandStatementQuery -> opteryx Session -> Arrow
    metadata.py                      # GetCatalogs/DbSchemas/Tables/TableTypes/SqlInfo handlers
    tickets.py                         # opaque ticket encode/decode for GetFlightInfo -> DoGet
    proto/FlightSql_pb2.py               # vendored Flight SQL protobuf definitions
examples/
  query.py                  # example CLI client (see below)
tests/                       # unit tests + in-process FlightClient round-trip tests
docs/design.md               # full design doc
```

## Local development

```bash
uv sync
```

(if `uv` isn't set up for your Python toolchain, a plain `python3 -m venv
.venv && .venv/bin/pip install -e .` works too — `uv` is just what the
Dockerfile and `odata.opteryx` both use)

Run the tests (unit tests against the command handlers directly, plus an
in-process `pyarrow.flight.FlightClient` round trip against a real bound
server — no network, no external services required):

```bash
uv run pytest
# or: .venv/bin/python -m pytest
```

Run the server locally:

```bash
PORT=8815 uv run python -m app.main
# or: PORT=8815 .venv/bin/python -m app.main
```

By default this runs with no auth configured (anonymous claims) and no
Firestore/GCS access — `CommandStatementQuery` against built-in sample data
(e.g. `$planets`) works out of the box; catalog/table listing and
credentialed queries need the environment variables below.

## Example client

[examples/query.py](examples/query.py) is a small, dependency-light CLI that
demonstrates the `GetFlightInfo` → `DoGet` round trip directly against a
running server:

```bash
python examples/query.py "SELECT * FROM \$planets LIMIT 5"

python examples/query.py "SELECT 1" --url grpc+tls://flight.opteryx.app:443

python examples/query.py "SELECT * FROM some.workspace.table" --token "$FLIGHT_TOKEN"
```

`--url` defaults to `$FLIGHT_SERVER_URL` (falling back to the production
service, `grpc+tls://flight.opteryx.app:443`); `--token` defaults to
`$FLIGHT_TOKEN` and is a bearer JWT — omit it for anonymous access (allowed
at the transport layer, but most relations reject anonymous callers at the
permissions layer; see [docs/design.md](docs/design.md), "Auth design").

This is *not* how a real BI tool connects — those use the upstream Flight SQL
JDBC driver or ADBC ODBC driver, which speak this same wire protocol under
the hood but hide the `GetFlightInfo`/`DoGet` split behind a normal SQL API.
This script exists to make the protocol concrete and as a quick smoke test
against a live deployment.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `PORT` | Port to bind the Flight gRPC server on | `8080` |
| `FLIGHT_TICKET_KEY` | `Fernet` key (32 url-safe base64 bytes) encrypting tickets. Generate with `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Required for stable behavior across restarts/multiple instances; a random one is generated per-process if unset | unset (ephemeral) |
| `FLIGHT_TICKET_TTL_SECONDS` | How long a ticket is redeemable after `GetFlightInfo` | `300` |
| `FLIGHT_RESULT_CACHE_TTL_SECONDS` / `FLIGHT_RESULT_CACHE_MAX_ENTRIES` | Bounds on the in-process result cache bridging `GetFlightInfo` -> `DoGet` | `300` / `128` |
| `GCP_PROJECT_ID`, `FIRESTORE_DATABASE`, `GCS_BUCKET` | Opteryx catalog backing store — same vars `odata.opteryx` uses | unset |
| `AUTH_URL`, `JWT_ISSUER`, `DATA_AUDIENCE` | Bearer-token verification — same vars `odata.opteryx` uses | `https://authenticate.opteryx.app` / same / `opteryx` |

## Deployment

Cloud Run, same pattern as `odata.opteryx`, with two gRPC-specific
requirements the design doc calls out:

- **`--use-http2`** is required — Cloud Run's ingress needs to know this is a
  gRPC service, or every Flight call fails at the protocol level before it
  ever reaches the app.
- A longer **`--timeout`** than a typical HTTP service needs, since `DoGet`
  on a large result is one long-lived streaming call rather than a bounded
  request/response.

See [docs/design.md](docs/design.md#deployment) for the full rationale
(Dockerfile deltas, `--min-instances`, `cloudbuild.yaml`).

## Status

v1 scope per the design doc: `CommandStatementQuery`, `GetFlightInfo` +
`DoGet`, auth middleware, and the metadata command surface are implemented
and tested (including live against the deployed service). Not yet done:
`CommandPreparedStatementQuery`, `DoPut`-based ingestion, transactions (all
explicitly out of scope for v1), and a real JDBC/ADBC driver smoke test
(only `pyarrow.flight.FlightClient` has exercised this server so far).
