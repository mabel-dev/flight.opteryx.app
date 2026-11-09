# flight.opteryx — Design

## Purpose

Expose Opteryx over Arrow Flight SQL so ODBC/JDBC-capable tools (BI tools, SQL
IDEs, notebook drivers) can connect using the standard Arrow Flight SQL JDBC
driver / ADBC ODBC driver, instead of requiring a bespoke client. Deployed as
a Cloud Run service, sibling to `odata.opteryx`.

This is the "easy first" version: build on PyArrow's own Flight/Flight SQL
Python bindings rather than hand-rolling protobuf command dispatch. Scope is
deliberately narrower than the OData service — read-only SQL execution plus
the metadata calls a JDBC/ODBC driver needs on connect.

## Why Flight SQL (recap)

- Flight is gRPC-based, so it runs on Cloud Run behind `--use-http2` — unlike
  a hand-rolled ODBC/JDBC wire protocol (e.g. Postgres wire protocol), which
  is raw TCP and cannot be routed through Cloud Run's HTTP-only ingress.
- Flight speaks Arrow natively end-to-end, so query results stream as Arrow
  record batches with no JSON serialization step (contrast with
  `odata.opteryx`'s `_MaterializedResult.to_pydict()` → orjson path).
- JDBC and ODBC drivers for Flight SQL already exist upstream (Arrow's own
  Flight SQL JDBC driver, and ADBC's ODBC driver) — no custom driver to
  write or distribute.

## Non-goals (v1)

- No writes: `CommandStatementUpdate`, `DoPut`-based ingestion, and
  transactions are out of scope. This is a read path only, mirroring
  `odata.opteryx`'s read-only surface.
- No bind parameters. `CommandPreparedStatementQuery` *is* supported —
  see "Prepared statements" below — but every statement advertises an empty
  parameter schema and its SQL is executed as written. Parameter binding is
  deferred until a client actually needs it.
- No mTLS. Cloud Run terminates TLS at its front end; auth is the same
  bearer-JWT scheme `odata.opteryx` already uses, carried in Flight per-call
  headers instead of an HTTP `Authorization` header.
- No connection-level session state (e.g. `USE <catalog>`). Catalog/schema
  are resolved per-call from the query text and the caller's claims, same as
  today's OData routes.

## What "easy first" means concretely

PyArrow's Python bindings give you `pyarrow.flight.FlightServerBase` plus the
low-level Flight primitives (`FlightDescriptor`, `FlightInfo`,
`FlightEndpoint`, `Ticket`, `GeneratorStream`, `ServerMiddleware`). Whether
the installed PyArrow version also exposes a high-level Flight SQL base class
that auto-unpacks the `google.protobuf.Any`-wrapped SQL commands
(`CommandStatementQuery`, `CommandGetTables`, etc.) varies by version and is
**not yet confirmed for this project** — the previous attempt to check this
by installing PyArrow into a scratch venv was interrupted before it ran.

**First implementation task**: pin a PyArrow version and confirm what it
gives you:

1. If the installed version exposes a high-level Flight SQL server base
   (look for `pyarrow.flight` classes/methods with `Sql` in the name, e.g.
   something resembling `FlightSqlServerBase` with virtual-style methods per
   command), subclass it and implement only the per-command hooks listed
   below.
2. If not, fall back to manually unpacking `descriptor.command` as a
   `google.protobuf.Any` against the Flight SQL protobuf message
   definitions PyArrow bundles, and dispatch on the unpacked type URL inside
   `get_flight_info` / `do_get` / `do_action` by hand.

Either way the command surface and behavior below is the same; only the
amount of boilerplate in `flight/server.py` changes. Do not guess at PyArrow
API names when writing code — import and inspect the actual installed
version first.

## Command surface (v1)

| Flight SQL command | Purpose | Backed by |
|---|---|---|
| `CommandStatementQuery` | Execute a SQL string, return results | opteryx `Session`, same as `interface.py` |
| `CommandPreparedStatementQuery` | Execute a previously prepared statement | same path as `CommandStatementQuery` |
| `CreatePreparedStatement` (action) | Prepare a SQL string, return a handle | executes eagerly to fill `dataset_schema` |
| `ClosePreparedStatement` (action) | Release a prepared statement | drops the cached result; no server-side object |
| `CommandGetSqlInfo` | Server capabilities (used by drivers on connect) | static/near-static response |
| `CommandGetCatalogs` | List catalogs | `OpteryxCatalog`, same data as `service_document.py` |
| `CommandGetDbSchemas` | List schemas | `OpteryxCatalog` |
| `CommandGetTables` | List tables (+ optional schema) | `OpteryxCatalog`, same data as `metadata.py` |
| `CommandGetTableTypes` | Table type enumeration (e.g. "TABLE", "VIEW") | static |

`GetFlightInfo` is called first for every command (query or metadata call)
and returns a `FlightInfo` describing the result schema and one
`FlightEndpoint` whose `Ticket` is an opaque, server-issued handle. `DoGet`
is then called with that ticket to stream the actual Arrow data. This two-step
shape is Flight's normal request pattern, not something specific to SQL
commands.

## Prepared statements

Added after v1 was deployed, for one reason: **the JDBC/ODBC compatibility
this whole service exists for does not work without them.** A live ADBC
smoke test against the deployed v1 passed on queries, `GetCatalogs`, and
`GetTables`, but failed on `adbc_prepare`:

```
INVALID_STATE: [Flight SQL Statement] must call Prepare before GetParameterSchema
```

JDBC and ODBC drivers route nearly everything through `PreparedStatement`,
including schema introspection. A server answering only
`CommandStatementQuery` is reachable from ADBC and hand-written clients, but
not from DataGrip or DBeaver — i.e. not from the tools the service was built
to serve.

The implementation is deliberately thin:

- **A handle is not server state.** `ActionCreatePreparedStatement` returns an
  encrypted, self-contained `(sql, claims)` payload — the same Fernet
  construction as a `TicketStatementQuery` handle, tagged `kind: "prepared"`
  so the two can't be redeemed in each other's role, and with a longer TTL
  because a `PreparedStatement` object outlives a single
  `GetFlightInfo`/`DoGet` pair. Nothing is allocated server-side, so nothing
  leaks if a client never closes one, and any instance can serve any handle.
- **Claims are captured at prepare time**, not re-read from the headers on the
  later `CommandPreparedStatementQuery`. Same reasoning as the ticket design:
  the statement was authorized once, and a later call must not be able to
  re-scope it by presenting different or absent credentials.
- **Preparing executes.** opteryx has no plan-only path yielding a result
  schema (see "Query execution & streaming design"), and
  `ActionCreatePreparedStatementResult.dataset_schema` must be populated for
  drivers to build their `ResultSetMetaData`. The result is cached under the
  handle, so the `GetFlightInfo` that follows is a cache hit rather than a
  second execution. A syntax error therefore surfaces at `prepareStatement()`
  time, which is where a JDBC user expects it.
- **No bind parameters.** Every statement reports an empty parameter schema.
  `DoPut` accepts and discards a parameter batch rather than failing, because
  some drivers send an empty one as part of their execute path — but any rows
  actually sent are logged and ignored, never silently treated as applied.

## Repo layout

Mirrors `odata.opteryx` where the concern is transport-agnostic; only the
transport layer (`app/flight/*` in place of `app/routes/*`) and entrypoint
differ.

```
flight.opteryx/
  app/
    main.py                  # starts the Flight gRPC server (no ASGI/uvicorn)
    core.py                   # Firestore client helper (from odata.opteryx)
    secret_store.py            # read-only JWT public key lookup (trimmed from odata.opteryx)
    auth/
      deps.py                  # require_bearer_token logic, adapted to read from Flight
                                # per-call headers instead of FastAPI Header()
      permissions.py            # copied from odata.opteryx, unchanged (policies -> visibility_filters)
    flight/
      server.py                 # the FlightServerBase / Flight SQL subclass — command dispatch
      auth_middleware.py         # ServerMiddleware reading the authorization header per call
      metadata.py                 # CommandGetCatalogs/DbSchemas/Tables/TableTypes/SqlInfo handlers
      query.py                    # CommandStatementQuery -> opteryx Session -> Arrow stream
      tickets.py                   # opaque ticket encode/decode for GetFlightInfo -> DoGet
  docs/
    design.md                  # this file
  Dockerfile
  pyproject.toml
  cloudbuild/
    cloudbuild.yaml
```

### Reused from `odata.opteryx` largely as-is

- `app/core.py`, `app/auth/permissions.py` — no transport dependency, copied
  directly. Logging now comes from `opteryx_shared_services.logging`.
- `app/secret_store.py` — trimmed to the one read-only call this service
  needs, `load_public_key(kid)`; key creation and private-key reads stay in
  the services that issue tokens.
- `require_bearer_token` in `app/auth/deps.py` (odata.opteryx's version) is
  already synchronous and
  takes a raw `Authorization` header value — it does not need FastAPI at
  all. Its call site changes (Flight middleware instead of a FastAPI
  `Depends`), and it is hardened here: asymmetric algorithms only, no
  Google OIDC (Cloud Tasks) fallback, and bounded pre-verification work
  (dated-`kid` window, cached JWKS).
- The `opteryx.set_default_connector(OpteryxConnector, catalog=OpteryxCatalog,
  ...)` wiring in `interface.py` — same setup, same env vars
  (`FIRESTORE_DATABASE`, `GCS_BUCKET`, `GCP_PROJECT_ID`).
- `visibility_filters` threading from claims → `session.execute_logical_plan`
  — same mechanism, same claims shape (`identity`, `billing_account`,
  `policies`).

### New

- `app/flight/*` — everything Flight/gRPC-specific.
- `app/main.py` — process entrypoint is the Flight server itself, not
  uvicorn.

## Auth design

Flight has no per-request HTTP headers in the FastAPI sense; instead each
call carries gRPC metadata, surfaced to a `ServerMiddleware` via
`start_call(info, headers)`. Design:

```python
# app/flight/auth_middleware.py
import pyarrow.flight as fl
from app.auth.deps import require_bearer_token

class ClaimsMiddleware(fl.ServerMiddleware):
    def __init__(self, claims):
        self.claims = claims

class ClaimsMiddlewareFactory(fl.ServerMiddlewareFactory):
    def start_call(self, info, headers):
        auth_values = headers.get("authorization", [])
        authorization = auth_values[0] if auth_values else None
        claims = require_bearer_token(authorization)   # unchanged from odata.opteryx
        return ClaimsMiddleware(claims)
```

registered on the server as `middleware={"auth": ClaimsMiddlewareFactory()}`.
Every command handler fetches claims via
`context.get_middleware("auth").claims` instead of a FastAPI dependency.

**Unlike `odata.opteryx`, there is no anonymous access.** `odata.opteryx`
lets a request with no `Authorization` header through with a best-effort
anonymous claims shape, and leaves it to each route to decide whether it
tolerates that (`is_anonymous_exempt`, scoped to two specific public
datasets). Flight SQL's command surface has no equivalent per-route hook —
`CommandStatementQuery` carries an arbitrary SQL string that can name any
table or none at all, so there is no single (workstream, collection) pair to
gate an anonymous-tolerance decision on before the query runs. Rather than
build one, v1 requires a valid bearer token on every call: `start_call`
above passes `authorization` straight to `require_bearer_token`, which
already rejects a missing or malformed value with `AuthError(401, ...)`.
This was in fact the original shape of this snippet; an earlier draft added
an anonymous-tolerant wrapper on top of it, which has since been removed
along with the wrapper.

Tickets and prepared statement handles carry the claims they were minted
under, and are only honoured for that same identity: `DoGet` (and
`GetFlightInfo` on a prepared handle) checks the caller's identity against
the one in the handle, so a leaked handle is not usable by another
authenticated caller. A handle also expires no later than the token it was
minted under (`exp`), whatever its own TTL.

Unlike the OData service, there is no Basic-auth fallback in v1 — Flight SQL
JDBC/ODBC drivers authenticate via bearer token or Flight's handshake
mechanism, not HTTP Basic. Revisit only if a specific client needs it.

## Query execution & streaming design

```python
# app/flight/query.py
def run_statement_query(sql: str, claims: dict):
    session = get_session_for_claims(claims)          # same Session construction as interface.py
    results_generator, result_type = session.execute_logical_plan(
        build_logical_plan(sql), connection=session,
        visibility_filters=claims.get("policies"),
    )
    return results_generator, result_type
```

`GetFlightInfo` for a `CommandStatementQuery`:

1. Parse the SQL far enough to know the result schema (or execute eagerly
   and cache — see open question below) — enough to build the `FlightInfo`'s
   Arrow schema.
2. Mint an opaque ticket (`tickets.encode(sql, claims)` — signed/encrypted
   so a client can't forge a ticket for someone else's claims) and return one
   `FlightEndpoint` pointing at this same server with that ticket.

`DoGet`:

1. Decode the ticket back to `(sql, claims)`.
2. Re-run (or resume) execution, materialize Draken morsels into Arrow
   `RecordBatch`es, and stream them back via `GeneratorStream` /
   `RecordBatchStream`.

This differs from `odata.opteryx`'s `_MaterializedResult`, which exists
there only because that service ultimately needs Python dicts for JSON
encoding. Here, morsels should convert straight to Arrow — check whether the
pinned `opteryx-core` version's `Morsel`/`Vector` expose `.to_arrow()` (the
OData service's comment notes pyarrow was dropped from opteryx-core's
reader/planner in commit `6094635a` — confirm current status before assuming
`.to_arrow()` exists; if it doesn't, build `pyarrow.RecordBatch.from_pydict()`
from `to_pylist()` as a fallback, same shape as `_MaterializedResult` does
today).

**Open question to resolve during implementation**: whether `GetFlightInfo`
should execute the query eagerly (simple, but means every call executes the
query twice if a client always calls `GetFlightInfo` then `DoGet` — once for
schema, once for data) or execute lazily and infer/cache the schema
(cheaper, more moving parts, needs a short-lived per-ticket cache keyed by
ticket + backed by something bounded, e.g. an in-process TTL cache, given
Cloud Run instances are ephemeral and this cannot rely on multi-instance
consistency). Recommend starting with eager execution + result caching by
ticket for the lifetime of that request lifecycle; revisit if double-execution
proves too costly under real query loads.

## Metadata handlers

`CommandGetCatalogs` / `CommandGetDbSchemas` / `CommandGetTables` /
`CommandGetTableTypes` return the same catalog/schema/table enumeration data
`odata.opteryx`'s `service_document.py` and `metadata.py` already compute
from `OpteryxCatalog`, just packaged as Arrow tables with the fixed schemas
the Flight SQL spec mandates for each command (e.g. `GetTables` returns
columns `catalog_name`, `db_schema_name`, `table_name`, `table_type`, and
optionally `table_schema`) instead of EDM XML. `CommandGetSqlInfo` can start
as a minimal static table (server name/version, supported SQL dialect,
transaction support = none) and grow only as real drivers request specific
info codes it doesn't yet answer.

## Deployment

### Dockerfile deltas from `odata.opteryx`

- Same two-stage build: mimalloc built from source in stage 1, copied into a
  `python:3.14-slim` final stage, non-root `norris` user, same
  `LD_PRELOAD`/`MIMALLOC_PURGE_DELAY` rationale (opteryx-core's native
  worker threads fragment glibc the same way regardless of transport).
- `pyproject.toml`: add `pyarrow` (pin exact version once confirmed above).
  Drop `fastapi`, `uvicorn[standard]`, `Brotli`, `orjson`,
  `python-multipart` — all HTTP/ASGI-specific and unused by a Flight
  server.
- `CMD python -m app.main` in place of
  `uvicorn app.main:service --host 0.0.0.0 --port $PORT --workers $WEB_CONCURRENCY`.
  The process itself is the gRPC server; there is no ASGI layer or worker
  count to configure the same way.
- `WEB_CONCURRENCY` env var goes away. `FlightServerBase` runs its own
  internal thread pool; Cloud Run's `--concurrency` flag should be sized
  against that pool, not against an asyncio event loop count.

### Cloud Run service config deltas

- `--use-http2` required — Cloud Run's HTTP-only ingress needs to know this
  is a gRPC service; Cloud Run terminates TLS and forwards h2c to the
  container.
- Longer `--timeout` than the OData service needs — a `DoGet` on a large
  result set is one long-lived streaming call, not a bounded
  request/response. Size against realistic worst-case query duration, up to
  Cloud Run's max (60 min).
- Consider `--min-instances` ≥ 1 if cold starts would otherwise kill
  in-flight streams during scale-from-zero — worth measuring rather than
  assuming.

### `cloudbuild/cloudbuild.yaml`

Same shape as `odata.opteryx`'s (build → push, tagged
`us-east1-docker.pkg.dev/$PROJECT_ID/$AR_REPOSITORY/flight-opteryx:$SHORT_SHA`),
swap only the image name.

## Testing approach

1. Unit tests against the command handlers directly (no network), same
   spirit as `odata.opteryx`'s `tests/test_odata_*` battery — feed a SQL
   string + fake claims into `query.py`, assert on the Arrow output.
2. An actual `pyarrow.flight.FlightClient` round-trip test in-process
   (`FlightServerBase` supports binding to `grpc://localhost:0` for tests)
   covering: connect + `GetFlightInfo` + `DoGet` for a simple query, and each
   metadata command.
3. Before calling v1 done, a real smoke test against at least one of the
   upstream Flight SQL JDBC driver and an ADBC ODBC driver, not just the
   Python client — the whole point of this service is compatibility with
   those drivers, and PyArrow-to-PyArrow round trips won't catch driver-side
   assumptions (e.g. specific `GetSqlInfo` codes a given BI tool requires
   before it will even attempt a query).

## Milestones

1. Confirm PyArrow Flight SQL API surface for the pinned version (blocks
   everything else).
2. `CommandStatementQuery` + `GetFlightInfo` + `DoGet` against a single
   fixed test dataset, no auth, running locally.
3. Auth middleware wired in, reusing `require_bearer_token` unchanged.
4. Metadata commands (`GetCatalogs`/`GetDbSchemas`/`GetTables`/`GetTableTypes`/`GetSqlInfo`).
5. Dockerfile + Cloud Run deploy, smoke-tested with a real JDBC driver.
6. `visibility_filters` / policy enforcement parity check against
   `odata.opteryx` (same claims, same query, same dataset → same rows).

Writes and transactions are explicitly deferred past this list — v1 is done
when a BI tool can connect, browse tables, and run a read-only SELECT.

Prepared statements were originally deferred here too, and that turned out
to be the wrong call: step 5 ("smoke-tested with a real JDBC driver") cannot
pass without them, because JDBC drivers prepare statements to introspect.
They are now implemented (see "Prepared statements" above), and step 5
remains the open item.
