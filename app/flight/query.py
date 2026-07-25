"""CommandStatementQuery execution: SQL text -> Arrow, via opteryx.

Mirrors odata.opteryx's `app/routes/v4/interface.py` for the parts that
aren't OData-specific: the `opteryx.set_default_connector(...)` wiring (same
setup, same env vars) and building a `Session` scoped to the caller's claims.

Where this differs from odata.opteryx: that service materializes rows to
Python dicts because it ultimately needs JSON. Flight speaks Arrow natively,
and opteryx-core's `Morsel`/`Vector` still expose `.to_arrow()` (see
`docs/design.md` for why the `_MaterializedResult`/`to_pylist()` workaround
odata.opteryx uses doesn't apply here — that workaround exists only because
odata.opteryx deliberately doesn't install pyarrow, and this service must),
so morsels convert straight to `pyarrow.RecordBatch` with no Python-object
detour.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../opteryx-core")))
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../pyiceberg-firestore-gcs"))
)

import opteryx
import pyarrow as pa

# Some opteryx releases may not export OpteryxConnector (e.g. in lightweight installs).
# Provide a minimal stand-in so imports still work, matching odata.opteryx's interface.py.
try:
    from opteryx.connectors import OpteryxConnector
except ImportError:  # pragma: no cover
    OpteryxConnector = type("OpteryxConnector", (), {})

from opteryx_catalog import OpteryxCatalog

from app.auth.permissions import access_policies_for_query
from app.auth.permissions import visibility_filters_from_claims
from app.logging import get_logger

logger = get_logger()

FIRESTORE_DATABASE = os.environ.get("FIRESTORE_DATABASE")
BUCKET_NAME = os.environ.get("GCS_BUCKET")
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")

opteryx.set_default_connector(
    OpteryxConnector,
    catalog=OpteryxCatalog,
    firestore_project=GCP_PROJECT_ID,
    firestore_database=FIRESTORE_DATABASE,
    gcs_bucket=BUCKET_NAME,
)

# Draken morsel size, not an Arrow batch size -- see execute_to_morsels's own
# max_size default (65_536) in opteryx.query_session.
DEFAULT_MAX_MORSEL_SIZE = int(os.environ.get("FLIGHT_MAX_MORSEL_SIZE", "65536"))

# How long a GetFlightInfo-side result stays cached, waiting for the matching
# DoGet. Independent of (but expected to be <=) the ticket's own TTL
# (app.flight.tickets.FLIGHT_TICKET_TTL_SECONDS) -- there is no reason to
# keep query results around longer than the ticket that unlocks them.
RESULT_CACHE_TTL_SECONDS = int(os.environ.get("FLIGHT_RESULT_CACHE_TTL_SECONDS", "300"))
# Bounds worst-case memory use by capped eviction (oldest-first) rather than
# relying on TTL alone, since a burst of GetFlightInfo calls whose DoGet
# never arrives would otherwise accumulate unboundedly within the TTL window.
RESULT_CACHE_MAX_ENTRIES = int(os.environ.get("FLIGHT_RESULT_CACHE_MAX_ENTRIES", "128"))


def session_for_claims(claims: Dict[str, Any]) -> "opteryx.query_session.Session":
    """Build a Session scoped to the caller, same construction as odata.opteryx's
    `execute_odata_query` (identity/access_policies/billing_account from claims),
    so Opteryx's own permission checks run against the actual caller rather than
    an empty (deny-all) context.
    """
    identity = claims.get("identity")
    access_policies = access_policies_for_query(claims) or None
    billing_account = claims.get("billing_account")
    return opteryx.session(
        user=identity,
        access_policies=access_policies,
        billing_account=billing_account,
    )


def _execute_to_tables(
    sql: str, claims: Dict[str, Any], max_size: int = DEFAULT_MAX_MORSEL_SIZE
) -> Iterator[pa.Table]:
    """Run `sql` for `claims` and yield one `pyarrow.Table` per Draken morsel.

    Yields Tables rather than RecordBatches so a zero-row result still
    carries its real schema: opteryx always yields at least one "courtesy"
    morsel even for a fully-filtered-out result (so a `pyarrow.Table` -- and
    therefore `.schema` -- is always produced), but `Table.to_batches()` on
    a zero-row table returns *no* batches at all, which would silently
    discard that schema if this yielded batches directly. Callers that only
    need the query's schema (e.g. `ResultCache.execute_and_cache`) should
    read the first Table's `.schema` rather than the first RecordBatch's.

    Lets opteryx's exceptions (`opteryx.exceptions.PermissionsError`,
    `SqlError`, `IncompatibleTypesError`, ...) propagate; mapping those to
    Flight errors is `app.flight.server`'s job, same division of
    responsibility as odata.opteryx's `interface.py`/route split.
    """
    session = session_for_claims(claims)
    visibility_filters = visibility_filters_from_claims(claims)
    for morsel in session.execute_to_morsels(
        sql, max_size=max_size, visibility_filters=visibility_filters
    ):
        morsel.materialize()  # idempotent; morsels off execute_to_morsels are already materialized
        yield morsel.to_arrow()


def execute_to_arrow(
    sql: str, claims: Dict[str, Any], max_size: int = DEFAULT_MAX_MORSEL_SIZE
) -> Iterator[pa.RecordBatch]:
    """Run `sql` for `claims` and yield `pyarrow.RecordBatch`es as they're produced.

    A zero-row result yields no batches at all (see `_execute_to_tables`) --
    callers that need the schema regardless of row count should use
    `_execute_to_tables` directly instead of inferring it from the first
    batch here.
    """
    for table in _execute_to_tables(sql, claims, max_size):
        for batch in table.to_batches():
            yield batch


def _run_to_batches(sql: str, claims: Dict[str, Any]) -> Tuple[pa.Schema, List[pa.RecordBatch], int]:
    """Fully materialize `sql`'s result, returning (schema, batches, total_rows).

    Schema comes from the first *Table* opteryx yields (always present, even
    for a zero-row result -- see `_execute_to_tables`), not the first
    RecordBatch (which may not exist at all for a zero-row result).
    """
    tables = list(_execute_to_tables(sql, claims))
    schema = tables[0].schema if tables else pa.schema([])
    batches = [batch for table in tables for batch in table.to_batches()]
    total_rows = sum(table.num_rows for table in tables)
    return schema, batches, total_rows


@dataclass
class _CacheEntry:
    schema: pa.Schema
    batches: List[pa.RecordBatch]
    total_rows: int
    expires_at: float = field(default=0.0)


class ResultCache:
    """Bounded, TTL-based cache from ticket handle -> fully materialized result.

    Implements the design's recommended tradeoff for the GetFlightInfo/DoGet
    split: `GetFlightInfo` executes the query eagerly (so it can return a
    real schema instead of an inferred/optimistic one) and caches the result
    here; `DoGet` streams from the cache instead of re-running the query.
    Deliberately in-process and not shared across instances -- Cloud Run
    instances are ephemeral, and a ticket's whole life is "issued and
    redeemed in the same request flow", so there's no correctness requirement
    for `DoGet` to land on the same instance that ran `GetFlightInfo`; when it
    doesn't (or the entry has since been evicted), `get_or_execute` just
    re-executes, which is exactly the "double execution" cost the design
    calls out as the acceptable-for-v1 fallback.
    """

    def __init__(self, ttl_seconds: int = RESULT_CACHE_TTL_SECONDS, max_entries: int = RESULT_CACHE_MAX_ENTRIES):
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._entries: Dict[bytes, _CacheEntry] = {}

    def _evict_expired(self, now: float) -> None:
        expired = [key for key, entry in self._entries.items() if entry.expires_at <= now]
        for key in expired:
            del self._entries[key]

    def execute_and_cache(self, handle: bytes, sql: str, claims: Dict[str, Any]) -> pa.Schema:
        """Execute `sql` now, cache the full result under `handle`, return its schema."""
        schema, batches, total_rows = _run_to_batches(sql, claims)
        self._store(handle, schema, batches, total_rows)
        return schema

    def put_table(self, handle: bytes, table: pa.Table) -> None:
        """Cache an already-computed table (used by metadata commands, which
        compute their whole result synchronously rather than via a morsel
        generator)."""
        self._store(handle, table.schema, table.to_batches(), table.num_rows)

    def _store(self, handle: bytes, schema: pa.Schema, batches: List[pa.RecordBatch], total_rows: int) -> None:
        now = time.monotonic()
        with self._lock:
            self._evict_expired(now)
            if len(self._entries) >= self._max_entries:
                oldest_key = min(self._entries, key=lambda k: self._entries[k].expires_at)
                del self._entries[oldest_key]
            self._entries[handle] = _CacheEntry(
                schema=schema, batches=batches, total_rows=total_rows, expires_at=now + self._ttl_seconds
            )

    def pop(self, handle: bytes) -> Optional[_CacheEntry]:
        now = time.monotonic()
        with self._lock:
            self._evict_expired(now)
            return self._entries.pop(handle, None)

    def get_or_execute(self, handle: bytes, sql: str, claims: Dict[str, Any]) -> _CacheEntry:
        """Used by DoGet: consume the cached result if present, else re-execute."""
        entry = self.pop(handle)
        if entry is not None:
            return entry
        logger.info("Flight result cache miss for ticket; re-executing query")
        schema, batches, total_rows = _run_to_batches(sql, claims)
        return _CacheEntry(schema=schema, batches=batches, total_rows=total_rows)


RESULT_CACHE = ResultCache()
