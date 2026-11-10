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
import threading
import time
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple

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
from app.auth.permissions import entitlements_from_claims
from app.auth.permissions import visibility_filters_from_claims
from opteryx_shared_services.config import get_config
from opteryx_shared_services.logging import get_logger

logger = get_logger()

GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")


# Resolved per use, not at import. A module-level constant is evaluated once
# at startup and then frozen for the life of the process, so config changes
# would never reach it without a redeploy.
def _firestore_database() -> str:
    return get_config("FIRESTORE_DATABASE")


def _bucket_name() -> str:
    return get_config("GCS_BUCKET")


def register_default_connector() -> None:
    """(Re-)register the default connector with freshly resolved configuration.

    `opteryx.connectors.set_default_connector` just rebinds a module-level
    dict (see opteryx-core `opteryx/connectors/__init__.py`), so calling it
    again is cheap and idempotent -- and it is the only way the connector's
    own `firestore_database`/`gcs_bucket` can ever pick up a config change:
    the registration captures those values by value, so a registration done
    once at import stays frozen for the life of the process.

    Called at import (below) to preserve the import-time side effect anything
    else in the process may rely on, and again from `session_for_claims` so
    every query re-resolves.
    """
    opteryx.set_default_connector(
        OpteryxConnector,
        catalog=OpteryxCatalog,
        firestore_project=GCP_PROJECT_ID,
        firestore_database=_firestore_database(),
        gcs_bucket=_bucket_name(),
    )


register_default_connector()

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

    `access_policies` is passed through EXACTLY as `access_policies_for_query`
    returns it -- including an empty list -- and must never be coerced to
    `None`. `opteryx.query_session.Session.__init__` checks `access_policies
    is None` (not falsiness) to decide whether to apply its own default of
    `[{"pattern": "*", "role": "owner"}]` (i.e. "no policies argument was
    given, so grant everything"). `[] or None` collapses "this caller was
    granted zero policies" into that same "not given" sentinel, silently
    handing every zero-policy caller -- anonymous callers above all --
    owner-level access to every relation in Opteryx. Confirmed against the
    live installed opteryx-core: `access_policies=[] or None` (i.e. `None`)
    resolves to `[{'pattern': '*', 'role': 'owner'}]`; `access_policies=[]`
    resolves to `[]`. odata.opteryx's `interface.py` has this same `or None`
    pattern, masked there only because every route checks
    `is_anonymous_exempt(workstream, collection)` before ever constructing a
    session -- Flight SQL's arbitrary-`CommandStatementQuery` surface has no
    single (workstream, collection) pair to gate on, so there is no
    equivalent guard upstream of this call; passing the real (possibly
    empty) list through is the only correct fix here.
    """
    # Re-resolve FIRESTORE_DATABASE/GCS_BUCKET and re-register before every
    # session, so a config change reaches the connector without a redeploy.
    register_default_connector()
    identity = claims.get("identity")
    access_policies = access_policies_for_query(claims)
    billing_account = claims.get("billing_account")
    _refuse_if_billing_blocked(billing_account)
    return opteryx.session(
        user=identity,
        access_policies=access_policies,
        # The caller's entitlement names, bare. The engine's permission capability
        # resolves what they confer (e.g. `automation_admin::public` -> AUTOMATE on
        # `public.*`); without them a caller entitled to run automation is refused
        # here and allowed everywhere else.
        entitlements=sorted(entitlements_from_claims(claims)),
        billing_account=billing_account,
    )


def _refuse_if_billing_blocked(billing_account: Optional[str]) -> None:
    """Raise when the caller's billing account is suspended or at its spending cap.

    Raised as opteryx's `PermissionsError` so every existing handler maps it to
    `FlightUnauthorizedError` with the message intact - Flight has no 402.
    """
    import opteryx.exceptions as opteryx_exceptions
    from opteryx_shared_services.config import get_config

    from app.auth import billing_block
    from app.core import _get_firestore_client

    reason = billing_block.check(
        billing_account,
        lambda: _get_firestore_client(
            database=get_config("ACCOUNTS_FIRESTORE_DATABASE", "(default)")
        ),
    )
    if reason:
        raise opteryx_exceptions.PermissionsError(billing_block.MESSAGES[reason])


def _accounts_db():
    from app.core import _get_firestore_client

    return _get_firestore_client(database=get_config("ACCOUNTS_FIRESTORE_DATABASE", "(default)"))


def _check_daily_allowance(billing_account: Optional[str]) -> Optional[str]:
    """Refuse a free-tier payer that has used today's allowance (app.auth.usage_allowance).

    Same rule, counters and wording as jobs' `_enforce_daily_allowance`: the two
    front doors spend one allowance. Raised as `PermissionsError`, like the
    billing block above, so it reaches the client as `FlightUnauthorizedError`
    with the message intact.

    Returns the counter day this query is metered against, or None when the
    payer is not capped, enforcement is off, or the check could not run (fails
    open, logged at error level).
    """
    import opteryx.exceptions as opteryx_exceptions

    from app.auth import billing_block, usage_allowance

    mode = usage_allowance.normalise_mode(get_config("BILLING_ALLOWANCE_MODE", "enforce"))
    if mode == usage_allowance.MODE_OFF or not billing_account:
        return None
    if billing_account == usage_allowance.HOUSE_ACCOUNT_ID:
        return None

    now = datetime.now(timezone.utc)
    day = usage_allowance.usage_day(now)
    try:
        account = billing_block.cached_account(billing_account, _accounts_db)
        plan = usage_allowance.effective_plan(billing_account, account)
        if plan != usage_allowance.PLAN_FREE:
            return None
        db = _accounts_db()
        card = usage_allowance.read_card(db, usage_allowance.card_id_for(plan, account))
        usage = usage_allowance.read_usage(db, billing_account, day)
        refusal = usage_allowance.decide(plan, card, usage, now)
    except Exception as exc:
        logger.error(
            f"daily allowance check for {billing_account} failed, allowing: "
            f"{type(exc).__name__}: {exc}"
        )
        return None

    if refusal is not None:
        if mode == usage_allowance.MODE_SHADOW:
            logger.info(
                f"daily allowance (shadow) would refuse {billing_account}: {refusal.reason} "
                f"queries={usage.queries} bytes_processed={usage.bytes_processed}"
            )
        else:
            raise opteryx_exceptions.PermissionsError(refusal.message)
    return day


def _meter(action: str, billing_account: str, day: str, fn) -> None:
    """Best-effort counter write. A lost one under-counts, the safe direction."""
    try:
        fn(_accounts_db(), billing_account, day)
    except Exception as exc:
        logger.error(f"failed to {action} for {billing_account}/{day}: {type(exc).__name__}: {exc}")


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

    A free-tier payer is metered here, on the counters jobs also uses: refused
    before anything runs if today's allowance is used, counted once execution
    starts, and its processed bytes added from the session's telemetry once
    the result is fully produced. A query that fails part-way is counted but
    adds no bytes, as in jobs.
    """
    session = session_for_claims(claims)
    billing_account = claims.get("billing_account")
    usage_day = _check_daily_allowance(billing_account)
    if usage_day:
        from app.auth import usage_allowance

        _meter("count query", billing_account, usage_day, usage_allowance.count_admission)

    visibility_filters = visibility_filters_from_claims(claims)
    for morsel in session.execute_to_morsels(
        sql, max_size=max_size, visibility_filters=visibility_filters
    ):
        morsel.materialize()  # idempotent; morsels off execute_to_morsels are already materialized
        yield morsel.to_arrow()

    if usage_day:
        try:
            nbytes = int((session.telemetry or {}).get("billing_bytes") or 0)
        except Exception:  # noqa: BLE001 - telemetry is diagnostic; never fail a finished query
            nbytes = 0
        if nbytes > 0:
            from app.auth import usage_allowance

            _meter(
                "settle bytes",
                billing_account,
                usage_day,
                lambda db, acct, day: usage_allowance.add_bytes(db, acct, day, nbytes),
            )


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

    def peek(self, handle: bytes) -> Optional[_CacheEntry]:
        """Return the cached result for `handle` without consuming it.

        Used by the prepared statement path, where the result is executed once
        at ActionCreatePreparedStatement time (to fill in `dataset_schema`) and
        then read again by the GetFlightInfo that follows -- which needs the
        schema but must leave the entry in place for the DoGet after it.
        """
        now = time.monotonic()
        with self._lock:
            self._evict_expired(now)
            return self._entries.get(handle)

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
