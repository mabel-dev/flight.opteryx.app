"""CommandGetSqlInfo / GetCatalogs / GetDbSchemas / GetTables / GetTableTypes.

Catalog/schema/table enumeration mirrors odata.opteryx's
`app/routes/v4/service_document.py`: workspace -> catalog_name,
collection -> db_schema_name, dataset/view name -> table_name, backed by the
same Firestore collection-group query pattern (cheap at scale -- one round
trip per workspace regardless of how many collections it has) rather than
`OpteryxCatalog.list_collections()`/`list_datasets()` per workspace. Which
rows a caller may see is NOT decided here: every row is put to
`opteryx_access.can_perform_action` (see `list_visible_datasets`). Statistics/sort-order annotations that OData's
`$metadata` endpoint adds aren't relevant to Flight SQL's fixed schemas, so
they're left out here.

Table/schema Arrow shapes below are the ones the Flight SQL spec mandates
per command (see the comments in Apache Arrow's upstream
`format/FlightSql.proto`, from which `app/flight/proto/FlightSql_pb2.py` is
generated) -- these are not ours to change.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence

import pyarrow as pa
from google.cloud.firestore_v1.base_query import FieldFilter
from opteryx_access import can_perform_action

from app.auth.permissions import grants_from_claims
from app.core import _get_firestore_client
from opteryx_shared_services.logging import get_logger

logger = get_logger()

# Workspaces the catalog lists BY NAME, on top of the caller's own personal
# namespace and every workspace their `policies` claim names. A listing choice,
# not an access decision: whether any row found in one is visible is still put
# to the library row by row, so an anonymous caller listing `public` sees only
# what opteryx-access lets it read there.
#
# `public` only. `samples` and `demo` are readable through implicit grants too
# (see `opteryx_access.implicitly_readable_workspaces`), but they are
# deliberately UNLISTED -- implicit grants never appear in the policies claim,
# and odata.opteryx's service document, which this catalog mirrors, unions in
# `public` alone. Anyone can still query them; they just are not in the tree.
LISTED_BY_NAME = ("public",)

TABLE_TYPES = ("TABLE", "VIEW")


@dataclass
class DatasetRow:
    catalog_name: str  # workspace
    db_schema_name: str  # collection
    table_name: str  # dataset/view name
    table_type: str  # "TABLE" or "VIEW"


def _normalize_resource_name(resource: str) -> str:
    if not resource:
        return resource
    if resource.endswith(".*"):
        resource = resource[:-2]
    if resource.endswith("."):
        resource = resource[:-1]
    return resource


def _query_collection_group(db, collection: str, workspace_filter: Optional[str], limit: int) -> List[DatasetRow]:
    results: List[DatasetRow] = []
    try:
        query = db.collection_group(collection)
        if workspace_filter:
            query = query.where(filter=FieldFilter("workspace", "==", workspace_filter))
        query = query.limit(limit)
        table_type = "VIEW" if collection == "views" else "TABLE"
        for doc in query.stream():
            try:
                data = doc.to_dict()
                workspace = data.get("workspace")
                collection_name = data.get("collection")
                name = data.get("name") or doc.id
                if not (workspace and collection_name and name):
                    continue
                results.append(DatasetRow(workspace, collection_name, name, table_type))
            except Exception:
                continue
    except Exception as exc:
        logger.error(f"Failed to query collection group {collection}: {exc}")
    return results


def _personal_datasets(db, identity: str) -> List[DatasetRow]:
    results: List[DatasetRow] = []
    try:
        for child, table_type in (("datasets", "TABLE"), ("views", "VIEW")):
            for doc in db.collection("personal").document(identity).collection(child).stream():
                try:
                    data = doc.to_dict()
                    name = data.get("name") or doc.id
                    results.append(DatasetRow("personal", identity, name, table_type))
                except Exception:
                    continue
    except Exception as exc:
        logger.error(f"Failed to retrieve personal datasets for {identity}: {exc}")
    return results


def _workspace_datasets(db, workspace_ids: Iterable[str]) -> List[DatasetRow]:
    results: List[DatasetRow] = []
    for workspace_id in workspace_ids:
        for coll in ("datasets", "views"):
            results.extend(_query_collection_group(db, coll, workspace_id, limit=1000))
    return results


def _workspace_of(pattern: str) -> str:
    """The workspace a policy pattern names: everything before its first dot.

    Used only to decide WHERE to look for rows, never whether a row is
    visible -- a pattern over one collection still sends the listing to the
    whole workspace, and the library then refuses every row the pattern does
    not cover.
    """
    return pattern.split(".", 1)[0]


def list_visible_datasets(claims: Dict[str, Any]) -> List[DatasetRow]:
    """Every (catalog, db_schema, table) the caller may read.

    Two separate steps, and only the first is this service's:

    1. WHERE TO LOOK -- the caller's own `personal.<identity>` namespace,
       every workspace their `policies` claim names, and `LISTED_BY_NAME`.
       This shapes the catalog (it is why `samples` and `demo` are absent
       from it) but grants nothing.
    2. WHAT IS VISIBLE -- each row found is put to
       `opteryx_access.can_perform_action(..., "READ", identity=...)` with the
       caller's issued grants, so the decision is the library's, including
       its implicit grants (owner of your own personal namespace, nobody
       else's; `public` read-only for a signed-in identity) and the cap that
       stops an issued policy reaching a reserved workspace. Per ROW rather
       than per workspace: a grant on one relation does not disclose the
       relations beside it, exactly as the query engine (which asks the same
       library) would refuse to read them.

    Every Flight call needs a bearer token, but a verified token with no
    `sub`/`email`/`preferred_username` still reaches here with no identity
    (see `app.auth.deps._normalize_claims`). It is answered the same way,
    with `identity=None`: the library
    decides what an anonymous session may read. Its issued policies are not
    consulted -- a token that names nobody must not be a way of holding
    somebody's grants -- so it is left with whatever the library grants
    everyone.
    """
    db = _get_firestore_client(database="catalogs")
    if db is None:
        logger.error("Firestore client unavailable; returning no catalog metadata")
        return []

    identity = claims.get("identity") or None
    grants = grants_from_claims(claims) if identity else []

    workspace_ids = {_workspace_of(grant.pattern) for grant in grants} | set(LISTED_BY_NAME)

    all_rows: List[DatasetRow] = []
    if identity:
        all_rows.extend(_personal_datasets(db, identity))
    all_rows.extend(_workspace_datasets(db, workspace_ids))

    return [
        row
        for row in all_rows
        if can_perform_action(
            grants,
            f"{row.catalog_name}.{row.db_schema_name}.{row.table_name}",
            "READ",
            identity=identity,
        )
    ]


def _like_to_fnmatch(pattern: Optional[str]) -> Optional[str]:
    """Flight SQL filter patterns use SQL LIKE wildcards (`%`, `_`); translate
    to fnmatch's (`*`, `?`) so `fnmatch.fnmatch` can apply them."""
    if pattern is None:
        return None
    return pattern.replace("%", "*").replace("_", "?")


def get_catalogs(claims: Dict[str, Any]) -> pa.Table:
    schema = pa.schema([pa.field("catalog_name", pa.utf8(), nullable=False)])
    names = sorted({row.catalog_name for row in list_visible_datasets(claims)})
    return pa.table({"catalog_name": names}, schema=schema)


def get_db_schemas(
    claims: Dict[str, Any], catalog: Optional[str], db_schema_filter_pattern: Optional[str]
) -> pa.Table:
    schema = pa.schema(
        [
            pa.field("catalog_name", pa.utf8()),
            pa.field("db_schema_name", pa.utf8(), nullable=False),
        ]
    )
    fn_pattern = _like_to_fnmatch(db_schema_filter_pattern)
    pairs = sorted(
        {
            (row.catalog_name, row.db_schema_name)
            for row in list_visible_datasets(claims)
            if (catalog is None or row.catalog_name == catalog)
            and (fn_pattern is None or fnmatch.fnmatch(row.db_schema_name, fn_pattern))
        }
    )
    return pa.table(
        {
            "catalog_name": [p[0] for p in pairs],
            "db_schema_name": [p[1] for p in pairs],
        },
        schema=schema,
    )


def get_tables(
    claims: Dict[str, Any],
    catalog: Optional[str],
    db_schema_filter_pattern: Optional[str],
    table_name_filter_pattern: Optional[str],
    table_types: Optional[Sequence[str]],
    include_schema: bool,
) -> pa.Table:
    fields = [
        pa.field("catalog_name", pa.utf8()),
        pa.field("db_schema_name", pa.utf8()),
        pa.field("table_name", pa.utf8(), nullable=False),
        pa.field("table_type", pa.utf8(), nullable=False),
    ]
    if include_schema:
        fields.append(pa.field("table_schema", pa.binary(), nullable=False))
    schema = pa.schema(fields)

    db_schema_fn = _like_to_fnmatch(db_schema_filter_pattern)
    table_name_fn = _like_to_fnmatch(table_name_filter_pattern)
    allowed_types = set(table_types) if table_types else None

    rows = sorted(
        (
            row
            for row in list_visible_datasets(claims)
            if (catalog is None or row.catalog_name == catalog)
            and (db_schema_fn is None or fnmatch.fnmatch(row.db_schema_name, db_schema_fn))
            and (table_name_fn is None or fnmatch.fnmatch(row.table_name, table_name_fn))
            and (allowed_types is None or row.table_type in allowed_types)
        ),
        key=lambda r: (r.catalog_name, r.db_schema_name, r.table_name, r.table_type),
    )

    columns = {
        "catalog_name": [r.catalog_name for r in rows],
        "db_schema_name": [r.db_schema_name for r in rows],
        "table_name": [r.table_name for r in rows],
        "table_type": [r.table_type for r in rows],
    }
    if include_schema:
        # v1 does not resolve per-table Arrow schemas for GetTables -- doing so
        # means a catalog lookup (OpteryxCatalog.load_dataset/load_view) per
        # row, which is a real per-table cost this metadata listing otherwise
        # avoids entirely. Emit an empty (zero-field) serialized schema per
        # row rather than lying about column names/types; add real per-table
        # schemas here if/when a client exercises include_schema=true.
        empty_schema_bytes = _serialize_empty_schema()
        columns["table_schema"] = [empty_schema_bytes for _ in rows]

    return pa.table(columns, schema=schema)


def _serialize_empty_schema() -> bytes:
    sink = pa.BufferOutputStream()
    with pa.ipc.new_stream(sink, pa.schema([])):
        pass
    return sink.getvalue().to_pybytes()


def get_table_types() -> pa.Table:
    schema = pa.schema([pa.field("table_type", pa.utf8(), nullable=False)])
    return pa.table({"table_type": list(TABLE_TYPES)}, schema=schema)


# --- CommandGetSqlInfo -------------------------------------------------------
#
# Union arm order/type-codes fixed by the Flight SQL spec's documented
# schema for CommandGetSqlInfo (see the upstream FlightSql.proto):
# string_value(0), bool_value(1), bigint_value(2), int32_bitmask(3),
# string_list(4), int32_to_int32_list_map(5). Only the arms actually used
# below are populated; unused arms are still declared (empty) so the union
# type itself matches spec regardless of which info codes are requested.

_SQL_INFO_UNION_FIELDS = [
    pa.field("string_value", pa.utf8()),
    pa.field("bool_value", pa.bool_()),
    pa.field("bigint_value", pa.int64()),
    pa.field("int32_bitmask", pa.int32()),
    pa.field("string_list", pa.list_(pa.field("string_data", pa.utf8()))),
    pa.field(
        "int32_to_int32_list_map",
        pa.map_(pa.int32(), pa.list_(pa.field("$data$", pa.int32()))),
    ),
]

# arrow.flight.protocol.sql.SqlInfo enum values (see FlightSql.proto) this
# server answers today. Minimal static set per the design: server identity,
# and the three non-goals (read-only, no substrait, no transactions) stated
# outright rather than left for a driver to guess at. Extend as real drivers
# request specific codes this doesn't yet cover.
FLIGHT_SQL_SERVER_NAME = 0
FLIGHT_SQL_SERVER_VERSION = 1
FLIGHT_SQL_SERVER_ARROW_VERSION = 2
FLIGHT_SQL_SERVER_READ_ONLY = 3
FLIGHT_SQL_SERVER_SQL = 4
FLIGHT_SQL_SERVER_SUBSTRAIT = 5
FLIGHT_SQL_SERVER_TRANSACTION = 8  # SqlSupportedTransaction; 0 = SQL_SUPPORTED_TRANSACTION_NONE


def _static_sql_info() -> Dict[int, tuple]:
    server_version = os.environ.get("FLIGHT_SERVER_VERSION", "0.0.1")
    return {
        FLIGHT_SQL_SERVER_NAME: ("string_value", "opteryx-flight"),
        FLIGHT_SQL_SERVER_VERSION: ("string_value", server_version),
        FLIGHT_SQL_SERVER_ARROW_VERSION: ("string_value", pa.__version__),
        FLIGHT_SQL_SERVER_READ_ONLY: ("bool_value", True),  # design non-goal: no writes in v1
        FLIGHT_SQL_SERVER_SQL: ("bool_value", True),
        FLIGHT_SQL_SERVER_SUBSTRAIT: ("bool_value", False),
        FLIGHT_SQL_SERVER_TRANSACTION: ("int32_bitmask", 0),  # design non-goal: no transactions in v1
    }


def get_sql_info(requested_info: Optional[Sequence[int]]) -> pa.Table:
    all_info = _static_sql_info()
    if requested_info:
        info_codes = [code for code in requested_info if code in all_info]
    else:
        info_codes = sorted(all_info.keys())

    arm_index = {field.name: i for i, field in enumerate(_SQL_INFO_UNION_FIELDS)}
    type_ids: List[int] = []
    offsets: List[int] = []
    arm_values: Dict[str, list] = {field.name: [] for field in _SQL_INFO_UNION_FIELDS}

    for code in info_codes:
        arm_name, value = all_info[code]
        type_ids.append(arm_index[arm_name])
        offsets.append(len(arm_values[arm_name]))
        arm_values[arm_name].append(value)

    children = [
        pa.array(arm_values["string_value"], type=pa.utf8()),
        pa.array(arm_values["bool_value"], type=pa.bool_()),
        pa.array(arm_values["bigint_value"], type=pa.int64()),
        pa.array(arm_values["int32_bitmask"], type=pa.int32()),
        pa.array(arm_values["string_list"], type=pa.list_(pa.field("string_data", pa.utf8()))),
        pa.array(
            arm_values["int32_to_int32_list_map"],
            type=pa.map_(pa.int32(), pa.list_(pa.field("$data$", pa.int32()))),
        ),
    ]
    value_array = pa.UnionArray.from_dense(
        types=pa.array(type_ids, type=pa.int8()),
        value_offsets=pa.array(offsets, type=pa.int32()),
        children=children,
        field_names=[f.name for f in _SQL_INFO_UNION_FIELDS],
    )

    schema = pa.schema(
        [
            pa.field("info_name", pa.uint32(), nullable=False),
            pa.field("value", value_array.type, nullable=False),
        ]
    )
    return pa.table(
        [pa.array(info_codes, type=pa.uint32()), value_array],
        schema=schema,
    )
