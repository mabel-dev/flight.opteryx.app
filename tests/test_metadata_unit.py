"""Unit tests against the metadata command handlers directly (no network).

list_visible_datasets is monkeypatched to avoid needing a live Firestore
catalog -- these tests are exercising the Arrow-shaping/filtering logic in
app.flight.metadata, not Firestore access control (which is a straight port
of odata.opteryx's service_document.py, already covered there).
"""

import pyarrow as pa
import pytest

from app.flight import metadata

FAKE_ROWS = [
    metadata.DatasetRow("public", "geopolitics", "countries", "TABLE"),
    metadata.DatasetRow("public", "geopolitics", "borders_view", "VIEW"),
    metadata.DatasetRow("acme", "sales", "orders", "TABLE"),
    metadata.DatasetRow("acme", "sales", "orders_by_region", "VIEW"),
]


@pytest.fixture(autouse=True)
def _fake_datasets(monkeypatch):
    monkeypatch.setattr(metadata, "list_visible_datasets", lambda claims: FAKE_ROWS)


def test_get_catalogs():
    table = metadata.get_catalogs({})
    assert table.column("catalog_name").to_pylist() == ["acme", "public"]


def test_get_db_schemas_all():
    table = metadata.get_db_schemas({}, catalog=None, db_schema_filter_pattern=None)
    assert table.to_pydict() == {
        "catalog_name": ["acme", "public"],
        "db_schema_name": ["sales", "geopolitics"],
    }


def test_get_db_schemas_filtered_by_catalog():
    table = metadata.get_db_schemas({}, catalog="public", db_schema_filter_pattern=None)
    assert table.to_pydict() == {
        "catalog_name": ["public"],
        "db_schema_name": ["geopolitics"],
    }


def test_get_db_schemas_like_pattern():
    table = metadata.get_db_schemas({}, catalog=None, db_schema_filter_pattern="geo%")
    assert table.column("db_schema_name").to_pylist() == ["geopolitics"]


def test_get_tables_filters_by_type():
    table = metadata.get_tables(
        {}, catalog=None, db_schema_filter_pattern=None, table_name_filter_pattern=None,
        table_types=["VIEW"], include_schema=False,
    )
    assert table.column("table_name").to_pylist() == ["orders_by_region", "borders_view"]
    assert set(table.column("table_type").to_pylist()) == {"VIEW"}


def test_get_tables_name_pattern():
    table = metadata.get_tables(
        {}, catalog=None, db_schema_filter_pattern=None, table_name_filter_pattern="orders%",
        table_types=None, include_schema=False,
    )
    assert sorted(table.column("table_name").to_pylist()) == ["orders", "orders_by_region"]


def test_get_tables_include_schema_adds_column():
    table = metadata.get_tables(
        {}, catalog="acme", db_schema_filter_pattern=None, table_name_filter_pattern=None,
        table_types=None, include_schema=True,
    )
    assert "table_schema" in table.schema.names
    for value in table.column("table_schema").to_pylist():
        assert isinstance(value, bytes)


def test_get_table_types():
    table = metadata.get_table_types()
    assert table.column("table_type").to_pylist() == ["TABLE", "VIEW"]


def test_get_sql_info_default_returns_all_static_codes():
    table = metadata.get_sql_info(None)
    assert set(table.column("info_name").to_pylist()) == set(metadata._static_sql_info().keys())


def test_get_sql_info_unknown_code_is_dropped():
    table = metadata.get_sql_info([0, 999999])
    assert table.column("info_name").to_pylist() == [0]


def test_like_to_fnmatch():
    assert metadata._like_to_fnmatch("geo%") == "geo*"
    assert metadata._like_to_fnmatch("g_o") == "g?o"
    assert metadata._like_to_fnmatch(None) is None
