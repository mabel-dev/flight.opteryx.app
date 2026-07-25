"""Unit tests against the query command handler directly (no network),
per docs/design.md's testing approach item 1.
"""

import pyarrow as pa
import pytest

from app.flight import query

ANON_CLAIMS = {"identity": None, "policies": [], "billing_account": None}


def test_execute_to_arrow_simple_select():
    batches = list(query.execute_to_arrow("SELECT 1 AS a, 2 AS b", ANON_CLAIMS))
    table = pa.Table.from_batches(batches)
    assert table.to_pydict() == {"a": [1], "b": [2]}


def test_execute_to_arrow_fully_filtered_result_yields_no_batches():
    # A zero-row Arrow Table has nothing to chunk, so `.to_batches()` (called
    # internally by execute_to_arrow) yields no RecordBatches at all here --
    # there's no batch-level schema to inspect from this generator alone.
    # ResultCache.execute_and_cache is the layer that handles this (falls
    # back to `pa.schema([])` when batches is empty); see test_query_unit's
    # test_result_cache_* and query.ResultCache.execute_and_cache.
    batches = list(
        query.execute_to_arrow(
            "SELECT * FROM (VALUES (1, 'x')) AS t(id, name) WHERE id > 100", ANON_CLAIMS
        )
    )
    assert batches == []


def test_result_cache_round_trip():
    cache = query.ResultCache(ttl_seconds=60, max_entries=4)
    handle = b"test-handle"
    schema = cache.execute_and_cache(handle, "SELECT 1 AS a", ANON_CLAIMS)
    assert schema.names == ["a"]

    entry = cache.pop(handle)
    assert entry is not None
    assert entry.total_rows == 1
    # A ticket is single-use: once DoGet has consumed it, it's gone.
    assert cache.pop(handle) is None


def test_result_cache_get_or_execute_falls_back_on_miss():
    cache = query.ResultCache(ttl_seconds=60, max_entries=4)
    entry = cache.get_or_execute(b"never-cached", "SELECT 42 AS answer", ANON_CLAIMS)
    assert entry.total_rows == 1
    assert pa.Table.from_batches(entry.batches).to_pydict() == {"answer": [42]}


def test_result_cache_preserves_schema_for_fully_filtered_result():
    # Regression test: a zero-row result must not collapse to an empty
    # schema. execute_to_arrow's raw batches are empty for a zero-row
    # result (see test_execute_to_arrow_fully_filtered_result_yields_no_batches),
    # so the cache must derive schema from the underlying per-morsel Table,
    # not from `batches[0]`.
    cache = query.ResultCache(ttl_seconds=60, max_entries=4)
    handle = b"empty-result-handle"
    schema = cache.execute_and_cache(
        handle, "SELECT * FROM (VALUES (1, 'x')) AS t(id, name) WHERE id > 100", ANON_CLAIMS
    )
    assert schema.names == ["id", "name"]

    entry = cache.pop(handle)
    assert entry.total_rows == 0
    assert entry.schema.names == ["id", "name"]
    assert entry.batches == []


def test_result_cache_evicts_oldest_when_full():
    cache = query.ResultCache(ttl_seconds=60, max_entries=2)
    cache.execute_and_cache(b"h1", "SELECT 1 AS a", ANON_CLAIMS)
    cache.execute_and_cache(b"h2", "SELECT 2 AS a", ANON_CLAIMS)
    cache.execute_and_cache(b"h3", "SELECT 3 AS a", ANON_CLAIMS)
    assert cache.pop(b"h1") is None  # evicted to make room for h3
    assert cache.pop(b"h3") is not None
