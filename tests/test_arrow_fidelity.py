"""Arrow schema and type fidelity of query results.

The point of this service is that a BI tool gets Arrow back with the types
the query actually produced. Two things have to hold, and neither was tested
beyond int64-and-string:

  * The schema a client is promised at GetFlightInfo is the schema the data
    arrives with at DoGet. A driver builds its result-set metadata from the
    first and reads rows against the second; a mismatch is a wrong column
    type in somebody's dashboard, or a hard driver error.
  * Types survive the opteryx-morsel-to-Arrow conversion unchanged --
    narrow integers do not silently widen, decimals keep their precision and
    scale, and nulls keep their column's type instead of collapsing.
"""

import pyarrow as pa
import pytest

from app.flight import query
from tests.helpers import create_prepared_statement
from tests.helpers import prepared_query_descriptor
from tests.helpers import statement_query_descriptor

CLAIMS = {
    "identity": "test-user",
    "policies": [{"pattern": "*", "role": "owner"}],
    "billing_account": "test-account",
}

# (name, sql, expected arrow type, expected value)
SCALAR_TYPES = [
    ("int64", "SELECT CAST(2 AS INT64) AS v", pa.int64(), 2),
    ("double", "SELECT 1.5 AS v", pa.float64(), 1.5),
    ("bool", "SELECT true AS v", pa.bool_(), True),
    ("string", "SELECT 'hello' AS v", pa.string(), "hello"),
    ("null", "SELECT NULL AS v", pa.null(), None),
    ("decimal", "SELECT CAST(1.23 AS DECIMAL(10,2)) AS v", pa.decimal128(10, 2), None),
    ("date", "SELECT CAST('2024-01-15' AS DATE) AS v", pa.date32(), None),
    ("timestamp", "SELECT CAST('2024-01-15 10:30:00' AS TIMESTAMP) AS v", pa.timestamp("us"), None),
    ("interval", "SELECT INTERVAL '1' DAY AS v", pa.month_day_nano_interval(), None),
]


@pytest.mark.parametrize(
    "name,sql,expected_type,expected_value",
    SCALAR_TYPES,
    ids=[case[0] for case in SCALAR_TYPES],
)
def test_scalar_type_survives_the_arrow_conversion(name, sql, expected_type, expected_value):
    schema, batches, rows = query._run_to_batches(sql, CLAIMS)
    assert schema.field("v").type == expected_type
    assert rows == 1
    if expected_value is not None:
        assert pa.Table.from_batches(batches, schema=schema).column("v")[0].as_py() == expected_value


def test_narrow_integer_widths_are_preserved():
    # `$planets` carries int8/int16/int32/float32/decimal columns, which is
    # the point of using it here: a conversion that widened everything to
    # int64/double would still pass every other test in this file.
    schema, _, _ = query._run_to_batches("SELECT * FROM $planets", CLAIMS)
    types = {field.name: field.type for field in schema}
    assert types["id"] == pa.int8()
    assert types["density"] == pa.int16()
    assert types["diameter"] == pa.int32()
    assert types["escape_velocity"] == pa.float32()
    assert types["mass"] == pa.float64()
    assert types["gravity"] == pa.decimal128(3, 1)
    assert types["name"] == pa.string()


def test_nulls_do_not_collapse_a_columns_type():
    # A column that is null in some rows must keep the type the non-null rows
    # give it, rather than degrading to pa.null().
    schema, batches, _ = query._run_to_batches(
        "SELECT * FROM (VALUES (1, 'a'), (NULL, NULL)) AS t(i, s)", CLAIMS
    )
    assert schema.field("i").type == pa.int64()
    assert schema.field("s").type == pa.string()
    table = pa.Table.from_batches(batches, schema=schema)
    assert table.column("i").to_pylist() == [1, None]
    assert table.column("s").to_pylist() == ["a", None]


def test_every_morsel_carries_the_same_schema():
    # A result large enough to span several morsels must not change shape
    # part-way through: `pa.Table.from_batches(..., schema=...)` in
    # `do_get` would raise, mid-stream, on a client that had already been
    # handed the first schema.
    tables = list(
        query._execute_to_tables(
            "SELECT a.id, b.name FROM $planets a CROSS JOIN $planets b", CLAIMS, max_size=8
        )
    )
    assert len(tables) > 1, "expected a multi-morsel result"
    for table in tables[1:]:
        assert table.schema == tables[0].schema


# -- end to end: promised schema == delivered schema -------------------------

FIDELITY_QUERIES = [
    "SELECT 1 AS a, 'x' AS b",
    "SELECT * FROM $planets",
    "SELECT CAST('2024-01-15' AS DATE) AS d, CAST(1.23 AS DECIMAL(10,2)) AS n",
    "SELECT * FROM (VALUES (1, 'x')) AS t(id, name) WHERE id > 100",  # zero rows
    "SELECT a.id, b.name FROM $planets a CROSS JOIN $planets b",  # multi-morsel
]


@pytest.mark.parametrize("sql", FIDELITY_QUERIES)
def test_get_flight_info_schema_matches_do_get_schema(flight_server, auth_options, sql):
    _, client = flight_server
    info = client.get_flight_info(statement_query_descriptor(sql), auth_options)
    table = client.do_get(info.endpoints[0].ticket, auth_options).read_all()
    assert table.schema == info.schema


@pytest.mark.parametrize("sql", FIDELITY_QUERIES)
def test_get_schema_matches_get_flight_info_schema(flight_server, auth_options, sql):
    """GetSchema and GetFlightInfo must agree.

    Regression test: `get_schema` returned a bare `pa.Schema`, which pyarrow
    rejects with `ArrowTypeError ("must return a SchemaResult instance")`,
    so EVERY GetSchema call failed. Drivers that probe a statement's shape
    before executing it -- which is most of them -- got an error where they
    expected a schema. Fixed to wrap the schema in `fl.SchemaResult`.
    """
    _, client = flight_server
    descriptor = statement_query_descriptor(sql)
    assert client.get_schema(descriptor, auth_options).schema == (
        client.get_flight_info(descriptor, auth_options).schema
    )


@pytest.mark.parametrize("sql", FIDELITY_QUERIES)
def test_prepared_statement_dataset_schema_matches_delivered_data(
    flight_server, auth_options, sql
):
    # The prepared-statement path publishes its schema a third way, in
    # ActionCreatePreparedStatementResult.dataset_schema, serialized as IPC
    # bytes. JDBC clients build their ResultSetMetaData from exactly this.
    _, client = flight_server
    result = create_prepared_statement(client, sql, auth_options)
    dataset_schema = pa.ipc.read_schema(pa.py_buffer(result.dataset_schema))

    descriptor = prepared_query_descriptor(result.prepared_statement_handle)
    info = client.get_flight_info(descriptor, auth_options)
    table = client.do_get(info.endpoints[0].ticket, auth_options).read_all()

    assert dataset_schema == info.schema
    assert dataset_schema == table.schema


def test_zero_row_result_still_carries_its_columns(flight_server, auth_options):
    # Worth its own test rather than only the parametrized pair above: a
    # zero-row result is where schema is easiest to lose (a zero-row Table
    # has no RecordBatches to read it off), and a driver handed an empty
    # schema reports "no such column" for a query that is simply empty.
    _, client = flight_server
    info = client.get_flight_info(
        statement_query_descriptor(
            "SELECT id, name FROM (VALUES (1, 'x')) AS t(id, name) WHERE id > 100"
        ),
        auth_options,
    )
    table = client.do_get(info.endpoints[0].ticket, auth_options).read_all()
    assert table.num_rows == 0
    assert table.schema.names == ["id", "name"]
    assert table.schema == info.schema
