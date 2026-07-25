"""In-process FlightClient round trip for CommandStatementQuery.

Per docs/design.md's testing approach item 2: an actual
pyarrow.flight.FlightClient round trip covering connect + GetFlightInfo +
DoGet for a simple query. Runs with no Authorization header, so the caller
gets anonymous claims (see app.auth.deps.require_flight_authentication);
anonymous callers still get opteryx's default owner-of-everything access
policy when the caller supplies none of their own, so a self-contained
query that touches no catalog table (e.g. `SELECT 1`) executes without any
auth setup.
"""

from tests.helpers import statement_query_descriptor


def test_simple_select_roundtrip(flight_server):
    _, client = flight_server
    descriptor = statement_query_descriptor("SELECT 1 AS a, 2 AS b")

    info = client.get_flight_info(descriptor)
    assert len(info.endpoints) == 1

    reader = client.do_get(info.endpoints[0].ticket)
    table = reader.read_all()

    assert table.to_pydict() == {"a": [1], "b": [2]}


def test_query_schema_matches_data(flight_server):
    _, client = flight_server
    descriptor = statement_query_descriptor("SELECT 1 AS a, 'x' AS b")

    info = client.get_flight_info(descriptor)
    reader = client.do_get(info.endpoints[0].ticket)
    table = reader.read_all()

    assert info.schema.names == ["a", "b"]
    assert table.schema.names == ["a", "b"]
    assert table.to_pydict() == {"a": [1], "b": ["x"]}


def test_fully_filtered_query_keeps_correct_schema(flight_server):
    _, client = flight_server
    descriptor = statement_query_descriptor(
        "SELECT * FROM (VALUES (1, 'x')) AS t(id, name) WHERE id > 100"
    )

    info = client.get_flight_info(descriptor)
    assert info.schema.names == ["id", "name"]

    reader = client.do_get(info.endpoints[0].ticket)
    table = reader.read_all()
    assert table.num_rows == 0
    assert table.schema.names == ["id", "name"]


def test_aggregation_roundtrip(flight_server):
    _, client = flight_server
    descriptor = statement_query_descriptor(
        "SELECT * FROM (VALUES (1, 10), (2, 20), (3, 30)) AS t(id, amount) WHERE amount > 15"
    )

    info = client.get_flight_info(descriptor)
    reader = client.do_get(info.endpoints[0].ticket)
    table = reader.read_all()

    assert table.num_rows == 2
    assert set(table.column("id").to_pylist()) == {2, 3}
