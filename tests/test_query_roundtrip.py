"""In-process FlightClient round trip for CommandStatementQuery.

Per docs/design.md's testing approach item 2: an actual
pyarrow.flight.FlightClient round trip covering connect + GetFlightInfo +
DoGet for a simple query. Every call authenticates via `auth_options` (see
conftest.py) -- unlike odata.opteryx, this service has no anonymous access,
so a call with no credentials must fail (see
test_unauthenticated_call_is_rejected below), not just get a reduced
default policy.
"""

import pyarrow.flight as fl
import pytest

from tests.helpers import statement_query_descriptor


def test_simple_select_roundtrip(flight_server, auth_options):
    _, client = flight_server
    descriptor = statement_query_descriptor("SELECT 1 AS a, 2 AS b")

    info = client.get_flight_info(descriptor, auth_options)
    assert len(info.endpoints) == 1

    reader = client.do_get(info.endpoints[0].ticket, auth_options)
    table = reader.read_all()

    assert table.to_pydict() == {"a": [1], "b": [2]}


def test_query_schema_matches_data(flight_server, auth_options):
    _, client = flight_server
    descriptor = statement_query_descriptor("SELECT 1 AS a, 'x' AS b")

    info = client.get_flight_info(descriptor, auth_options)
    reader = client.do_get(info.endpoints[0].ticket, auth_options)
    table = reader.read_all()

    assert info.schema.names == ["a", "b"]
    assert table.schema.names == ["a", "b"]
    assert table.to_pydict() == {"a": [1], "b": ["x"]}


def test_fully_filtered_query_keeps_correct_schema(flight_server, auth_options):
    _, client = flight_server
    descriptor = statement_query_descriptor(
        "SELECT * FROM (VALUES (1, 'x')) AS t(id, name) WHERE id > 100"
    )

    info = client.get_flight_info(descriptor, auth_options)
    assert info.schema.names == ["id", "name"]

    reader = client.do_get(info.endpoints[0].ticket, auth_options)
    table = reader.read_all()
    assert table.num_rows == 0
    assert table.schema.names == ["id", "name"]


def test_aggregation_roundtrip(flight_server, auth_options):
    _, client = flight_server
    descriptor = statement_query_descriptor(
        "SELECT * FROM (VALUES (1, 10), (2, 20), (3, 30)) AS t(id, amount) WHERE amount > 15"
    )

    info = client.get_flight_info(descriptor, auth_options)
    reader = client.do_get(info.endpoints[0].ticket, auth_options)
    table = reader.read_all()

    assert table.num_rows == 2
    assert set(table.column("id").to_pylist()) == {2, 3}


def test_unauthenticated_call_is_rejected(flight_server):
    # No anonymous access: GetFlightInfo with no auth metadata at all must
    # fail at the transport layer, before the query ever runs.
    _, client = flight_server
    descriptor = statement_query_descriptor("SELECT 1")

    with pytest.raises(fl.FlightUnauthenticatedError):
        client.get_flight_info(descriptor)


def test_invalid_token_is_rejected(flight_server):
    _, client = flight_server
    descriptor = statement_query_descriptor("SELECT 1")
    bad_options = fl.FlightCallOptions(headers=[(b"authorization", b"Bearer wrong-token")])

    with pytest.raises(fl.FlightUnauthenticatedError):
        client.get_flight_info(descriptor, bad_options)
