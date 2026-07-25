"""In-process FlightClient round trip for the metadata commands that don't
depend on a live Firestore catalog (CommandGetTableTypes, CommandGetSqlInfo).
CommandGetCatalogs/DbSchemas/Tables are covered as unit tests against
app.flight.metadata directly (tests/test_metadata_unit.py), with
list_visible_datasets monkeypatched, since they need a Firestore-backed
catalog this environment doesn't have.

Every call authenticates via `auth_options` (see conftest.py) -- this
service has no anonymous access.
"""

from app.flight.proto import FlightSql_pb2 as fsql
from tests.helpers import command_descriptor


def test_get_table_types_roundtrip(flight_server, auth_options):
    _, client = flight_server
    descriptor = command_descriptor(fsql.CommandGetTableTypes())

    info = client.get_flight_info(descriptor, auth_options)
    reader = client.do_get(info.endpoints[0].ticket, auth_options)
    table = reader.read_all()

    assert table.column("table_type").to_pylist() == ["TABLE", "VIEW"]


def test_get_sql_info_roundtrip(flight_server, auth_options):
    _, client = flight_server
    descriptor = command_descriptor(fsql.CommandGetSqlInfo())

    info = client.get_flight_info(descriptor, auth_options)
    reader = client.do_get(info.endpoints[0].ticket, auth_options)
    table = reader.read_all()

    names = table.column("info_name").to_pylist()
    assert 0 in names  # FLIGHT_SQL_SERVER_NAME
    assert 3 in names  # FLIGHT_SQL_SERVER_READ_ONLY


def test_get_sql_info_filters_requested_codes(flight_server, auth_options):
    _, client = flight_server
    descriptor = command_descriptor(fsql.CommandGetSqlInfo(info=[0]))

    info = client.get_flight_info(descriptor, auth_options)
    reader = client.do_get(info.endpoints[0].ticket, auth_options)
    table = reader.read_all()

    assert table.column("info_name").to_pylist() == [0]
