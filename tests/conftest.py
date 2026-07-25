import pyarrow.flight as fl
import pytest

from app.flight.server import OpteryxFlightServer


@pytest.fixture()
def flight_server():
    server = OpteryxFlightServer(location="grpc://localhost:0")
    client = fl.FlightClient(f"grpc://localhost:{server.port}")
    try:
        yield server, client
    finally:
        client.close()
        server.shutdown()
        server.wait()
