import time

import pytest

from app.flight import tickets
from app.flight.proto import FlightSql_pb2 as fsql


def test_statement_handle_round_trip():
    handle = tickets.encode_statement_handle("SELECT 1", {"identity": "user@example.com"})
    sql, claims = tickets.decode_statement_handle(handle)
    assert sql == "SELECT 1"
    assert claims == {"identity": "user@example.com"}


def test_statement_handle_tamper_detected():
    handle = tickets.encode_statement_handle("SELECT 1", {"identity": "x"})
    with pytest.raises(tickets.InvalidTicket):
        tickets.decode_statement_handle(handle[:-1] + (b"x" if handle[-1:] != b"x" else b"y"))


def test_statement_handle_garbage_rejected():
    with pytest.raises(tickets.InvalidTicket):
        tickets.decode_statement_handle(b"not-a-real-ticket")


def test_metadata_ticket_round_trip():
    command = fsql.CommandGetTables(catalog="acme", include_schema=True)
    handle = tickets.encode_metadata_ticket(command, {"identity": "u"})
    decoded_command, claims = tickets.decode_metadata_ticket(handle)
    assert isinstance(decoded_command, fsql.CommandGetTables)
    assert decoded_command.catalog == "acme"
    assert decoded_command.include_schema is True
    assert claims == {"identity": "u"}


def test_metadata_ticket_rejects_non_metadata_message():
    with pytest.raises(ValueError):
        tickets.encode_metadata_ticket(fsql.CommandStatementQuery(query="SELECT 1"), {})
