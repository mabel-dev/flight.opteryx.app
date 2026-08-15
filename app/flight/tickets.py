"""Opaque, signed/encrypted ticket handles for CommandStatementQuery.

`GetFlightInfo` mints a ticket carrying everything `DoGet` needs to
(re-)run the query: the SQL text and the caller's claims. The ticket must be
opaque to the client and tamper-proof — a client must not be able to forge a
ticket for someone else's claims, or edit the SQL text of one they were
issued. `cryptography.fernet.Fernet` gives both: it's AES-128-CBC +
HMAC-SHA256 authenticated encryption, so a modified token fails to decrypt
rather than decoding to attacker-controlled data.

Tickets also carry a short TTL (`Fernet.decrypt(..., ttl=...)`), since a
ticket is only ever meant to bridge one `GetFlightInfo` -> `DoGet` pair, not
to be replayed later or cached by the client.

The key is per-process. Cloud Run instances are ephemeral and stateless
between deploys/scale events, and a ticket's whole lifetime is "issued and
redeemed within the same request flow" — there is no requirement for a
ticket minted by one instance to be redeemable on another, so an in-memory
key (falling back to one generated at import time) is sufficient. Set
`FLIGHT_TICKET_KEY` to pin a stable key across processes if that ever
becomes necessary (e.g. a load balancer that can route `DoGet` to a
different instance than `GetFlightInfo`).
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any
from typing import Dict
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

from app.flight.proto import FlightSql_pb2 as fsql
from app.logging import get_logger

logger = get_logger()

DEFAULT_TICKET_TTL_SECONDS = 300


class InvalidTicket(Exception):
    """Raised when a ticket handle is malformed, tampered with, or expired."""


def _load_or_generate_key() -> bytes:
    env_key = os.environ.get("FLIGHT_TICKET_KEY")
    if env_key:
        return env_key.encode("ascii")
    logger.warning(
        "FLIGHT_TICKET_KEY not set; generating an ephemeral per-process ticket key. "
        "Tickets minted by this process will not be redeemable by any other process "
        "or after a restart."
    )
    return Fernet.generate_key()


_FERNET = Fernet(_load_or_generate_key())


def _ttl_seconds() -> int:
    return int(os.environ.get("FLIGHT_TICKET_TTL_SECONDS", DEFAULT_TICKET_TTL_SECONDS))


def encode_statement_handle(sql: str, claims: Dict[str, Any]) -> bytes:
    """Mint an opaque handle carrying `(sql, claims)`.

    The returned bytes are meant to be embedded verbatim as the
    `statement_handle` of a `TicketStatementQuery` (see `app.flight.server`).
    """
    payload = json.dumps({"sql": sql, "claims": claims}, separators=(",", ":")).encode("utf-8")
    return _FERNET.encrypt(payload)


def decode_statement_handle(handle: bytes) -> Tuple[str, Dict[str, Any]]:
    """Recover `(sql, claims)` from a handle minted by `encode_statement_handle`.

    Raises `InvalidTicket` if the handle is malformed, was tampered with, or
    has outlived `FLIGHT_TICKET_TTL_SECONDS`.
    """
    try:
        payload = _FERNET.decrypt(handle, ttl=_ttl_seconds())
        data = json.loads(payload)
        return data["sql"], data["claims"]
    except InvalidToken as exc:
        raise InvalidTicket("Ticket is invalid, tampered with, or expired") from exc
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise InvalidTicket("Ticket payload is malformed") from exc


# Prepared statements (ActionCreatePreparedStatement -> CommandPreparedStatementQuery)
# reuse the same (sql, claims) payload as a statement ticket, but they are not
# interchangeable with one and must not be treated as such:
#
#  * Lifetime. A statement ticket bridges a single GetFlightInfo -> DoGet pair
#    and expires in minutes. A prepared statement is held open by the client
#    for as long as the JDBC/ODBC `PreparedStatement` object lives, and may be
#    executed many times, so it gets its own (longer) TTL.
#  * Confusion resistance. A `kind` marker means a handle minted for one role
#    can't be redeemed in the other, even though both decrypt with the same key.
PREPARED_HANDLE_TTL_SECONDS = 3600


def _prepared_ttl_seconds() -> int:
    return int(os.environ.get("FLIGHT_PREPARED_TTL_SECONDS", PREPARED_HANDLE_TTL_SECONDS))


def encode_prepared_handle(sql: str, claims: Dict[str, Any]) -> bytes:
    """Mint an opaque `prepared_statement_handle` carrying `(sql, claims)`.

    As with statement tickets, the claims are captured here -- at prepare
    time -- and reused for every execution of this handle, rather than being
    re-read from whatever headers accompany the later
    CommandPreparedStatementQuery call. Same reasoning as `app.flight.server`:
    the caller was authorized once, and a later call must not be able to
    execute the statement under different (or absent) claims.
    """
    payload = json.dumps(
        {"kind": "prepared", "sql": sql, "claims": claims}, separators=(",", ":")
    ).encode("utf-8")
    return _FERNET.encrypt(payload)


def decode_prepared_handle(handle: bytes) -> Tuple[str, Dict[str, Any]]:
    """Recover `(sql, claims)` from a handle minted by `encode_prepared_handle`.

    Raises `InvalidTicket` if the handle is malformed, tampered with, expired,
    or is a statement/metadata ticket rather than a prepared statement handle.
    """
    try:
        payload = _FERNET.decrypt(handle, ttl=_prepared_ttl_seconds())
        data = json.loads(payload)
        if data.get("kind") != "prepared":
            raise InvalidTicket("Handle is not a prepared statement handle")
        return data["sql"], data["claims"]
    except InvalidToken as exc:
        raise InvalidTicket("Handle is invalid, tampered with, or expired") from exc
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise InvalidTicket("Handle payload is malformed") from exc


# Metadata commands (GetCatalogs/GetDbSchemas/GetTables/GetTableTypes/GetSqlInfo)
# have no Flight-SQL-mandated ticket message type of their own -- only
# CommandStatementQuery does (TicketStatementQuery, handled above). Their
# tickets are plain opaque handles: the encrypted command message (so DoGet
# can recompute the result on a cache miss without re-deriving filters from
# scratch) plus the claims that were live when GetFlightInfo ran, same
# reasoning as encode_statement_handle.
_METADATA_COMMAND_TYPES_BY_NAME = {
    cls.__name__: cls
    for cls in (
        fsql.CommandGetSqlInfo,
        fsql.CommandGetCatalogs,
        fsql.CommandGetDbSchemas,
        fsql.CommandGetTables,
        fsql.CommandGetTableTypes,
    )
}


def encode_metadata_ticket(command: Any, claims: Dict[str, Any]) -> bytes:
    command_type = type(command).__name__
    if command_type not in _METADATA_COMMAND_TYPES_BY_NAME:
        raise ValueError(f"Not a known metadata command type: {command_type}")
    payload = json.dumps(
        {
            "command_type": command_type,
            "command_bytes": base64.b64encode(command.SerializeToString()).decode("ascii"),
            "claims": claims,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return _FERNET.encrypt(payload)


def decode_metadata_ticket(handle: bytes) -> Tuple[Any, Dict[str, Any]]:
    try:
        payload = _FERNET.decrypt(handle, ttl=_ttl_seconds())
        data = json.loads(payload)
        command_cls = _METADATA_COMMAND_TYPES_BY_NAME[data["command_type"]]
        command = command_cls()
        command.ParseFromString(base64.b64decode(data["command_bytes"]))
        return command, data["claims"]
    except InvalidToken as exc:
        raise InvalidTicket("Ticket is invalid, tampered with, or expired") from exc
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise InvalidTicket("Ticket payload is malformed") from exc
