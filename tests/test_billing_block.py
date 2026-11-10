"""Queries billed to a suspended or capped account are refused before a session opens.

The rule is control.opteryx's, shared as `opteryx_shared_services.billing.block`. Flight
has no 402, so the refusal is opteryx's `PermissionsError`, which the server
maps to `FlightUnauthorizedError` with the message intact.
"""

import datetime

import opteryx.exceptions as opteryx_exceptions
import pytest

from opteryx_shared_services.billing import accounts as billing_accounts
from opteryx_shared_services.billing import block as billing_block
from app.flight import query

NOV = datetime.datetime(2026, 11, 9, 12, tzinfo=datetime.timezone.utc)


@pytest.mark.parametrize(
    "account_id, account, expected",
    [
        (None, None, None),
        ("acct", None, None),
        ("acct", {"billing_status": "past_due"}, None),
        ("acct", {"billing_status": "suspended"}, "payment_failed"),
        ("acct", {"cap_reached_period": "202611"}, "spend_cap_reached"),
        ("acct", {"cap_reached_period": "202610"}, None),
        ("opteryx", {"billing_status": "suspended"}, None),
    ],
)
def test_rule_matches_control(account_id, account, expected):
    assert billing_block.billing_block_reason(account_id, account, now=NOV) == expected


class _Snap:
    def __init__(self, data):
        self._data, self.exists = data, data is not None

    def to_dict(self):
        return self._data


class _Db:
    def __init__(self, accounts):
        self.accounts = accounts

    def collection(self, name):
        return self

    def document(self, account_id):
        data = self.accounts.get(account_id)
        return type("Doc", (), {"get": lambda _self: _Snap(data)})()


@pytest.fixture
def accounts(monkeypatch):
    billing_accounts.clear_cache()
    data = {}
    sessions = []
    monkeypatch.setattr("app.core._get_firestore_client", lambda *a, **k: _Db(data))
    monkeypatch.setattr(query, "register_default_connector", lambda: None)
    monkeypatch.setattr(query.opteryx, "session", lambda **kw: sessions.append(kw) or object())
    data["_sessions"] = sessions
    yield data
    billing_accounts.clear_cache()


def test_a_suspended_account_gets_no_session(accounts):
    accounts["acct_1"] = {"billing_status": "suspended"}

    with pytest.raises(opteryx_exceptions.PermissionsError, match="invoice could not be paid"):
        query.session_for_claims({"identity": "alice", "billing_account": "acct_1"})

    assert accounts["_sessions"] == []


def test_an_account_at_its_cap_gets_no_session(accounts):
    accounts["acct_1"] = {"cap_reached_period": billing_block.billing_period()}

    with pytest.raises(opteryx_exceptions.PermissionsError, match="spending cap"):
        query.session_for_claims({"identity": "alice", "billing_account": "acct_1"})


def test_an_account_in_good_standing_gets_a_session(accounts):
    accounts["acct_1"] = {"billing_status": "past_due"}

    query.session_for_claims({"identity": "alice", "billing_account": "acct_1"})

    assert accounts["_sessions"][0]["billing_account"] == "acct_1"
