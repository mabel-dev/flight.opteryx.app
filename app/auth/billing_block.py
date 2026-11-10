"""Refuse work billed to an account that is suspended or over its spending cap.

VENDORED. The rule is `billing_block_reason` in control.opteryx's
`app/billing_accounts.py`, which owns the account document and is the original.
jobs, odata and flight each carry this copy - the same arrangement as
`config_client.py` - because a service hop on every query's submit path is a
new way for every query to fail. Keep the copies in step; their tests pin the
same cases as control's `tests/test_billing_status.py`.

Who writes the fields read here:
- `billing_status` - control's Stripe webhook, `suspended` once Stripe stops
  retrying a failed invoice.
- `cap_reached_period` - xb500's hourly `spend_check`, when month-to-date spend
  reaches the cap; control clears it when the cap is raised.

Fails open, as the config client does: an unreadable account document allows
the query. The block is a commercial control, not a security boundary, and a
Firestore hiccup must not refuse every query on the platform.
"""

from __future__ import annotations

import datetime
import time
from typing import Callable
from typing import Optional

from opteryx_shared_services.logging import get_logger

logger = get_logger()

HOUSE_ACCOUNT_ID = "opteryx"
CACHE_TTL_SECONDS = 60
_CACHE_MAX = 10_000

BLOCK_PAYMENT_FAILED = "payment_failed"
BLOCK_SPEND_CAP = "spend_cap_reached"

MESSAGES = {
    BLOCK_PAYMENT_FAILED: (
        "Queries are paused for this billing account because an invoice could not be "
        "paid. A billing admin can update the card on the billing page, which pays it "
        "and resumes queries."
    ),
    BLOCK_SPEND_CAP: (
        "This billing account has reached its monthly spending cap. A billing admin can "
        "raise the cap on the billing page; otherwise queries resume next month."
    ),
}

_cache: dict[str, tuple[float, Optional[dict]]] = {}


def billing_period(now: Optional[datetime.datetime] = None) -> str:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return now.astimezone(datetime.timezone.utc).strftime("%Y%m")


def billing_block_reason(
    account_id: Optional[str], account: Optional[dict], now: Optional[datetime.datetime] = None
) -> Optional[str]:
    if account_id is None or account is None or account_id == HOUSE_ACCOUNT_ID:
        return None
    if account.get("billing_status") == "suspended":
        return BLOCK_PAYMENT_FAILED
    reached = account.get("cap_reached_period")
    if reached and reached == billing_period(now):
        return BLOCK_SPEND_CAP
    return None


def check(account_id: Optional[str], client_factory: Callable) -> Optional[str]:
    """Why `account_id`'s work must be refused, or None. Account reads are cached for a minute.

    A block or an unblock therefore takes up to a minute to reach every instance.
    """
    if not account_id or account_id == HOUSE_ACCOUNT_ID:
        return None
    try:
        account = cached_account(account_id, client_factory)
    except Exception as exc:  # noqa: BLE001 - fail open, see the module docstring
        logger.warning(f"billing block check for {account_id} failed, allowing: {exc}")
        return None
    return billing_block_reason(account_id, account)


def cached_account(account_id: str, client_factory: Callable) -> Optional[dict]:
    """The `billing_accounts/{account_id}` document, or None if absent; cached for a minute.

    Shared with `usage_allowance`, so the two submit-time checks cost one read.
    Raises if the read fails - callers decide how to fail.
    """
    now = time.monotonic()
    hit = _cache.get(account_id)
    if hit is not None and now - hit[0] < CACHE_TTL_SECONDS:
        return hit[1]
    db = client_factory()
    snap = db.collection("billing_accounts").document(account_id).get()
    account = snap.to_dict() if snap.exists else None
    if len(_cache) >= _CACHE_MAX:
        _cache.clear()
    _cache[account_id] = (now, account)
    return account
