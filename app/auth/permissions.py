"""Permission handling utilities.

This module provides utilities for converting and handling permissions
between JWT format and Opteryx format.
"""

from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from app.logging import get_logger

logger = get_logger()

# The workstream.collection pairs reachable with zero credentials (see
# app.auth.deps.require_authentication, which lets anonymous requests through
# rather than rejecting them). Every endpoint that accepts anonymous callers
# must still scope them down to exactly these pairs itself. Only add a pair
# here for datasets that are intentionally public (e.g. open data backing
# public-facing dashboards) — this is the full anonymous-access surface.
ANONYMOUS_EXEMPT_WORKSTREAM = "public"
ANONYMOUS_EXEMPT_PAIRS = {
    ("public", "security"),
    ("public", "geopolitics"),
}


def is_anonymous_exempt(workstream: Optional[str], collection: Optional[str]) -> bool:
    """Whether (workstream, collection) is reachable without authentication."""
    return (workstream, collection) in ANONYMOUS_EXEMPT_PAIRS


# Entitlement that lifts row-level filtering entirely. Holders see every account's rows.
DATA_ADMIN_ENTITLEMENT = "data_admin"

# Some consumers namespace entitlements (authorize.opteryx uses
# "urn:opteryx:entitlement:user_admin"); the issuer currently emits them bare. Accept
# either so this does not silently stop matching if the issuer starts namespacing.
_ENTITLEMENT_URN_PREFIX = "urn:opteryx:entitlement:"


def entitlements_from_claims(claims: Dict[str, Any]) -> set:
    """Extract the caller's entitlements as a set of bare names.

    The identity store holds these as a list (`entitlements: ["user_admin",
    "data_admin"]`) but the issuer flattens them into a single comma-delimited
    `entitlement` claim. Both shapes are accepted, as is the plural key.

    Splitting on the delimiter is safe here: entitlements are multi-valued by
    definition, so a delimiter is unambiguous. The billing account is not — it has its
    own single-valued claim and is never parsed out of a delimited string.
    """
    raw = claims.get("entitlement") or claims.get("entitlements") or ()

    if isinstance(raw, str):
        values = [v for v in raw.replace(",", " ").split() if v]
    elif isinstance(raw, (list, tuple, set)):
        values = [str(v).strip() for v in raw if str(v).strip()]
    else:
        logger.warning(f"Ignoring entitlement claim of unexpected type {type(raw).__name__}")
        return set()

    return {
        v[len(_ENTITLEMENT_URN_PREFIX) :] if v.startswith(_ENTITLEMENT_URN_PREFIX) else v
        for v in values
    }


def billing_account_from_claims(claims: Dict[str, Any]) -> Optional[str]:
    """Extract the caller's billing account from the JWT `billing_account` claim.

    This used to read `scope`. It must not: `scope` is an OAuth permission list,
    written by register.opteryx as comma-separated permission words, and reading it
    as a tenant identity billed every self-service user to whatever value happened to
    be sitting there — in practice the literal "opteryx", which is simultaneously the
    house account and the name of the system workspace, so billing rows read as though
    the workspace were the payer. The issuer now emits the account as its own claim.

    A single value by definition: a caller bills to one account or to none. There is
    nothing to split and nothing to disambiguate, which is the point of the separate
    claim — the old multi-valued `scope` was silently unbillable.

    Falls back to `sub` when the claim is absent: a caller with no explicit account
    bills to themselves rather than to the house account. Note this puts identities
    and tenant account names in one namespace — a `sub` equal to a tenant's account
    name would inherit that tenant's billing rows through the Eq visibility filter.

    Returns:
        The billing account, or None if the token carries neither claim.
    """
    billing_account = claims.get("billing_account")
    if billing_account is None:
        billing_account = claims.get("sub")

    if billing_account is None:
        return None
    if not isinstance(billing_account, str):
        logger.warning(
            f"Ignoring billing account of unexpected type {type(billing_account).__name__}"
        )
        return None

    billing_account = billing_account.strip()
    return billing_account or None


# The base table holding billing events.
BILLING_RELATION = "opteryx.ops.billing"

# The daily rollups over it. These are MATERIALIZED views — real tables the engine
# scans by name — so each one needs its own row-level filter.
#
# When they were plain views a filter keyed on BILLING_RELATION alone was both
# sufficient and required: Opteryx expands a view into scans of its underlying tables
# before the binder applies visibility filters, so a filter keyed on a view name
# matched no scan. Materializing them inverts that. A query against a rollup now scans
# the rollup, never the base table, so the BILLING_RELATION entry matches nothing and —
# because unmatched relations are NOT filtered (see below) — every account's rows are
# served. The failure is silent either way, which is why both keys are held here rather
# than one being dropped as redundant.
#
# Filtering after aggregation is only safe because `billing_account` is a GROUP BY key
# in all four definitions: every row of every rollup belongs to exactly one account, so
# scoping the output equals scoping the input. A future rollup that does NOT group by
# billing_account cannot be secured this way and must not be added to this tuple.
BILLING_ROLLUP_RELATIONS = (
    "opteryx.ops.query_count_billing",
    "opteryx.ops.storage_billing",
    "opteryx.ops.processed_billing",
    # AI assistant usage (tokens, conversation turns, describes). Reports usage
    # only — the cost column is a literal zero because AI is not charged for yet.
    "opteryx.ops.ai_usage_billing",
)

# Every relation carrying a `billing_account` column that a caller may reach. Both the
# reader grants and the row-level filters are derived from this, so a rollup added
# above is covered by both without anyone having to remember the second one.
BILLING_RELATIONS = (BILLING_RELATION, *BILLING_ROLLUP_RELATIONS)

# Relations any AUTHENTICATED caller may read, regardless of the policies in their token.
# This is deliberately not the same as anonymous access (see ANONYMOUS_EXEMPT_PAIRS):
# row-level filtering scopes these to the caller's own billing account, which is only
# possible once we know who the caller is. An anonymous caller has no account to scope
# to and so must get nothing — see visibility_filters_from_claims, which denies rather
# than allows when the account is unknown.
#
# Deliberately the rollups only, not BILLING_RELATION itself: a caller needs their
# account's aggregated usage/cost, never the raw per-query-event table (which carries
# the submitted SQL and the submitting user). Reading the raw table still requires an
# explicit reader policy in the caller's own token (or the data_admin exemption) — this
# blanket grant does not extend to it. It still gets a row-level filter below regardless
# (see visibility_filters_from_claims), since that path is keyed off BILLING_RELATIONS
# independently and must stay fail-safe for whoever *does* hold an explicit grant on it.
AUTHENTICATED_READ_RELATIONS = BILLING_ROLLUP_RELATIONS


def access_policies_for_query(claims: Dict[str, Any]) -> List[Dict[str, str]]:
    """Access policies for executing a query, including authenticated-read grants.

    This is the caller's own policies plus a reader grant on AUTHENTICATED_READ_RELATIONS
    when the caller is authenticated.

    Kept separate from `get_access_policies_from_claims` on purpose: the $metadata
    authorization path collapses a policy pattern to its workstream
    (`pattern.split(".")[0]`), so feeding these grants through there would widen access
    to every dataset in the workstream rather than the named relations. Opteryx's own
    check fnmatches the full relation name, so at the query path the grant stays exact.
    """
    policies = list(get_access_policies_from_claims(claims))

    if claims.get("identity"):
        policies.extend({"pattern": r, "role": "reader"} for r in AUTHENTICATED_READ_RELATIONS)

    return policies


# Deny-all predicate. Opteryx documents an empty list as "no rows visible", but that
# path builds an `Eq(True, False)` literal comparison which the c-native execution engine
# cannot compile — it raises NotSupportedError ("filter predicate outside the c-native
# kernel set") instead of returning nothing, so callers get a 500 rather than an empty
# result. Matching the account against a value it can never hold achieves the same thing
# through a kernel that does exist. A NUL byte cannot appear in a JWT claim or a Firestore
# collection name, so nothing can collide with this.
_DENY_ALL_ACCOUNT = "\x00__deny_all__"


def visibility_filters_from_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Build Opteryx row-level visibility filters for the caller.

    Opteryx keys these by relation name and applies them only to relations present in
    the dict — an absent relation is returned UNFILTERED. That makes this fail-open, so
    every billing relation is always given an entry: either a real predicate, or one
    that matches nothing. Never return `{}` for a caller we cannot identify; that would
    serve every account's billing data rather than none of it.

    Both the base table and the materialized rollups are keyed, because which one a
    query scans depends on which one it names — the rollups no longer expand into the
    base table.

    Filters for relations the query never touches cost nothing, so this is applied to
    every request rather than being special-cased per endpoint.

    Callers holding the data_admin entitlement are exempt: they get an empty dict, which
    Opteryx treats as "no filtering", so they see every account's rows.

    Returns:
        dict: {relation_name: DNF predicate list}, suitable for
              `visibility_filters=` on the Opteryx planner entry points.
    """
    if DATA_ADMIN_ENTITLEMENT in entitlements_from_claims(claims):
        return {}

    billing_account = claims.get("billing_account") or _DENY_ALL_ACCOUNT

    predicate = [("billing_account", "Eq", billing_account)]
    return {relation: list(predicate) for relation in BILLING_RELATIONS}


def convert_policies_for_opteryx(policies: Optional[list]) -> List[Dict[str, str]]:
    """Convert JWT "policies" claim to Opteryx access_policies format.

    Accepts policies in various formats:
      - list of dicts: [{"id": ..., "role": "reader", "pattern": "benchmarks.*"}, ...]
      - list of lists/tuples: [[policy_id, role, pattern], ...]

    Returns:
        list: List of dicts in Opteryx format with "pattern", "role", and
              "policy" (the policy id, or None if the input format doesn't
              carry one) keys. Returns empty list if policies is None or empty.
    """
    if not policies:
        return []

    access_policies = []

    try:
        for p in policies:
            # dict format
            if isinstance(p, dict):
                role = p.get("role")
                pattern = p.get("pattern") or p.get("workspace") or p.get("resource")
                policy_id = p.get("id")
                if role and pattern:
                    access_policies.append({"pattern": pattern, "role": role, "policy": policy_id})
            # list/tuple format: [id, role, pattern, ...]
            elif isinstance(p, (list, tuple)) and len(p) >= 3:
                policy_id = p[0]
                role = p[1]
                pattern = p[2]
                if role and pattern:
                    access_policies.append({"pattern": pattern, "role": role, "policy": policy_id})
            # legacy/two-element tuples (role, pattern)
            elif isinstance(p, (list, tuple)) and len(p) == 2:
                role = p[0]
                pattern = p[1]
                if role and pattern:
                    access_policies.append({"pattern": pattern, "role": role, "policy": None})
    except Exception as exc:
        logger.warning(f"Failed to convert policies to Opteryx format: {exc}. Policies: {policies}")
        return []

    return access_policies


def get_access_policies_from_claims(claims: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract and convert JWT "policies" claim to Opteryx access policies.

    This function DOES NOT mutate the provided `claims` dict; it converts
    the token's "policies" claim on-the-fly and returns Opteryx-format
    access policies.

    Args:
        claims: JWT claims dict containing policies

    Returns:
        list: Access policies in Opteryx format

    Examples:
        >>> claims = {"policies": [["id", "reader", "public.*"]], "identity": "user@example.com"}
        >>> get_access_policies_from_claims(claims)
        [{"pattern": "public.*", "role": "reader"}]
    """
    policies = claims.get("policies", [])
    return convert_policies_for_opteryx(policies)
