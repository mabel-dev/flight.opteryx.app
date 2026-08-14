"""Tests for row-level visibility filtering of billing data.

These guard behaviour that fails silently and expensively if it regresses: Opteryx
leaves unlisted relations UNFILTERED, so a mistake here serves every tenant's billing
data rather than raising. Note that asserting "account A sees A's rows" passes even
when filtering is entirely broken — the assertions that matter are the ones checking
that a filter is present and that it actually covers what the grant hands out.

Mirrors odata.opteryx's copy: these two doors carry the same policy and drifted
apart once before, which is how this door served every account's rollup rows.

The enumerated relation list these used to guard is gone, replaced by a namespace
pattern. The failure it existed to catch — a new relation nobody added to the list —
is now impossible by construction, so what needs pinning instead is that the pattern
covers the grant and that nothing outside the namespace is granted.
"""

from fnmatch import fnmatchcase

from app.auth.permissions import (
    AUTHENTICATED_READ_RELATIONS,
    BILLING_NAMESPACE,
    DATA_ADMIN_ENTITLEMENT,
    access_policies_for_query,
    billing_account_from_claims,
    entitlements_from_claims,
    visibility_filters_from_claims,
)

SCOPED = {"identity": "u", "billing_account": "acme"}


def _predicate(claims):
    return visibility_filters_from_claims(claims).get(BILLING_NAMESPACE)


def test_the_filter_is_keyed_on_a_pattern_not_a_relation_name():
    """A glob metacharacter is what makes opteryx-core fnmatch the key instead of
    looking it up exactly. Without one this silently reverts to matching a single
    relation literally named `platform.billing.*`, i.e. nothing at all."""
    assert "*" in BILLING_NAMESPACE
    assert BILLING_NAMESPACE == "platform.billing.*"


def test_every_granted_relation_is_covered_by_the_filter_pattern():
    """The grant hands out read access; the pattern is what scopes it to one account.
    A granted relation the pattern does not match is served UNFILTERED — every
    tenant's rows — and nothing raises."""
    assert AUTHENTICATED_READ_RELATIONS
    for relation in AUTHENTICATED_READ_RELATIONS:
        assert fnmatchcase(relation, BILLING_NAMESPACE), (
            f"{relation} is blanket-readable but outside {BILLING_NAMESPACE}"
        )


def test_the_raw_event_stream_is_not_blanket_readable():
    """`platform.billing.events` carries the submitted SQL and the submitting user.
    It stays behind an explicit reader policy or the data_admin exemption — while
    remaining row-filtered, because the pattern covers the whole namespace."""
    assert "platform.billing.events" not in AUTHENTICATED_READ_RELATIONS
    assert fnmatchcase("platform.billing.events", BILLING_NAMESPACE), (
        "not granted, but must still be filtered"
    )


def test_the_grant_is_narrower_than_the_filter():
    """Deliberate asymmetry: filter fail-safe over everything, grant only what a
    tenant needs. If these ever become equal, something has been widened."""
    covered_but_ungranted = [
        "platform.billing.events",
        "platform.billing.account_daily",
        "platform.billing.attribution_daily",
        "platform.billing.usage_hourly",
    ]
    for relation in covered_but_ungranted:
        assert fnmatchcase(relation, BILLING_NAMESPACE)
        assert relation not in AUTHENTICATED_READ_RELATIONS


def test_a_relation_outside_the_namespace_is_not_covered():
    """The pattern must not be so loose it filters unrelated relations — that would
    make every one of them fail to bind for lack of a billing_account column."""
    for relation in ("public.astronomy.planets", "opteryx.ops.audit_log", "platform.pricing.rate_card"):
        assert not fnmatchcase(relation, BILLING_NAMESPACE)


def test_pricing_reference_data_is_outside_the_namespace():
    """`platform.pricing.rate_card` has no billing_account column, so being covered
    would make it unqueryable — and a tenant reading it would see other accounts'
    negotiated prices. Both reasons it lives in a separate namespace."""
    assert not fnmatchcase("platform.pricing.rate_card", BILLING_NAMESPACE)


def test_account_is_scoped_to_the_callers_own_account():
    assert _predicate(SCOPED) == [("billing_account", "Eq", "acme")]


def test_unknown_account_denies_rather_than_leaking():
    """A caller we cannot identify must get no rows, not every row."""
    for claims in (
        {"identity": "u", "billing_account": None},
        {"identity": None, "billing_account": None},
        {},
    ):
        predicate = _predicate(claims)
        assert predicate, "the namespace must always carry a filter (absent == unfiltered)"
        column, op, value = predicate[0]
        assert (column, op) == ("billing_account", "Eq")
        assert value not in (None, ""), "must not match rows with a null/empty account"


def test_deny_all_is_not_the_empty_list():
    """Opteryx documents `[]` as deny-all, but it compiles to an Eq(True, False) literal
    the c-native engine cannot execute — it raises NotSupportedError instead of returning
    nothing, turning a denial into a 500."""
    assert _predicate({"identity": "u", "billing_account": None}) != []


def test_data_admin_is_exempt_from_row_filtering():
    for claims in (
        {"identity": "b", "billing_account": "opteryx", "entitlement": "user_admin,data_admin"},
        {"identity": "b", "billing_account": "opteryx", "entitlements": ["data_admin"]},
        {"identity": "b", "billing_account": None, "entitlement": "data_admin"},
    ):
        assert visibility_filters_from_claims(claims) == {}


def test_other_entitlements_do_not_grant_exemption():
    claims = {"identity": "u", "billing_account": "acme", "entitlement": "user_admin"}
    assert _predicate(claims) == [("billing_account", "Eq", "acme")]
    assert DATA_ADMIN_ENTITLEMENT not in entitlements_from_claims(claims)


def test_only_data_admin_ever_produces_an_empty_filter_set():
    """An empty dict means 'no filtering at all'. Nothing but the admin exemption may
    produce one, or that becomes a route to unfiltered billing data."""
    for claims in (
        SCOPED,
        {"identity": "u", "billing_account": None},
        {"identity": None},
        {"identity": "u", "entitlement": "user_admin"},
        {},
    ):
        assert visibility_filters_from_claims(claims) != {}


def test_the_blanket_grant_requires_authentication():
    """Row-level filtering scopes these to the caller's own account, which is only
    possible once we know who the caller is. An anonymous caller has no account to
    scope to and so must get nothing."""
    anonymous = [p["pattern"] for p in access_policies_for_query({"policies": []})]
    for relation in AUTHENTICATED_READ_RELATIONS:
        assert relation not in anonymous

    authenticated = [p["pattern"] for p in access_policies_for_query({"identity": "u", "policies": []})]
    for relation in AUTHENTICATED_READ_RELATIONS:
        assert relation in authenticated


def test_billing_account_comes_from_its_own_claim():
    """Many users bill to one account, so the account is carried explicitly rather
    than inferred from identity."""
    claims = {"sub": "bastian", "identity": "bastian", "billing_account": "acme"}
    assert billing_account_from_claims(claims) == "acme"


def test_scope_is_never_read_as_a_billing_account():
    """Regression: `scope` is an OAuth permission list, not a tenant identity."""
    assert billing_account_from_claims({"sub": "bastian", "scope": "opteryx"}) == "bastian"
    assert billing_account_from_claims({"sub": "bastian", "scope": "read,write"}) == "bastian"
    claims = {"sub": "bastian", "scope": "opteryx", "billing_account": "acme"}
    assert billing_account_from_claims(claims) == "acme"


def test_absent_account_bills_to_the_caller_themselves():
    """An unscoped individual bills to themselves, not to the house account — which
    is exactly what platform.billing.attribution resolves them to."""
    assert billing_account_from_claims({"sub": "bastian"}) == "bastian"
    assert billing_account_from_claims({"sub": "bastian", "billing_account": None}) == "bastian"


def test_unidentifiable_caller_yields_no_account():
    assert billing_account_from_claims({}) is None
    assert billing_account_from_claims({"sub": None}) is None
    assert billing_account_from_claims({"sub": "   "}) is None
    assert billing_account_from_claims({"billing_account": ["acme"]}) is None
