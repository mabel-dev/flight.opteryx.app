"""Authorization: does an identity reach exactly what it should, and does
this service answer that question the same way its siblings do?

Divergence between odata.opteryx, jobs.opteryx and this service on the same
authorization question has been a recurring production problem -- the
`BILLING_NAMESPACE` comment in `app.auth.permissions` records one such drift
that left this very service "serving every account's rollup rows". So the
sibling contract is pinned here as literal expectations rather than left
implicit.

**Why literals and not a cross-repo import.** The obvious test is to import
odata.opteryx's `app.auth.permissions` and diff it. That test cannot run in
CI: the siblings are not installed (deliberately -- see the repo's testing
constraints) and are not on disk in a GitHub runner. A test that silently
skips when they are absent would pass in CI while checking nothing, which is
the failure mode this whole exercise exists to remove. So each constant
below is transcribed, with its source named, and changing it is a deliberate
edit somebody has to justify.

Sources, as of this change:
  * odata.opteryx `app/auth/permissions.py`
  * jobs.opteryx  `app/utils/claims.py`, `app/auth/deps.py`
"""

import pytest

from app.auth import permissions
from app.flight import metadata

# --- transcribed sibling contract -------------------------------------------

# odata.opteryx app/auth/permissions.py::ANONYMOUS_EXEMPT_PAIRS
ODATA_ANONYMOUS_EXEMPT_PAIRS = {("public", "security"), ("public", "geopolitics")}

# odata.opteryx app/auth/permissions.py::_READ_CAPABLE_ROLES
ODATA_READ_CAPABLE_ROLES = {"reader", "writer", "admin", "owner"}

# odata.opteryx app/auth/permissions.py -- module constants
ODATA_DATA_ADMIN_ENTITLEMENT = "data_admin"
ODATA_ENTITLEMENT_URN_PREFIX = "urn:opteryx:entitlement:"
ODATA_BILLING_NAMESPACE = "platform.billing.*"
ODATA_AUTHENTICATED_READ_RELATIONS = (
    "platform.billing.charges_daily",
    "platform.billing.charges_daily_by_workspace",
)
ODATA_ACTOR_BREAKDOWN_RELATION = "platform.billing.charges_daily_by_actor"


# --- the constants themselves -----------------------------------------------


def test_anonymous_surface_matches_odata():
    # The full set of (workstream, collection) pairs reachable with no
    # credentials. If this service ever exposed a pair odata.opteryx does
    # not, Flight would be the soft underbelly of the fleet.
    assert permissions.ANONYMOUS_EXEMPT_PAIRS == ODATA_ANONYMOUS_EXEMPT_PAIRS


def test_billing_constants_match_odata():
    assert permissions.DATA_ADMIN_ENTITLEMENT == ODATA_DATA_ADMIN_ENTITLEMENT
    assert permissions._ENTITLEMENT_URN_PREFIX == ODATA_ENTITLEMENT_URN_PREFIX
    assert permissions.BILLING_NAMESPACE == ODATA_BILLING_NAMESPACE
    assert permissions.AUTHENTICATED_READ_RELATIONS == ODATA_AUTHENTICATED_READ_RELATIONS
    assert permissions.ACTOR_BREAKDOWN_RELATION == ODATA_ACTOR_BREAKDOWN_RELATION


def test_read_capable_roles_match_odata():
    # This service keeps its own private copy of the role set
    # (`metadata._role_allows_read`) rather than importing odata's
    # `role_allows_read`, so the two can drift silently. Pin both directions:
    # every role odata reads with must read here, and no other role may.
    for role in ODATA_READ_CAPABLE_ROLES:
        assert metadata._role_allows_read(role), role
        assert metadata._role_allows_read(role.upper()), role  # comparison is casefolded

    for role in ("viewer", "auditor", "none", "", None):
        assert not metadata._role_allows_read(role), role


# --- entitlement parsing ----------------------------------------------------

# odata.opteryx and jobs.opteryx implement `entitlements_from_claims` with
# the same body (jobs returns a sorted list, odata and this service a set),
# so the *semantics* are what agreement means here.
ENTITLEMENT_CASES = [
    ({"entitlement": "data_admin"}, {"data_admin"}),
    ({"entitlement": "data_admin,user_admin"}, {"data_admin", "user_admin"}),
    ({"entitlement": "data_admin, user_admin"}, {"data_admin", "user_admin"}),
    ({"entitlements": ["data_admin", "user_admin"]}, {"data_admin", "user_admin"}),
    ({"entitlement": "urn:opteryx:entitlement:data_admin"}, {"data_admin"}),
    ({"entitlement": ""}, set()),
    ({}, set()),
    ({"entitlement": 17}, set()),  # unexpected type: ignored, never raised on
]


@pytest.mark.parametrize("claims,expected", ENTITLEMENT_CASES)
def test_entitlement_parsing_matches_siblings(claims, expected):
    assert permissions.entitlements_from_claims(claims) == expected


def test_scoped_entitlements_survive_unprefixed():
    # opteryx_access only recognises a scoped entitlement written bare --
    # `automation_admin::public` resolves, `urn:...:automation_admin::public`
    # resolves to nothing. Stripping the prefix is therefore load-bearing,
    # not cosmetic, and the scope separator must come through untouched.
    claims = {"entitlement": "urn:opteryx:entitlement:automation_admin::public"}
    assert permissions.entitlements_from_claims(claims) == {"automation_admin::public"}


# --- identity -> what the query engine is told ------------------------------


def test_anonymous_claims_get_no_policies_at_all():
    # The single most important line in this service's authorization: a
    # caller with nothing must be handed `[]`, which opteryx reads as
    # deny-all. `None` would mean "no argument given", which opteryx defaults
    # to owner-on-everything. Covered for `session_for_claims` in
    # test_query_unit; covered here at the policy-building layer, which is
    # where the value originates.
    assert permissions.access_policies_for_query({}) == []
    assert permissions.access_policies_for_query({"identity": None, "policies": []}) == []


def test_a_callers_own_policies_are_passed_through_verbatim():
    claims = {
        "identity": "u@example.com",
        "policies": [{"id": "p1", "role": "reader", "pattern": "acme.sales.*"}],
    }
    policies = permissions.access_policies_for_query(claims)
    assert {"pattern": "acme.sales.*", "role": "reader", "policy": "p1"} in policies


def test_no_wildcard_owner_grant_is_ever_synthesised():
    # The blast radius test. Whatever shape of claims arrives, this service
    # must never manufacture a grant on `*` -- that is opteryx's own
    # "no argument given" default and must stay unreachable from here.
    shapes = [
        {},
        {"identity": "u@example.com"},
        {"identity": "u@example.com", "policies": []},
        {"identity": "u@example.com", "policies": [{"role": "owner", "pattern": "acme.*"}]},
        {"identity": "u@example.com", "entitlement": "data_admin"},
        {"identity": "u@example.com", "policies": "not-a-list"},
    ]
    for claims in shapes:
        for policy in permissions.access_policies_for_query(claims):
            assert policy["pattern"] != "*", claims


def test_malformed_policies_are_dropped_not_widened():
    # A policy missing a role or a pattern must vanish, not fall back to
    # something permissive.
    claims = {
        "identity": "u@example.com",
        "policies": [
            {"role": "reader"},  # no pattern
            {"pattern": "acme.*"},  # no role
            {},
            "nonsense",
            {"role": "reader", "pattern": "acme.sales.orders"},
        ],
    }
    patterns = [p["pattern"] for p in permissions.access_policies_for_query(claims)]
    assert "acme.sales.orders" in patterns
    assert "acme.*" not in patterns


# --- dataset visibility (the GetTables/GetCatalogs/GetDbSchemas surface) ----
#
# `list_visible_datasets` is the only place this service decides, on its own,
# which datasets an identity may even know exist. It was previously untested:
# tests/test_metadata_unit.py monkeypatches it away wholesale to test the
# Arrow shaping above it. Firestore is mocked at the client boundary here so
# the real access-control body runs.

ALL_ROWS = [
    metadata.DatasetRow("public", "geopolitics", "countries", "TABLE"),
    metadata.DatasetRow("public", "security", "incidents", "TABLE"),
    metadata.DatasetRow("public", "internal_only", "secrets", "TABLE"),
    metadata.DatasetRow("acme", "sales", "orders", "TABLE"),
    metadata.DatasetRow("acme", "hr", "salaries", "TABLE"),
    metadata.DatasetRow("globex", "sales", "orders", "TABLE"),
    metadata.DatasetRow("personal", "alice@example.com", "scratch", "TABLE"),
    metadata.DatasetRow("personal", "bob@example.com", "bobs_notes", "TABLE"),
]


@pytest.fixture()
def catalog(monkeypatch):
    """Stand in for Firestore at the client boundary.

    `_workspace_datasets` and `_personal_datasets` are replaced rather than
    `_get_firestore_client`, because faking Firestore's collection-group
    query builder faithfully would be a bigger fake than the thing under
    test. Everything above them -- the policy-to-workspace mapping and the
    per-row visibility decision, which is the access control -- still runs
    for real.
    """

    def _workspace_datasets(db, workspace_ids):
        return [row for row in ALL_ROWS if row.catalog_name in set(workspace_ids)]

    def _personal_datasets(db, identity):
        return [
            row
            for row in ALL_ROWS
            if row.catalog_name == "personal" and row.db_schema_name == identity
        ]

    monkeypatch.setattr(metadata, "_get_firestore_client", lambda database: object())
    monkeypatch.setattr(metadata, "_workspace_datasets", _workspace_datasets)
    monkeypatch.setattr(metadata, "_personal_datasets", _personal_datasets)


def _visible(claims):
    return {
        (r.catalog_name, r.db_schema_name, r.table_name)
        for r in metadata.list_visible_datasets(claims)
    }


def test_anonymous_caller_sees_only_the_exempt_pairs(catalog):
    # Agreement with odata.opteryx's service document: an unidentified caller
    # sees the exempt pairs and nothing else -- notably NOT the rest of the
    # `public` workspace, which is visible to authenticated callers.
    assert _visible({}) == {
        ("public", "geopolitics", "countries"),
        ("public", "security", "incidents"),
    }


def test_anonymous_caller_cannot_widen_itself_with_policies(catalog):
    # Policies on a token with no identity must buy nothing. Otherwise a
    # token that merely failed to carry a `sub` would be a way around the
    # anonymous surface.
    claims = {"policies": [{"role": "owner", "pattern": "acme.*"}]}
    assert _visible(claims) == {
        ("public", "geopolitics", "countries"),
        ("public", "security", "incidents"),
    }


def test_identity_reaches_its_own_personal_workspace(catalog):
    claims = {"identity": "alice@example.com", "policies": []}
    assert ("personal", "alice@example.com", "scratch") in _visible(claims)


def test_identity_never_reaches_another_identitys_personal_workspace(catalog):
    # The sharpest authorization line in the service: `personal.<identity>`
    # is nobody else's, whatever policies they hold.
    claims = {
        "identity": "alice@example.com",
        "policies": [{"role": "owner", "pattern": "personal.*"}],
    }
    visible = _visible(claims)
    assert ("personal", "alice@example.com", "scratch") in visible
    assert ("personal", "bob@example.com", "bobs_notes") not in visible


def test_a_grant_on_one_workspace_does_not_reach_another(catalog):
    claims = {"identity": "u@example.com", "policies": [{"role": "reader", "pattern": "acme.*"}]}
    visible = _visible(claims)
    assert ("acme", "sales", "orders") in visible
    assert ("globex", "sales", "orders") not in visible


def test_a_non_read_capable_role_grants_no_visibility(catalog):
    claims = {"identity": "u@example.com", "policies": [{"role": "auditor", "pattern": "acme.*"}]}
    visible = _visible(claims)
    assert not any(catalog_name == "acme" for catalog_name, _, _ in visible)


def test_authenticated_callers_see_the_whole_public_workspace(catalog):
    # Wider than the anonymous surface, and intentionally so: `public` is
    # readable by anyone who is somebody. Pinned because the difference
    # between the two surfaces is easy to collapse by accident.
    claims = {"identity": "u@example.com", "policies": []}
    assert ("public", "internal_only", "secrets") in _visible(claims)


def test_KNOWN_DIVERGENCE_a_relation_grant_is_widened_to_its_whole_workspace(catalog):
    """A grant on ONE relation makes every relation beside it visible here.

    This is a characterization test, not an endorsement. `list_visible_datasets`
    maps a policy to a workspace with `pattern.split(".")[0]` and then decides
    visibility per workspace, so `reader on acme.sales.orders` discloses
    `acme.hr.salaries` too.

    odata.opteryx answers the same question with `read_grant_for_relation`,
    which fnmatches the policy pattern against the FULL relation name, and its
    docstring names this exact failure: "Matching on anything less (e.g.
    collapsing the pattern to its workstream) would let a grant on one relation
    disclose every relation beside it."

    So the two services disagree, and this service is the permissive one. The
    assertion below records what it does TODAY so the divergence is visible in
    the suite rather than latent. Closing it means giving this service the
    equivalent of `read_grant_for_relation`, which changes what GetTables
    returns and is deliberately out of scope for a CI-enablement change --
    it is reported as a finding instead.
    """
    claims = {
        "identity": "u@example.com",
        "policies": [{"role": "reader", "pattern": "acme.sales.orders"}],
    }
    visible = _visible(claims)

    assert ("acme", "sales", "orders") in visible  # granted, and correct
    assert ("acme", "hr", "salaries") in visible  # NOT granted -- the divergence

    # The part that is at least not broken: the widening stops at the
    # workspace boundary and does not reach a workspace nothing was granted in.
    assert ("globex", "sales", "orders") not in visible
