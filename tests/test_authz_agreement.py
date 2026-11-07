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

import opteryx_access as access
import pytest

from app.auth import permissions
from app.flight import metadata

# --- transcribed sibling contract -------------------------------------------

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


def test_no_local_anonymous_allowlist_survives():
    # Which workspaces an unidentified caller may read is opteryx-access's
    # decision (`implicit_access` / `can_perform_action` with identity=None).
    # The transcribed copy that used to live here is what drifted between
    # services; it must not quietly come back.
    for name in ("ANONYMOUS_EXEMPT_PAIRS", "ANONYMOUS_EXEMPT_WORKSTREAM", "is_anonymous_exempt"):
        assert not hasattr(permissions, name), name
    assert not hasattr(metadata, "_role_allows_read")


def test_billing_constants_match_odata():
    assert permissions.DATA_ADMIN_ENTITLEMENT == ODATA_DATA_ADMIN_ENTITLEMENT
    assert permissions._ENTITLEMENT_URN_PREFIX == ODATA_ENTITLEMENT_URN_PREFIX
    assert permissions.BILLING_NAMESPACE == ODATA_BILLING_NAMESPACE
    assert permissions.AUTHENTICATED_READ_RELATIONS == ODATA_AUTHENTICATED_READ_RELATIONS
    assert permissions.ACTOR_BREAKDOWN_RELATION == ODATA_ACTOR_BREAKDOWN_RELATION


def test_read_capable_roles_are_the_librarys():
    # Which roles confer READ is opteryx-access's table, not a private copy
    # here. Every role the library reads with makes a granted row visible; a
    # role it does not know makes none visible, whatever its spelling.
    for role in ("reader", "writer", "owner"):
        assert access.action_allowed_for_role(role, "READ"), role
    for role in ("viewer", "auditor", "none", "admin", "READER"):
        assert not access.action_allowed_for_role(role, "READ"), role


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
    metadata.DatasetRow("samples", "tpch_sf1", "lineitem", "TABLE"),
    metadata.DatasetRow("demo", "planets", "moons", "TABLE"),
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


def test_anonymous_caller_sees_only_what_the_library_lets_it_read(catalog):
    # Flight requires a bearer token, but one with no subject still arrives
    # with no identity. What such a caller sees is opteryx-access's decision:
    # in `public`, only the collections it lets an unidentified session read,
    # never the rest of the workspace (which needs a signed-in identity).
    expected = {
        (catalog_name, schema, table)
        for catalog_name, schema, table in {
            ("public", "geopolitics", "countries"),
            ("public", "security", "incidents"),
            ("public", "internal_only", "secrets"),
        }
        if access.can_perform_action([], f"{catalog_name}.{schema}.{table}", "READ")
    }
    assert _visible({}) == expected
    assert ("public", "internal_only", "secrets") not in _visible({})


def test_anonymous_caller_cannot_widen_itself_with_policies(catalog):
    # Policies on a token with no identity must buy nothing. Otherwise a
    # token that merely failed to carry a `sub` would be a way of holding
    # somebody's grants.
    claims = {"policies": [{"role": "owner", "pattern": "acme.*"}]}
    assert _visible(claims) == _visible({})
    assert not any(catalog_name == "acme" for catalog_name, _, _ in _visible(claims))


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
    # Wider than the anonymous surface, and intentionally so: the library
    # makes `public` readable by every signed-in identity. Pinned because the
    # difference between the two surfaces is easy to collapse by accident.
    claims = {"identity": "u@example.com", "policies": []}
    assert ("public", "internal_only", "secrets") in _visible(claims)


def test_samples_and_demo_are_readable_but_not_listed(catalog):
    # Both are readable by a signed-in identity through implicit grants, but
    # deliberately unlisted: implicit grants never appear in the policies
    # claim, and the catalog lists `public` alone by name. Anyone can still
    # query them -- they are just not in the tree.
    assert access.can_perform_action([], "samples.tpch_sf1.lineitem", "READ", identity="u")
    assert access.can_perform_action([], "demo.planets.moons", "READ", identity="u")
    visible = _visible({"identity": "u@example.com", "policies": []})
    assert not any(catalog_name in {"samples", "demo"} for catalog_name, _, _ in visible)
    assert not any(catalog_name in {"samples", "demo"} for catalog_name, _, _ in _visible({}))


def test_an_issued_policy_cannot_reach_a_reserved_workspace(catalog):
    # The library caps reserved workspaces at their implicit grants: a stored
    # policy over `samples` (which `validate_pattern` would refuse to issue
    # today) still confers nothing beyond what the implicit reader grant does.
    claims = {"identity": "u@example.com", "policies": [{"role": "owner", "pattern": "samples.*"}]}
    # the policy names `samples`, so the listing looks there -- and lists it,
    # because the library says a signed-in identity may read it
    assert ("samples", "tpch_sf1", "lineitem") in _visible(claims)
    assert not access.can_perform_action(
        access.parse_policy_claim(claims), "samples.tpch_sf1.lineitem", "DELETE", identity="u"
    )


def test_a_relation_grant_discloses_only_that_relation(catalog):
    """A grant on ONE relation makes only that relation visible.

    This used to be a KNOWN DIVERGENCE: visibility was decided per workspace
    after collapsing each policy to `pattern.split(".")[0]`, so `reader on
    acme.sales.orders` disclosed `acme.hr.salaries` too, where odata.opteryx
    (and the query engine) matched the full relation name. Every row is now
    put to `opteryx_access.can_perform_action`, which matches the full name,
    so the two services agree and the listing no longer names a relation the
    caller cannot read.
    """
    claims = {
        "identity": "u@example.com",
        "policies": [{"role": "reader", "pattern": "acme.sales.orders"}],
    }
    visible = _visible(claims)

    assert ("acme", "sales", "orders") in visible
    assert ("acme", "hr", "salaries") not in visible
    assert ("globex", "sales", "orders") not in visible


def test_triple_shaped_policies_still_grant_visibility(catalog):
    # The issuer's `[id, role, pattern]` triple is a shape the library's own
    # claim parser skips; `grants_from_claims` converts it first, so it must
    # still reach the library as a grant.
    claims = {"identity": "u@example.com", "policies": [["p1", "reader", "acme.hr.*"]]}
    visible = _visible(claims)
    assert ("acme", "hr", "salaries") in visible
    assert ("acme", "sales", "orders") not in visible
