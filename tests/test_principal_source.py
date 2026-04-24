"""Tests for principal source (internal vs external/IdP-synced) tagging."""

from __future__ import annotations

import pytest
import responses as responses_lib

from tests.conftest import (
    ACCOUNT_HOST,
    ACCOUNT_ID,
    WORKSPACE_HOST,
    ALL_GROUPS,
    ALL_USERS,
    ALL_SPS,
    SCIM_GROUP_DATA_ENGINEERS,
    SCIM_USER_ALICE,
    SCIM_SP_ETL,
)
from databricks_group_audit.models import (
    GroupMember,
    GroupMembership,
    GroupNode,
    MemberType,
    PrincipalAuditResult,
    PrincipalSource,
    _source_from_external_id,
)

BASE = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"


# ---------------------------------------------------------------------------
# _source_from_external_id helper
# ---------------------------------------------------------------------------


def test_source_external_when_id_set():
    assert _source_from_external_id("abc-123") == PrincipalSource.EXTERNAL


def test_source_internal_when_none():
    assert _source_from_external_id(None) == PrincipalSource.INTERNAL


def test_source_internal_when_empty_string():
    assert _source_from_external_id("") == PrincipalSource.INTERNAL


# ---------------------------------------------------------------------------
# GroupMember.source property
# ---------------------------------------------------------------------------


def test_group_member_source_external():
    m = GroupMember(id="u-1", display_name="Alice", member_type=MemberType.USER,
                    external_id="entra-abc-123")
    assert m.source == PrincipalSource.EXTERNAL


def test_group_member_source_internal():
    m = GroupMember(id="u-1", display_name="Alice", member_type=MemberType.USER,
                    external_id=None)
    assert m.source == PrincipalSource.INTERNAL


def test_group_member_default_external_id_is_none():
    m = GroupMember(id="u-1", display_name="Alice", member_type=MemberType.USER)
    assert m.external_id is None
    assert m.source == PrincipalSource.INTERNAL


# ---------------------------------------------------------------------------
# GroupNode.source property
# ---------------------------------------------------------------------------


def test_group_node_source_external():
    n = GroupNode(id="g-1", display_name="data-engineers", external_id="okta-grp-xyz")
    assert n.source == PrincipalSource.EXTERNAL


def test_group_node_source_internal():
    n = GroupNode(id="g-1", display_name="data-engineers", external_id=None)
    assert n.source == PrincipalSource.INTERNAL


# ---------------------------------------------------------------------------
# GroupMembership.source property
# ---------------------------------------------------------------------------


def test_group_membership_source():
    gm = GroupMembership(group_id="g-1", group_name="admins", external_id="ext-123")
    assert gm.source == PrincipalSource.EXTERNAL

    gm2 = GroupMembership(group_id="g-2", group_name="local-group")
    assert gm2.source == PrincipalSource.INTERNAL


# ---------------------------------------------------------------------------
# PrincipalAuditResult.principal_source property
# ---------------------------------------------------------------------------


def test_result_source_external():
    r = PrincipalAuditResult(
        principal_type="USER", principal_id="u-1",
        principal_name="alice@example.com",
        principal_external_id="entra-alice-xyz",
    )
    assert r.principal_source == PrincipalSource.EXTERNAL


def test_result_source_internal_default():
    r = PrincipalAuditResult(
        principal_type="USER", principal_id="u-1",
        principal_name="alice@example.com",
    )
    assert r.principal_source == PrincipalSource.INTERNAL


# ---------------------------------------------------------------------------
# Group resolver extracts externalId from SCIM
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_client():
    from databricks_group_audit.client import DatabricksAPIClient
    return DatabricksAPIClient(
        client_id="cid", client_secret="sec",
        account_id=ACCOUNT_ID, account_host=ACCOUNT_HOST,
    )


def test_resolver_extracts_group_external_id(mock_client):
    group_with_ext = {**SCIM_GROUP_DATA_ENGINEERS, "externalId": "entra-grp-001"}
    user_with_ext = {**SCIM_USER_ALICE, "externalId": "entra-user-alice"}

    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.POST, f"{ACCOUNT_HOST}/oidc/v1/token",
                 json={"access_token": "tok", "expires_in": 3600})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Groups",
                 json={"Resources": [group_with_ext], "totalResults": 1})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Groups/{group_with_ext['id']}",
                 json=group_with_ext)
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Users",
                 json={"Resources": [user_with_ext], "totalResults": 1})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Users/{user_with_ext['id']}",
                 json=user_with_ext)
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/ServicePrincipals",
                 json={"Resources": ALL_SPS, "totalResults": len(ALL_SPS)})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/ServicePrincipals/sp-1",
                 json=SCIM_SP_ETL)

        from databricks_group_audit.group_resolver import GroupMembershipResolver
        resolver = GroupMembershipResolver(mock_client)
        node = resolver.resolve_group("data-engineers")

    assert node is not None
    assert node.external_id == "entra-grp-001"
    assert node.source == PrincipalSource.EXTERNAL

    alice = next(u for u in node.direct_users if u.id == "user-1")
    assert alice.external_id == "entra-user-alice"
    assert alice.source == PrincipalSource.EXTERNAL


def test_resolver_no_external_id_is_internal(mock_client):
    # Standard fixtures have no externalId
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.POST, f"{ACCOUNT_HOST}/oidc/v1/token",
                 json={"access_token": "tok", "expires_in": 3600})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Groups",
                 json={"Resources": [SCIM_GROUP_DATA_ENGINEERS], "totalResults": 1})
        rsps.add(responses_lib.GET,
                 f"{BASE}/scim/v2/Groups/{SCIM_GROUP_DATA_ENGINEERS['id']}",
                 json=SCIM_GROUP_DATA_ENGINEERS)
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Users",
                 json={"Resources": ALL_USERS, "totalResults": len(ALL_USERS)})
        for u in ALL_USERS:
            rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Users/{u['id']}", json=u)
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/ServicePrincipals",
                 json={"Resources": ALL_SPS, "totalResults": len(ALL_SPS)})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/ServicePrincipals/sp-1",
                 json=SCIM_SP_ETL)

        from databricks_group_audit.group_resolver import GroupMembershipResolver
        resolver = GroupMembershipResolver(mock_client)
        node = resolver.resolve_group("data-engineers")

    assert node is not None
    assert node.external_id is None
    assert node.source == PrincipalSource.INTERNAL

    for u in node.direct_users:
        assert u.external_id is None
        assert u.source == PrincipalSource.INTERNAL


def test_sp_external_id_extracted(mock_client):
    sp_with_ext = {**SCIM_SP_ETL, "externalId": "aws-sso-sp-xyz"}
    group = {**SCIM_GROUP_DATA_ENGINEERS, "members": [
        {"value": "sp-1", "display": "ETL-Bot", "$ref": "ServicePrincipals/sp-1"},
    ]}

    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.POST, f"{ACCOUNT_HOST}/oidc/v1/token",
                 json={"access_token": "tok", "expires_in": 3600})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Groups",
                 json={"Resources": [group], "totalResults": 1})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Groups/group-1", json=group)
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Users",
                 json={"Resources": [], "totalResults": 0})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/ServicePrincipals",
                 json={"Resources": [sp_with_ext], "totalResults": 1})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/ServicePrincipals/sp-1",
                 json=sp_with_ext)

        from databricks_group_audit.group_resolver import GroupMembershipResolver
        resolver = GroupMembershipResolver(mock_client)
        node = resolver.resolve_group("data-engineers")

    assert node is not None
    etl = next(sp for sp in node.direct_service_principals if sp.id == "sp-1")
    assert etl.external_id == "aws-sso-sp-xyz"
    assert etl.source == PrincipalSource.EXTERNAL


# ---------------------------------------------------------------------------
# principal_auditor — find_principal returns external_id
# ---------------------------------------------------------------------------


def test_find_principal_returns_external_id(mock_client):
    user_ext = {**SCIM_USER_ALICE, "externalId": "okta-alice-99"}

    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.POST, f"{ACCOUNT_HOST}/oidc/v1/token",
                 json={"access_token": "tok", "expires_in": 3600})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Users",
                 json={"Resources": [user_ext], "totalResults": 1})

        from databricks_group_audit.principal_auditor import PrincipalAuditor
        auditor = PrincipalAuditor(mock_client)
        ptype, pid, pname, ext_id = auditor.find_principal("alice@example.com")

    assert ptype == "USER"
    assert ext_id == "okta-alice-99"


def test_find_principal_internal_user_has_no_ext_id(mock_client):
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.POST, f"{ACCOUNT_HOST}/oidc/v1/token",
                 json={"access_token": "tok", "expires_in": 3600})
        rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Users",
                 json={"Resources": [SCIM_USER_ALICE], "totalResults": 1})

        from databricks_group_audit.principal_auditor import PrincipalAuditor
        auditor = PrincipalAuditor(mock_client)
        _, _, _, ext_id = auditor.find_principal("alice@example.com")

    assert ext_id is None


# ---------------------------------------------------------------------------
# get_all_members_flat source breakdown
# ---------------------------------------------------------------------------


def test_members_flat_source_breakdown():
    from databricks_group_audit.group_resolver import GroupMembershipResolver

    node = GroupNode(id="g-1", display_name="admins")
    node.direct_users = [
        GroupMember("u-1", "Alice", MemberType.USER, external_id="ext-1"),
        GroupMember("u-2", "Bob", MemberType.USER, external_id=None),
        GroupMember("u-3", "Charlie", MemberType.USER, external_id="ext-3"),
    ]
    node.direct_service_principals = [
        GroupMember("sp-1", "ETL", MemberType.SERVICE_PRINCIPAL, external_id=None),
    ]

    flat = GroupMembershipResolver.get_all_members_flat(node)
    users = flat["users"]
    sps = flat["service_principals"]

    ext_users = [u for u in users if u.source == PrincipalSource.EXTERNAL]
    int_users = [u for u in users if u.source == PrincipalSource.INTERNAL]
    assert len(ext_users) == 2
    assert len(int_users) == 1

    assert sps[0].source == PrincipalSource.INTERNAL
