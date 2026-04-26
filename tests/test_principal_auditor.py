"""Tests for the principal-centric auditor (reverse lookup)."""

import json

import pytest
import responses

from databricks_group_audit.models import WorkspaceInfo
from databricks_group_audit.principal_auditor import PrincipalAuditor
from tests.conftest import (
    ACCOUNT_HOST,
    ACCOUNT_ID,
    ALL_GROUPS,
    CATALOGS_RESPONSE,
    MAIN_CATALOG_GRANTS,
    SCIM_SP_ETL,
    SCIM_USER_ALICE,
    SCIM_USER_BOB,
    SCIM_USER_CHARLIE,
    STAGING_CATALOG_GRANTS,
    WORKSPACE_HOST,
)

BASE = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_scim_endpoints(rsps):
    """Register standard SCIM mock endpoints."""
    rsps.add(responses.POST, f"{ACCOUNT_HOST}/oidc/accounts/{ACCOUNT_ID}/v1/token",
             json={"access_token": "mock-token", "expires_in": 3600})

    # Group list — supports filter queries by matching displayName or returning all
    def _group_list_callback(request):
        filt = request.params.get("filter", "")
        if "displayName" in filt:
            name = filt.split('"')[1]
            matched = [g for g in ALL_GROUPS if g["displayName"] == name]
        else:
            matched = ALL_GROUPS
        body = {"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100}
        return (200, {}, body)

    rsps.add_callback(responses.GET, f"{BASE}/scim/v2/Groups",
                      callback=lambda req: (200, {}, json.dumps(_group_list_callback(req)[2])),
                      content_type="application/json")

    # Individual groups
    for g in ALL_GROUPS:
        rsps.add(responses.GET, f"{BASE}/scim/v2/Groups/{g['id']}", json=g)

    # User list with filter support
    all_users = [SCIM_USER_ALICE, SCIM_USER_BOB, SCIM_USER_CHARLIE]

    def _user_list_callback(request):
        filt = request.params.get("filter", "")
        if "emails.value" in filt:
            email = filt.split('"')[1]
            matched = [u for u in all_users
                       if any(e.get("value") == email for e in u.get("emails", []))]
        else:
            matched = all_users
        return (200, {}, {"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100})

    def _user_cb(req):
        status, headers, body = _user_list_callback(req)
        return status, headers, json.dumps(body)

    rsps.add_callback(responses.GET, f"{BASE}/scim/v2/Users",
                      callback=_user_cb,
                      content_type="application/json")

    # Individual users
    for u in all_users:
        rsps.add(responses.GET, f"{BASE}/scim/v2/Users/{u['id']}", json=u)

    # SP list with filter
    all_sps = [SCIM_SP_ETL]

    def _sp_list_callback(request):
        filt = request.params.get("filter", "")
        if "applicationId" in filt:
            app_id = filt.split('"')[1]
            matched = [s for s in all_sps if s.get("applicationId") == app_id]
        elif "displayName" in filt:
            name = filt.split('"')[1]
            matched = [s for s in all_sps if s.get("displayName") == name]
        else:
            matched = all_sps
        return (200, {}, {"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100})

    def _sp_cb(req):
        status, headers, body = _sp_list_callback(req)
        return status, headers, json.dumps(body)

    rsps.add_callback(responses.GET, f"{BASE}/scim/v2/ServicePrincipals",
                      callback=_sp_cb,
                      content_type="application/json")

    rsps.add(responses.GET, f"{BASE}/scim/v2/ServicePrincipals/sp-1", json=SCIM_SP_ETL)


def _add_workspace_endpoints(rsps):
    """Register workspace permission assignment and UC endpoints."""
    # Workspace token
    rsps.add(responses.POST, f"{WORKSPACE_HOST}/oidc/v1/token",
             json={"access_token": "ws-token", "expires_in": 3600})

    # Permission assignments — Alice is direct USER, data-engineers is USER group
    rsps.add(responses.GET, f"{BASE}/workspaces/ws-001/permissionassignments",
             json={"permission_assignments": [
                 {"principal": {"principal_id": "user-1"}, "permissions": ["USER"]},
                 {"principal": {"principal_id": "group-1"}, "permissions": ["USER"]},
             ]})

    # Catalogs + grants
    rsps.add(responses.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/catalogs",
             json=CATALOGS_RESPONSE)
    rsps.add(responses.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/catalog/main",
             json=MAIN_CATALOG_GRANTS)
    rsps.add(responses.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/catalog/staging",
             json=STAGING_CATALOG_GRANTS)


# ---------------------------------------------------------------------------
# Tests — find_principal
# ---------------------------------------------------------------------------

class TestFindPrincipal:

    @responses.activate
    def test_find_user_by_email(self, mock_client):
        _add_scim_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")
        ptype, pid, name, _ext_id, _uc_name = auditor.find_principal("alice@example.com")
        assert ptype == "USER"
        assert pid == "user-1"
        assert name == "Alice Smith"

    @responses.activate
    def test_find_sp_by_app_id(self, mock_client):
        _add_scim_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")
        ptype, pid, name, _ext_id, _uc_name = auditor.find_principal("app-etl-001")
        assert ptype == "SERVICE_PRINCIPAL"
        assert pid == "sp-1"
        assert name == "ETL-Bot"

    @responses.activate
    def test_find_sp_by_display_name(self, mock_client):
        _add_scim_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")
        ptype, pid, name, _ext_id, _uc_name = auditor.find_principal("ETL-Bot")
        assert ptype == "SERVICE_PRINCIPAL"
        assert pid == "sp-1"

    @responses.activate
    def test_find_group_by_name(self, mock_client):
        _add_scim_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")
        ptype, pid, name, _ext_id, _uc_name = auditor.find_principal("data-engineers")
        # "data-engineers" has no @ so User lookup is skipped; SP lookup fails;
        # but SP by displayName may match first if SP has that name. Since no SP
        # named "data-engineers" exists, it falls through to group.
        assert ptype == "GROUP"
        assert pid == "group-1"

    @responses.activate
    def test_find_nonexistent_raises(self, mock_client):
        _add_scim_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")
        with pytest.raises(ValueError, match="not found"):
            auditor.find_principal("nobody@nowhere.com")

    @responses.activate
    def test_uc_name_is_username_when_different_from_display_name(self, mock_client):
        """Azure AD guest users have a #ext# UPN as userName; uc_name must return it."""
        guest_user = {
            "id": "guest-1",
            "displayName": "External User",
            "userName": "external_gmail.com#ext#@tenant.onmicrosoft.com",
            "emails": [{"value": "external@gmail.com"}],
        }
        rsps = responses
        rsps.add(responses.POST, f"{ACCOUNT_HOST}/oidc/accounts/{ACCOUNT_ID}/v1/token",
                 json={"access_token": "tok", "expires_in": 3600})
        rsps.add(responses.GET, f"{BASE}/scim/v2/Users",
                 json={"Resources": [guest_user], "totalResults": 1, "itemsPerPage": 100})
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")
        ptype, pid, name, _ext_id, uc_name = auditor.find_principal("external@gmail.com")
        assert ptype == "USER"
        assert name == "External User"
        assert uc_name == "external_gmail.com#ext#@tenant.onmicrosoft.com"

    @responses.activate
    def test_uc_name_falls_back_to_identifier_when_no_username(self, mock_client):
        """When SCIM record has no userName, uc_name falls back to the lookup email."""
        _add_scim_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")
        # Alice's mock record has no userName field
        _ptype, _pid, _name, _ext_id, uc_name = auditor.find_principal("alice@example.com")
        assert uc_name == "alice@example.com"


# ---------------------------------------------------------------------------
# Tests — resolve_group_memberships
# ---------------------------------------------------------------------------

class TestResolveGroupMemberships:

    @responses.activate
    def test_user_direct_membership(self, mock_client):
        """Alice (user-1) is a direct member of data-engineers (group-1)."""
        _add_scim_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")

        memberships, id_to_name = auditor.resolve_group_memberships(
            "user-1", "USER", "Alice Smith",
        )

        group_names = {m.group_name for m in memberships}
        assert "data-engineers" in group_names

        # Should also find transitive: all-data-team (parent of data-engineers)
        # and org-all (grandparent)
        assert "all-data-team" in group_names
        assert "org-all" in group_names

    @responses.activate
    def test_direct_vs_transitive_flags(self, mock_client):
        """Direct parents should be flagged is_direct=True, grandparents False."""
        _add_scim_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")

        memberships, _ = auditor.resolve_group_memberships(
            "user-1", "USER", "Alice Smith",
        )

        by_name = {m.group_name: m for m in memberships}
        assert by_name["data-engineers"].is_direct is True
        assert by_name["all-data-team"].is_direct is False
        assert by_name["org-all"].is_direct is False

    @responses.activate
    def test_sp_membership(self, mock_client):
        """SP sp-1 is a member of data-engineers."""
        _add_scim_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")

        memberships, _ = auditor.resolve_group_memberships(
            "sp-1", "SERVICE_PRINCIPAL", "ETL-Bot",
        )

        group_names = {m.group_name for m in memberships}
        assert "data-engineers" in group_names

    @responses.activate
    def test_membership_paths(self, mock_client):
        """Paths should trace from the principal upward."""
        _add_scim_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")

        memberships, _ = auditor.resolve_group_memberships(
            "user-1", "USER", "Alice Smith",
        )

        by_name = {m.group_name: m for m in memberships}
        # Direct parent path: [Alice Smith, data-engineers]
        assert by_name["data-engineers"].path == ["Alice Smith", "data-engineers"]
        # Grandparent path includes the chain
        assert "all-data-team" in by_name["all-data-team"].path


# ---------------------------------------------------------------------------
# Tests — get_workspace_assignments
# ---------------------------------------------------------------------------

class TestWorkspaceAssignments:

    @responses.activate
    def test_finds_direct_and_group_roles(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")

        workspaces = [WorkspaceInfo(
            workspace_id="ws-001",
            deployment_name="test",
            workspace_name="test-ws",
            workspace_url=WORKSPACE_HOST,
            cloud="AZURE",
            region="eastus",
        )]

        roles = auditor.get_workspace_assignments(
            workspaces=workspaces,
            principal_id="user-1",
            group_ids={"group-1"},
            id_to_name={"group-1": "data-engineers"},
        )

        assert len(roles) >= 2
        direct_roles = [r for r in roles if r.via_group == "(direct)"]
        group_roles = [r for r in roles if r.via_group == "data-engineers"]
        assert len(direct_roles) == 1
        assert len(group_roles) == 1

    @responses.activate
    def test_no_match_returns_empty(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")

        workspaces = [WorkspaceInfo(
            workspace_id="ws-001",
            deployment_name="test",
            workspace_name="test-ws",
            workspace_url=WORKSPACE_HOST,
            cloud="AZURE",
            region="eastus",
        )]

        roles = auditor.get_workspace_assignments(
            workspaces=workspaces,
            principal_id="user-999",
            group_ids={"group-999"},
            id_to_name={},
        )

        assert roles == []

    @responses.activate
    def test_parallel_two_workspaces_roles_merged(self, mock_client):
        """Roles from two workspaces queried in parallel are all returned."""
        WS2_HOST = "https://test-workspace-2.azuredatabricks.net"
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)
        responses.add(responses.POST, f"{WS2_HOST}/oidc/v1/token",
                      json={"access_token": "ws2-token", "expires_in": 3600})
        responses.add(responses.GET, f"{BASE}/workspaces/ws-002/permissionassignments",
                      json={"permission_assignments": [
                          {"principal": {"principal_id": "group-1"}, "permissions": ["ADMIN"]},
                      ]})

        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")
        workspaces = [
            WorkspaceInfo("ws-001", "test", "test-ws", WORKSPACE_HOST, "AZURE", "eastus"),
            WorkspaceInfo("ws-002", "test2", "test-ws-2", WS2_HOST, "AZURE", "eastus"),
        ]

        roles = auditor.get_workspace_assignments(
            workspaces=workspaces,
            principal_id="user-1",
            group_ids={"group-1"},
            id_to_name={"group-1": "data-engineers"},
            max_workers=2,
        )

        ws_names = {r.workspace_name for r in roles}
        assert "test-ws" in ws_names
        assert "test-ws-2" in ws_names

    @responses.activate
    def test_empty_workspaces_returns_empty(self, mock_client):
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")
        roles = auditor.get_workspace_assignments(
            workspaces=[], principal_id="user-1",
            group_ids=set(), id_to_name={},
        )
        assert roles == []


# ---------------------------------------------------------------------------
# Tests — scan_permissions
# ---------------------------------------------------------------------------

class TestScanPermissions:

    @responses.activate
    def test_finds_user_and_group_grants(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")

        from databricks_group_audit.models import WorkspaceRole
        ws_roles = [WorkspaceRole(
            workspace_id="ws-001",
            workspace_name="test-ws",
            workspace_url=WORKSPACE_HOST,
            permission_level="USER",
            via_group="(direct)",
            via_group_id="user-1",
        )]

        perms = auditor.scan_permissions(
            workspace_roles=ws_roles,
            principal_name="alice@example.com",
            group_names={"data-engineers", "all-data-team"},
        )

        # Should find grants for alice@example.com, data-engineers, all-data-team
        principals = {p.via_group for p in perms}
        assert "alice@example.com" in principals
        assert "data-engineers" in principals
        assert "all-data-team" in principals

    @responses.activate
    def test_deduplicates_workspaces(self, mock_client):
        """Same workspace via two groups should only be scanned once."""
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)
        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")

        from databricks_group_audit.models import WorkspaceRole
        ws_roles = [
            WorkspaceRole("ws-001", "test-ws", WORKSPACE_HOST, "USER", "(direct)", "user-1"),
            WorkspaceRole("ws-001", "test-ws", WORKSPACE_HOST, "USER", "data-engineers", "group-1"),
        ]

        perms = auditor.scan_permissions(
            workspace_roles=ws_roles,
            principal_name="alice@example.com",
            group_names={"data-engineers"},
        )

        # Should not fail or produce duplicates from scanning twice
        catalog_names = [p.securable_name for p in perms]
        assert len(catalog_names) == len(set(
            (p.securable_name, p.via_group) for p in perms
        ))

    @responses.activate
    def test_parallel_two_workspaces_perms_merged(self, mock_client):
        """Permissions from two distinct workspace URLs are both collected."""
        WS2_HOST = "https://test-workspace-2.azuredatabricks.net"
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)
        responses.add(responses.POST, f"{WS2_HOST}/oidc/v1/token",
                      json={"access_token": "ws2-token", "expires_in": 3600})
        responses.add(responses.GET, f"{WS2_HOST}/api/2.1/unity-catalog/catalogs",
                      json={"catalogs": [{"name": "ops"}]})
        responses.add(responses.GET,
                      f"{WS2_HOST}/api/2.1/unity-catalog/permissions/catalog/ops",
                      json={"privilege_assignments": [
                          {"principal": "alice@example.com", "privileges": ["USE_CATALOG"]},
                      ]})

        auditor = PrincipalAuditor(mock_client, cloud_provider="azure")

        from databricks_group_audit.models import WorkspaceRole
        ws_roles = [
            WorkspaceRole("ws-001", "test-ws", WORKSPACE_HOST, "USER", "(direct)", "user-1"),
            WorkspaceRole("ws-002", "test-ws-2", WS2_HOST, "USER", "(direct)", "user-1"),
        ]

        perms = auditor.scan_permissions(
            workspace_roles=ws_roles,
            principal_name="alice@example.com",
            group_names=set(),
            max_workers=2,
        )

        ws_names = {p.workspace_name for p in perms}
        assert "test-ws" in ws_names
        assert "test-ws-2" in ws_names


# ---------------------------------------------------------------------------
# Tests — full audit orchestration
# ---------------------------------------------------------------------------

class TestAuditOrchestrator:

    @responses.activate
    def test_full_audit_user(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)

        # Also need workspace discovery — mock the /workspaces endpoint
        responses.add(responses.GET, f"{BASE}/workspaces",
                      json=[{
                          "workspace_id": "ws-001",
                          "deployment_name": "test-workspace",
                          "workspace_name": "test-ws",
                          "workspace_status": "RUNNING",
                          "deployment_url": "test-workspace.azuredatabricks.net",
                      }])

        from databricks_group_audit.workspace import WorkspaceDiscovery
        ws_disc = WorkspaceDiscovery(mock_client, cloud_provider="azure")
        auditor = PrincipalAuditor(mock_client, workspace_discovery=ws_disc, cloud_provider="azure")

        result = auditor.audit("alice@example.com")

        assert result.principal_type == "USER"
        assert result.principal_name == "Alice Smith"
        assert len(result.groups) >= 1
        assert any(g.group_name == "data-engineers" for g in result.groups)

    @responses.activate
    def test_full_audit_max_workers_one(self, mock_client):
        """max_workers=1 forces serial execution; result must be correct."""
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)
        responses.add(responses.GET, f"{BASE}/workspaces",
                      json=[{
                          "workspace_id": "ws-001",
                          "deployment_name": "test-workspace",
                          "workspace_name": "test-ws",
                          "workspace_status": "RUNNING",
                          "deployment_url": "test-workspace.azuredatabricks.net",
                      }])

        from databricks_group_audit.workspace import WorkspaceDiscovery
        ws_disc = WorkspaceDiscovery(mock_client, cloud_provider="azure")
        auditor = PrincipalAuditor(mock_client, workspace_discovery=ws_disc, cloud_provider="azure")

        result = auditor.audit("alice@example.com", max_workers=1)

        assert result.principal_type == "USER"
        assert any(g.group_name == "data-engineers" for g in result.groups)
        assert len(result.permissions) >= 1

    @responses.activate
    def test_nonexistent_principal_raises(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)

        from databricks_group_audit.workspace import WorkspaceDiscovery
        ws_disc = WorkspaceDiscovery(mock_client, cloud_provider="azure")
        auditor = PrincipalAuditor(mock_client, workspace_discovery=ws_disc, cloud_provider="azure")

        with pytest.raises(ValueError, match="not found"):
            auditor.audit("nonexistent@nowhere.com")

    @responses.activate
    def test_dead_end_groups_detected(self, mock_client):
        """Groups with no workspace permission assignment are dead ends."""
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)

        # Workspace assignments only match user-1 directly, NOT group-1
        # Override the permission assignments to exclude group-1
        responses.replace(
            responses.GET,
            f"{BASE}/workspaces/ws-001/permissionassignments",
            json={"permission_assignments": [
                {"principal": {"principal_id": "user-1"}, "permissions": ["USER"]},
            ]},
        )
        responses.add(responses.GET, f"{BASE}/workspaces",
                      json=[{
                          "workspace_id": "ws-001",
                          "deployment_name": "test-workspace",
                          "workspace_name": "test-ws",
                          "workspace_status": "RUNNING",
                          "deployment_url": "test-workspace.azuredatabricks.net",
                      }])

        from databricks_group_audit.workspace import WorkspaceDiscovery
        ws_disc = WorkspaceDiscovery(mock_client, cloud_provider="azure")
        auditor = PrincipalAuditor(mock_client, workspace_discovery=ws_disc, cloud_provider="azure")

        result = auditor.audit("alice@example.com")

        # When only the principal directly has workspace access (no group assignments),
        # every group membership is a dead end because no group in any path has workspace
        # access — including data-engineers, all-data-team, and org-all.
        assert len(result.dead_end_groups) >= 1
        assert "data-engineers" in result.dead_end_groups
        assert "all-data-team" in result.dead_end_groups
        assert "org-all" in result.dead_end_groups

    @responses.activate
    def test_dead_ends_excludes_transitive_ancestors_of_workspace_groups(self, mock_client):
        """Groups that are ancestors of a workspace-assigned group are NOT dead ends.

        Hierarchy: org-all → all-data-team → data-engineers (workspace-assigned)
        Alice is in data-engineers.  all-data-team and org-all are transitive
        ancestors of data-engineers — they are not dead ends because the principal
        reaches workspace access through data-engineers, which is a descendant of both.
        """
        _add_scim_endpoints(responses)
        _add_workspace_endpoints(responses)  # group-1 (data-engineers) has USER access

        responses.add(responses.GET, f"{BASE}/workspaces",
                      json=[{
                          "workspace_id": "ws-001",
                          "deployment_name": "test-workspace",
                          "workspace_name": "test-ws",
                          "workspace_status": "RUNNING",
                          "deployment_url": "test-workspace.azuredatabricks.net",
                      }])

        from databricks_group_audit.workspace import WorkspaceDiscovery
        ws_disc = WorkspaceDiscovery(mock_client, cloud_provider="azure")
        auditor = PrincipalAuditor(mock_client, workspace_discovery=ws_disc, cloud_provider="azure")

        result = auditor.audit("alice@example.com")

        # data-engineers is directly workspace-assigned → not a dead end
        assert "data-engineers" not in result.dead_end_groups
        # all-data-team and org-all are ancestors of data-engineers → not dead ends
        assert "all-data-team" not in result.dead_end_groups
        assert "org-all" not in result.dead_end_groups
