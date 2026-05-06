"""Tests for AccessCloner (provisioning report + apply)."""

from __future__ import annotations

import json

import responses

from databricks_access_audit.access_cloner import AccessCloner
from databricks_access_audit.models import CloneActionType
from tests.conftest import (
    ACCOUNT_HOST,
    ACCOUNT_ID,
    SCIM_USER_ALICE,
    SCIM_USER_BOB,
    WORKSPACE_HOST,
)

BASE = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"

# ---------------------------------------------------------------------------
# Group fixtures for cloner tests
# ---------------------------------------------------------------------------

# Source principal: Alice (user-1)
# Target principal: Bob (user-2)

# Alice belongs directly to two groups:
#   - internal-group: Databricks-managed (no externalId)
#   - idp-group: IdP-synced (has externalId)
# Bob belongs to no groups initially.

SCIM_GROUP_INTERNAL = {
    "id": "group-internal",
    "displayName": "internal-group",
    "externalId": None,
    "members": [
        {"value": "user-1", "display": "Alice", "$ref": "Users/user-1"},
    ],
}

SCIM_GROUP_IDP = {
    "id": "group-idp",
    "displayName": "idp-group",
    "externalId": "ext-idp-123",
    "members": [
        {"value": "user-1", "display": "Alice", "$ref": "Users/user-1"},
    ],
}

# A group with no workspace assignment (used for UNVERIFIED / SKIPPED / UC-only tests)
SCIM_GROUP_NO_WS = {
    "id": "group-no-ws",
    "displayName": "no-ws-group",
    "externalId": None,
    "members": [
        {"value": "user-1", "display": "Alice", "$ref": "Users/user-1"},
    ],
}

ALL_TEST_GROUPS = [SCIM_GROUP_INTERNAL, SCIM_GROUP_IDP, SCIM_GROUP_NO_WS]
ALL_TEST_USERS = [SCIM_USER_ALICE, SCIM_USER_BOB]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_scim_endpoints(rsps, all_groups=None, all_users=None):
    """Register minimal SCIM endpoints for cloner tests."""
    if all_groups is None:
        all_groups = ALL_TEST_GROUPS
    if all_users is None:
        all_users = ALL_TEST_USERS

    rsps.add(responses.POST, f"{ACCOUNT_HOST}/oidc/accounts/{ACCOUNT_ID}/v1/token",
             json={"access_token": "mock-token", "expires_in": 3600})

    def _group_list_cb(request):
        filt = request.params.get("filter", "")
        if "displayName" in filt:
            name = filt.split('"')[1]
            matched = [g for g in all_groups if g["displayName"] == name]
        else:
            matched = all_groups
        body = {"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100}
        return (200, {}, json.dumps(body))

    rsps.add_callback(responses.GET, f"{BASE}/scim/v2/Groups",
                      callback=_group_list_cb, content_type="application/json")

    for g in all_groups:
        rsps.add(responses.GET, f"{BASE}/scim/v2/Groups/{g['id']}", json=g)

    def _user_list_cb(request):
        filt = request.params.get("filter", "")
        if "emails.value" in filt:
            email = filt.split('"')[1]
            matched = [u for u in all_users
                       if any(e.get("value") == email for e in u.get("emails", []))]
        else:
            matched = all_users
        body = {"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100}
        return (200, {}, json.dumps(body))

    rsps.add_callback(responses.GET, f"{BASE}/scim/v2/Users",
                      callback=_user_list_cb, content_type="application/json")

    for u in all_users:
        rsps.add(responses.GET, f"{BASE}/scim/v2/Users/{u['id']}", json=u)

    # SPs — empty for these tests
    rsps.add(responses.GET, f"{BASE}/scim/v2/ServicePrincipals",
             json={"Resources": [], "totalResults": 0, "itemsPerPage": 100})


def _add_workspace_discovery(rsps, workspace_id="ws-001", workspace_name="test-ws"):
    """Register workspace discovery endpoint."""
    rsps.add(responses.GET, f"{BASE}/workspaces", json=[{
        "workspace_id": workspace_id,
        "deployment_name": "test-workspace",
        "workspace_name": workspace_name,
        "workspace_url": WORKSPACE_HOST,
        "workspace_status": "RUNNING",
        "cloud": "AZURE",
        "azure_workspace_info": {"region": "eastus"},
    }])


WS_ID = "ws-001"


def _add_permission_assignments(rsps, group_ids_with_access, workspace_id=WS_ID):
    """Register /permissionassignments returning access for the given group IDs."""
    assignments = [
        {"principal": {"principal_id": gid}, "permissions": ["USER"]}
        for gid in group_ids_with_access
    ]
    rsps.add(responses.GET, f"{BASE}/workspaces/{workspace_id}/permissionassignments",
             json={"permission_assignments": assignments})


# ---------------------------------------------------------------------------
# Tests — IDP_REQUIRED
# ---------------------------------------------------------------------------

class TestCloneIdpRequired:

    @responses.activate
    def test_idp_group_classified_as_idp_required(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_discovery(responses)
        # idp-group has workspace access
        _add_permission_assignments(responses, ["group-idp"])

        cloner = AccessCloner(mock_client, cloud_provider="azure")
        report = cloner.build_report(
            source="alice@example.com",
            target="bob@example.com",
            explicit_workspace_urls="",
        )

        idp = [a for a in report.actions if a.group_id == "group-idp"]
        assert len(idp) == 1
        assert idp[0].action_type == CloneActionType.IDP_REQUIRED
        assert idp[0].external_id == "ext-idp-123"


# ---------------------------------------------------------------------------
# Tests — DATABRICKS (workspace assignment)
# ---------------------------------------------------------------------------

class TestCloneDatabricksWithWorkspace:

    @responses.activate
    def test_internal_group_with_ws_assignment_classified_databricks(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_discovery(responses)
        # internal-group has workspace access
        _add_permission_assignments(responses, ["group-internal"])

        cloner = AccessCloner(mock_client, cloud_provider="azure")
        report = cloner.build_report(
            source="alice@example.com",
            target="bob@example.com",
            explicit_workspace_urls="",
        )

        db = [a for a in report.actions if a.group_id == "group-internal"]
        assert len(db) == 1
        assert db[0].action_type == CloneActionType.DATABRICKS
        assert "test-ws" in db[0].workspace_accesses

    @responses.activate
    def test_databricks_action_has_no_external_id(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_discovery(responses)
        _add_permission_assignments(responses, ["group-internal"])

        cloner = AccessCloner(mock_client, cloud_provider="azure")
        report = cloner.build_report(
            source="alice@example.com",
            target="bob@example.com",
            explicit_workspace_urls="",
        )

        db = [a for a in report.databricks_actions if a.group_id == "group-internal"]
        assert len(db) == 1
        assert not db[0].external_id


# ---------------------------------------------------------------------------
# Tests — UNVERIFIED (no ws assignment, no scan_uc)
# ---------------------------------------------------------------------------

class TestCloneUnverified:

    @responses.activate
    def test_no_ws_assignment_without_scan_uc_is_unverified(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_discovery(responses)
        # no-ws-group has NO workspace access
        _add_permission_assignments(responses, [])

        cloner = AccessCloner(mock_client, cloud_provider="azure")
        report = cloner.build_report(
            source="alice@example.com",
            target="bob@example.com",
            scan_uc=False,
            explicit_workspace_urls="",
        )

        unverified = [a for a in report.actions if a.group_id == "group-no-ws"]
        assert len(unverified) == 1
        assert unverified[0].action_type == CloneActionType.UNVERIFIED


# ---------------------------------------------------------------------------
# Tests — DATABRICKS via UC (scan_uc=True + UC grant found)
# ---------------------------------------------------------------------------

class TestCloneDatabricksViaUC:

    @responses.activate
    def test_no_ws_with_scan_uc_and_uc_grant_is_databricks(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_discovery(responses)
        # group-no-ws has no workspace assignment
        _add_permission_assignments(responses, [])

        # Workspace token
        responses.add(responses.POST, f"{WORKSPACE_HOST}/oidc/v1/token",
                      json={"access_token": "ws-token", "expires_in": 3600})

        # UC catalog with a grant for no-ws-group
        responses.add(responses.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/catalogs",
                      json={"catalogs": [{"name": "main"}]})
        responses.add(responses.GET,
                      f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/catalog/main",
                      json={"privilege_assignments": [
                          {"principal": "no-ws-group", "privileges": ["USE_CATALOG"]},
                      ]})

        cloner = AccessCloner(mock_client, cloud_provider="azure")
        report = cloner.build_report(
            source="alice@example.com",
            target="bob@example.com",
            scan_uc=True,
            explicit_workspace_urls="",
        )

        no_ws_actions = [a for a in report.actions if a.group_id == "group-no-ws"]
        assert len(no_ws_actions) == 1
        assert no_ws_actions[0].action_type == CloneActionType.DATABRICKS
        assert "UC grants detected" in no_ws_actions[0].uc_grants_summary


# ---------------------------------------------------------------------------
# Tests — SKIPPED (scan_uc=True + no UC grant)
# ---------------------------------------------------------------------------

class TestCloneSkipped:

    @responses.activate
    def test_no_ws_with_scan_uc_and_no_uc_grant_is_skipped(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_discovery(responses)
        # group-no-ws has no workspace assignment
        _add_permission_assignments(responses, [])

        # Workspace token
        responses.add(responses.POST, f"{WORKSPACE_HOST}/oidc/v1/token",
                      json={"access_token": "ws-token", "expires_in": 3600})

        # UC catalog with NO grant for no-ws-group
        responses.add(responses.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/catalogs",
                      json={"catalogs": [{"name": "main"}]})
        responses.add(responses.GET,
                      f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/catalog/main",
                      json={"privilege_assignments": [
                          {"principal": "other-group", "privileges": ["USE_CATALOG"]},
                      ]})

        cloner = AccessCloner(mock_client, cloud_provider="azure")
        report = cloner.build_report(
            source="alice@example.com",
            target="bob@example.com",
            scan_uc=True,
            explicit_workspace_urls="",
        )

        no_ws_actions = [a for a in report.actions if a.group_id == "group-no-ws"]
        assert len(no_ws_actions) == 1
        assert no_ws_actions[0].action_type == CloneActionType.SKIPPED


# ---------------------------------------------------------------------------
# Tests — apply=True (SCIM PATCH)
# ---------------------------------------------------------------------------

class TestCloneApply:

    @responses.activate
    def test_apply_patches_databricks_groups(self, mock_client):
        """apply() should PATCH the DATABRICKS actions and mark applied=True."""
        _add_scim_endpoints(responses)
        _add_workspace_discovery(responses)
        _add_permission_assignments(responses, ["group-internal"])

        # Register SCIM PATCH endpoint
        responses.add(responses.PATCH, f"{BASE}/scim/v2/Groups/group-internal",
                      json={}, status=200)

        cloner = AccessCloner(mock_client, cloud_provider="azure")
        report = cloner.build_report(
            source="alice@example.com",
            target="bob@example.com",
            explicit_workspace_urls="",
        )

        db_actions = [a for a in report.databricks_actions if a.group_id == "group-internal"]
        assert len(db_actions) == 1
        assert db_actions[0].applied is False

        cloner.apply(report, target_id="user-2")

        assert db_actions[0].applied is True
        assert db_actions[0].error is None

    @responses.activate
    def test_apply_failure_sets_error(self, mock_client):
        """When PATCH fails, action.error is set and applied stays False."""
        _add_scim_endpoints(responses)
        _add_workspace_discovery(responses)
        _add_permission_assignments(responses, ["group-internal"])

        # Register SCIM PATCH endpoint that returns 403
        responses.add(responses.PATCH, f"{BASE}/scim/v2/Groups/group-internal",
                      json={"error": "Forbidden"}, status=403)

        cloner = AccessCloner(mock_client, cloud_provider="azure")
        report = cloner.build_report(
            source="alice@example.com",
            target="bob@example.com",
            explicit_workspace_urls="",
        )

        db_actions = [a for a in report.databricks_actions if a.group_id == "group-internal"]
        assert len(db_actions) == 1

        cloner.apply(report, target_id="user-2")

        assert db_actions[0].applied is False
        assert db_actions[0].error is not None

    @responses.activate
    def test_apply_skips_idp_actions(self, mock_client):
        """IDP_REQUIRED actions must not be patched."""
        _add_scim_endpoints(responses)
        _add_workspace_discovery(responses)
        # idp-group has workspace access
        _add_permission_assignments(responses, ["group-idp"])

        cloner = AccessCloner(mock_client, cloud_provider="azure")
        report = cloner.build_report(
            source="alice@example.com",
            target="bob@example.com",
            explicit_workspace_urls="",
        )

        # apply — no PATCH endpoints registered so any PATCH would raise
        cloner.apply(report, target_id="user-2")

        idp_actions = report.idp_actions
        assert all(not a.applied for a in idp_actions)


# ---------------------------------------------------------------------------
# Tests — report properties
# ---------------------------------------------------------------------------

class TestCloneReportProperties:

    @responses.activate
    def test_report_display_names(self, mock_client):
        _add_scim_endpoints(responses)
        _add_workspace_discovery(responses)
        _add_permission_assignments(responses, [])

        cloner = AccessCloner(mock_client, cloud_provider="azure")
        report = cloner.build_report(
            source="alice@example.com",
            target="bob@example.com",
            explicit_workspace_urls="",
        )

        assert report.source_display_name == "Alice Smith"
        assert report.target_display_name == "Bob Jones"
        assert report.source_principal == "alice@example.com"
        assert report.target_principal == "bob@example.com"
