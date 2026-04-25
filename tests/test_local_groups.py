"""Tests for LocalGroupChecker (workspace-local SCIM group detection)."""

from __future__ import annotations

import pytest
import responses as responses_lib

from databricks_group_audit.local_groups import LocalGroupChecker
from databricks_group_audit.models import WorkspaceInfo
from tests.conftest import (
    ACCOUNT_HOST,
    ACCOUNT_ID,
    ALL_GROUPS,
    WORKSPACE_HOST,
)

WS_SCIM_ENDPOINT = f"{WORKSPACE_HOST}/api/2.0/preview/scim/v2/Groups"
BASE = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"

# Account group names from conftest (lowercased for comparison)
ACCOUNT_NAMES = {g["displayName"].lower() for g in ALL_GROUPS}


def _ws(name="prod", url=WORKSPACE_HOST):
    return WorkspaceInfo(
        workspace_id="ws-1", deployment_name="prod",
        workspace_name=name, workspace_url=url,
        cloud="AZURE", region="eastus",
    )


def _account_scim_mock(rsps):
    rsps.add(responses_lib.POST, f"{ACCOUNT_HOST}/oidc/v1/token",
             json={"access_token": "tok", "expires_in": 3600})
    rsps.add(responses_lib.GET, f"{BASE}/scim/v2/Groups",
             json={"Resources": ALL_GROUPS, "totalResults": len(ALL_GROUPS),
                   "itemsPerPage": 100})


def _ws_groups_mock(rsps, groups, workspace_url=WORKSPACE_HOST):
    rsps.add(responses_lib.POST, f"{workspace_url}/oidc/v1/token",
             json={"access_token": "ws-tok", "expires_in": 3600})
    rsps.add(responses_lib.GET, f"{workspace_url}/api/2.0/preview/scim/v2/Groups",
             json={"Resources": groups, "totalResults": len(groups),
                   "itemsPerPage": 100})


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_client():
    from databricks_group_audit.client import DatabricksAPIClient
    return DatabricksAPIClient(
        client_id="test-id", client_secret="test-secret",
        account_id=ACCOUNT_ID, account_host=ACCOUNT_HOST,
    )


# ---------------------------------------------------------------------------
# get_account_group_names
# ---------------------------------------------------------------------------


def test_get_account_group_names(mock_client):
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _account_scim_mock(rsps)
        checker = LocalGroupChecker(mock_client)
        names = checker.get_account_group_names()

    assert "data-engineers" in names
    assert "data-analysts" in names
    assert "all-data-team" in names


# ---------------------------------------------------------------------------
# No workspace-local groups
# ---------------------------------------------------------------------------


def test_no_local_groups_when_all_in_account(mock_client):
    """All workspace groups also appear at account level → no findings."""
    ws_groups = [
        {"id": "wg-1", "displayName": "data-engineers", "members": []},
        {"id": "wg-2", "displayName": "data-analysts", "members": []},
    ]
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _account_scim_mock(rsps)
        _ws_groups_mock(rsps, ws_groups)

        checker = LocalGroupChecker(mock_client)
        findings = checker.check_workspace(_ws())

    assert findings == []


# ---------------------------------------------------------------------------
# Local group detected
# ---------------------------------------------------------------------------


def test_local_group_detected(mock_client):
    ws_groups = [
        {"id": "wg-1", "displayName": "data-engineers", "members": []},
        {
            "id": "wg-99", "displayName": "legacy-workspace-only",
            "members": [{"value": "u1"}, {"value": "u2"}],
        },
    ]
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _account_scim_mock(rsps)
        _ws_groups_mock(rsps, ws_groups)

        checker = LocalGroupChecker(mock_client)
        findings = checker.check_workspace(_ws())

    assert len(findings) == 1
    assert findings[0].group_name == "legacy-workspace-only"
    assert findings[0].group_id == "wg-99"
    assert findings[0].member_count == 2
    assert findings[0].workspace_name == "prod"


# ---------------------------------------------------------------------------
# check_workspace uses pre-fetched account names
# ---------------------------------------------------------------------------


def test_check_workspace_uses_prefetched_names(mock_client):
    """Passing account_group_names skips the extra account SCIM call."""
    ws_groups = [
        {"id": "wg-99", "displayName": "local-only", "members": []},
    ]
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _ws_groups_mock(rsps, ws_groups)
        # No account SCIM endpoint registered — if it's called the test fails
        # with a ConnectionError.
        rsps.add(responses_lib.POST, f"{WORKSPACE_HOST}/oidc/v1/token",
                 json={"access_token": "tok", "expires_in": 3600})

        checker = LocalGroupChecker(mock_client)
        findings = checker.check_workspace(
            _ws(),
            account_group_names={"data-engineers"},  # pre-fetched
        )

    assert len(findings) == 1
    assert findings[0].group_name == "local-only"


# ---------------------------------------------------------------------------
# Case-insensitive comparison
# ---------------------------------------------------------------------------


def test_comparison_is_case_insensitive(mock_client):
    ws_groups = [{"id": "wg-1", "displayName": "Data-Engineers", "members": []}]
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _account_scim_mock(rsps)
        _ws_groups_mock(rsps, ws_groups)

        checker = LocalGroupChecker(mock_client)
        findings = checker.check_workspace(_ws())

    # "Data-Engineers" == "data-engineers" (case-insensitive) → not local
    assert findings == []


# ---------------------------------------------------------------------------
# check_all_workspaces
# ---------------------------------------------------------------------------


def test_check_all_workspaces_aggregates(mock_client):
    ws1_url = "https://ws1.azuredatabricks.net"
    ws2_url = "https://ws2.azuredatabricks.net"

    ws1_groups = [{"id": "g1", "displayName": "local-ws1", "members": [{"value": "u1"}]}]
    ws2_groups = [
        {"id": "g2", "displayName": "data-engineers", "members": []},
        {"id": "g3", "displayName": "local-ws2", "members": []},
    ]

    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _account_scim_mock(rsps)
        _ws_groups_mock(rsps, ws1_groups, workspace_url=ws1_url)
        _ws_groups_mock(rsps, ws2_groups, workspace_url=ws2_url)
        rsps.add(responses_lib.POST, f"{ws1_url}/oidc/v1/token",
                 json={"access_token": "tok", "expires_in": 3600})
        rsps.add(responses_lib.POST, f"{ws2_url}/oidc/v1/token",
                 json={"access_token": "tok", "expires_in": 3600})

        workspaces = [
            _ws("workspace-1", ws1_url),
            _ws("workspace-2", ws2_url),
        ]
        checker = LocalGroupChecker(mock_client)
        findings = checker.check_all_workspaces(workspaces)

    assert len(findings) == 2
    names = {f.group_name for f in findings}
    assert names == {"local-ws1", "local-ws2"}


# ---------------------------------------------------------------------------
# Workspace API error is skipped gracefully
# ---------------------------------------------------------------------------


def test_workspace_api_error_skipped(mock_client):
    """If workspace SCIM is unreachable, that workspace produces no findings."""
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _account_scim_mock(rsps)
        rsps.add(responses_lib.POST, f"{WORKSPACE_HOST}/oidc/v1/token",
                 json={"access_token": "tok", "expires_in": 3600})
        rsps.add(responses_lib.GET, WS_SCIM_ENDPOINT,
                 body=Exception("connection refused"))

        checker = LocalGroupChecker(mock_client)
        findings = checker.check_workspace(_ws())

    assert findings == []


# ---------------------------------------------------------------------------
# Empty workspace SCIM
# ---------------------------------------------------------------------------


def test_empty_workspace_scim(mock_client):
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _account_scim_mock(rsps)
        _ws_groups_mock(rsps, [])

        checker = LocalGroupChecker(mock_client)
        findings = checker.check_workspace(_ws())

    assert findings == []


# ---------------------------------------------------------------------------
# Groups without displayName are skipped
# ---------------------------------------------------------------------------


def test_group_without_display_name_skipped(mock_client):
    ws_groups = [{"id": "g1", "members": []}]  # no displayName
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _account_scim_mock(rsps)
        _ws_groups_mock(rsps, ws_groups)

        checker = LocalGroupChecker(mock_client)
        findings = checker.check_workspace(_ws())

    assert findings == []


# ---------------------------------------------------------------------------
# Multi-page pagination
# ---------------------------------------------------------------------------


def test_pagination_fetches_all_pages(mock_client):
    """_get_workspace_groups must follow pagination until totalResults is reached."""
    page1 = [{"id": "g1", "displayName": "local-a", "members": []}]
    page2 = [{"id": "g2", "displayName": "local-b", "members": []}]

    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _account_scim_mock(rsps)
        rsps.add(responses_lib.POST, f"{WORKSPACE_HOST}/oidc/v1/token",
                 json={"access_token": "ws-tok", "expires_in": 3600})
        # First page: 1 of 2 results
        rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.0/preview/scim/v2/Groups",
                 json={"Resources": page1, "totalResults": 2, "itemsPerPage": 1})
        # Second page: 2nd result, totalResults still 2
        rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.0/preview/scim/v2/Groups",
                 json={"Resources": page2, "totalResults": 2, "itemsPerPage": 1})

        checker = LocalGroupChecker(mock_client)
        findings = checker.check_workspace(_ws())

    assert len(findings) == 2
    names = {f.group_name for f in findings}
    assert names == {"local-a", "local-b"}


# ---------------------------------------------------------------------------
# check_all_workspaces with empty workspace list
# ---------------------------------------------------------------------------


def test_check_all_workspaces_empty_list(mock_client):
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _account_scim_mock(rsps)
        checker = LocalGroupChecker(mock_client)
        findings = checker.check_all_workspaces([])
    assert findings == []
