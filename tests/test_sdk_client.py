"""Tests for DatabricksSDKClient adapter layer.

All SDK objects are patched with MagicMock so no real network calls are made.
Each test verifies that the adapter correctly translates between the raw
dict-based protocol used by scanners/resolvers and the typed SDK API.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from databricks_group_audit.sdk_client import DatabricksSDKClient, SDK_AVAILABLE

pytestmark = pytest.mark.skipif(not SDK_AVAILABLE, reason="databricks-sdk not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sdk_obj(**kwargs):
    """Minimal stand-in for an SDK dataclass that has as_dict()."""
    obj = MagicMock()
    obj.as_dict.return_value = kwargs
    return obj


def _make_client() -> tuple[DatabricksSDKClient, MagicMock, MagicMock]:
    """Return (client, mock_account, mock_ws_client)."""
    with patch("databricks_group_audit.sdk_client.AccountClient") as MockAC:
        mock_account = MagicMock()
        MockAC.return_value = mock_account
        client = DatabricksSDKClient(
            client_id="cid",
            client_secret="secret",
            account_id="acct-1",
            account_host="https://accounts.azuredatabricks.net",
        )

    mock_ws = MagicMock()
    client._workspace_clients["https://ws.azuredatabricks.net"] = mock_ws
    return client, mock_account, mock_ws


# ---------------------------------------------------------------------------
# account_api — SCIM Groups
# ---------------------------------------------------------------------------

def test_account_api_groups_list():
    client, acct, _ = _make_client()
    g = _sdk_obj(id="g1", displayName="engineers", members=[])
    acct.groups.list.return_value = [g]

    resp = client.account_api("GET", "/scim/v2/Groups")

    acct.groups.list.assert_called_once_with(filter=None)
    assert resp["Resources"][0]["id"] == "g1"
    assert resp["totalResults"] == 1


def test_account_api_groups_list_with_filter():
    client, acct, _ = _make_client()
    acct.groups.list.return_value = []
    client.account_api("GET", "/scim/v2/Groups", params={"filter": 'displayName eq "eng"'})
    acct.groups.list.assert_called_once_with(filter='displayName eq "eng"')


def test_account_api_group_by_id():
    client, acct, _ = _make_client()
    g = _sdk_obj(id="g42", displayName="admins")
    acct.groups.get.return_value = g

    resp = client.account_api("GET", "/scim/v2/Groups/g42")

    acct.groups.get.assert_called_once_with("g42")
    assert resp["id"] == "g42"


# ---------------------------------------------------------------------------
# account_api — SCIM Users
# ---------------------------------------------------------------------------

def test_account_api_users_list():
    client, acct, _ = _make_client()
    u = _sdk_obj(id="u1", displayName="Alice", emails=[{"value": "alice@example.com"}])
    acct.users.list.return_value = [u]

    resp = client.account_api("GET", "/scim/v2/Users")
    assert resp["Resources"][0]["id"] == "u1"


def test_account_api_user_by_id():
    client, acct, _ = _make_client()
    acct.users.get.return_value = _sdk_obj(id="u99")

    resp = client.account_api("GET", "/scim/v2/Users/u99")
    acct.users.get.assert_called_once_with("u99")
    assert resp["id"] == "u99"


# ---------------------------------------------------------------------------
# account_api — SCIM ServicePrincipals
# ---------------------------------------------------------------------------

def test_account_api_sps_list():
    client, acct, _ = _make_client()
    sp = _sdk_obj(id="sp1", displayName="ETL-Bot", applicationId="app-001")
    acct.service_principals.list.return_value = [sp]

    resp = client.account_api("GET", "/scim/v2/ServicePrincipals")
    assert resp["Resources"][0]["displayName"] == "ETL-Bot"


def test_account_api_sp_by_id():
    client, acct, _ = _make_client()
    acct.service_principals.get.return_value = _sdk_obj(id="sp7")

    resp = client.account_api("GET", "/scim/v2/ServicePrincipals/sp7")
    acct.service_principals.get.assert_called_once_with("sp7")


# ---------------------------------------------------------------------------
# account_api — Workspaces
# ---------------------------------------------------------------------------

def test_account_api_workspaces_list():
    client, acct, _ = _make_client()
    acct.workspaces.list.return_value = [
        _sdk_obj(workspace_id=111, workspace_name="ws-a", workspace_status="RUNNING"),
    ]

    resp = client.account_api("GET", "/workspaces")
    assert isinstance(resp, list)
    assert resp[0]["workspace_id"] == 111


# ---------------------------------------------------------------------------
# account_api — Permission Assignments
# ---------------------------------------------------------------------------

def test_account_api_permission_assignments():
    client, acct, _ = _make_client()
    pa = _sdk_obj(principal={"display_name": "eng"}, permissions=["CAN_USE"])
    acct.workspace_assignment.list.return_value = [pa]

    resp = client.account_api("GET", "/workspaces/12345/permissionassignments")
    acct.workspace_assignment.list.assert_called_once_with(12345)
    assert len(resp["permission_assignments"]) == 1


# ---------------------------------------------------------------------------
# account_api — unknown endpoint falls back to raw HTTP
# ---------------------------------------------------------------------------

def test_account_api_unknown_endpoint_falls_back():
    client, acct, _ = _make_client()
    acct.api_client.do.return_value = {"result": "ok"}

    resp = client.account_api("GET", "/some/custom/endpoint")
    acct.api_client.do.assert_called_once()
    assert resp == {"result": "ok"}


def test_account_api_fallback_non_dict_returns_empty():
    client, acct, _ = _make_client()
    acct.api_client.do.return_value = "unexpected string"

    resp = client.account_api("GET", "/weird")
    assert resp == {}


# ---------------------------------------------------------------------------
# workspace_api — Unity Catalog catalogs
# ---------------------------------------------------------------------------

def test_workspace_api_catalogs():
    client, _, ws = _make_client()
    ws.catalogs.list.return_value = [
        _sdk_obj(name="main"), _sdk_obj(name="staging"),
    ]

    resp = client.workspace_api(
        "https://ws.azuredatabricks.net", "GET",
        "/api/2.1/unity-catalog/catalogs",
    )
    cats = [c["name"] for c in resp["catalogs"]]
    assert cats == ["main", "staging"]


# ---------------------------------------------------------------------------
# workspace_api — catalog grants
# ---------------------------------------------------------------------------

def test_workspace_api_catalog_grants():
    client, _, ws = _make_client()
    pa = _sdk_obj(principal="data-engineers", privileges=["USE_CATALOG"])
    grants_obj = MagicMock()
    grants_obj.privilege_assignments = [pa]
    ws.grants.get.return_value = grants_obj

    resp = client.workspace_api(
        "https://ws.azuredatabricks.net", "GET",
        "/api/2.1/unity-catalog/permissions/catalog/main",
    )
    assert len(resp["privilege_assignments"]) == 1
    assert resp["privilege_assignments"][0]["principal"] == "data-engineers"


def test_workspace_api_catalog_grants_null_assignments():
    """grants.privilege_assignments = None should return empty list."""
    client, _, ws = _make_client()
    grants_obj = MagicMock()
    grants_obj.privilege_assignments = None
    ws.grants.get.return_value = grants_obj

    resp = client.workspace_api(
        "https://ws.azuredatabricks.net", "GET",
        "/api/2.1/unity-catalog/permissions/catalog/main",
    )
    assert resp["privilege_assignments"] == []


# ---------------------------------------------------------------------------
# workspace_api — schemas
# ---------------------------------------------------------------------------

def test_workspace_api_schemas():
    client, _, ws = _make_client()
    ws.schemas.list.return_value = [_sdk_obj(name="bronze")]

    resp = client.workspace_api(
        "https://ws.azuredatabricks.net", "GET",
        "/api/2.1/unity-catalog/schemas",
        params={"catalog_name": "main"},
    )
    ws.schemas.list.assert_called_once_with(catalog_name="main")
    assert resp["schemas"][0]["name"] == "bronze"


# ---------------------------------------------------------------------------
# workspace_api — schema grants
# ---------------------------------------------------------------------------

def test_workspace_api_schema_grants():
    client, _, ws = _make_client()
    pa = _sdk_obj(principal="data-engineers", privileges=["USE_SCHEMA"])
    grants_obj = MagicMock()
    grants_obj.privilege_assignments = [pa]
    ws.grants.get.return_value = grants_obj

    resp = client.workspace_api(
        "https://ws.azuredatabricks.net", "GET",
        "/api/2.1/unity-catalog/permissions/schema/main.bronze",
    )
    assert resp["privilege_assignments"][0]["privileges"] == ["USE_SCHEMA"]


# ---------------------------------------------------------------------------
# workspace_api — tables
# ---------------------------------------------------------------------------

def test_workspace_api_tables():
    client, _, ws = _make_client()
    ws.tables.list.return_value = [_sdk_obj(name="events", table_type="MANAGED")]

    resp = client.workspace_api(
        "https://ws.azuredatabricks.net", "GET",
        "/api/2.1/unity-catalog/tables",
        params={"catalog_name": "main", "schema_name": "bronze"},
    )
    ws.tables.list.assert_called_once_with(catalog_name="main", schema_name="bronze")
    assert resp["tables"][0]["name"] == "events"


# ---------------------------------------------------------------------------
# workspace_api — table grants
# ---------------------------------------------------------------------------

def test_workspace_api_table_grants():
    client, _, ws = _make_client()
    pa = _sdk_obj(principal="alice@example.com", privileges=["SELECT"])
    grants_obj = MagicMock()
    grants_obj.privilege_assignments = [pa]
    ws.grants.get.return_value = grants_obj

    resp = client.workspace_api(
        "https://ws.azuredatabricks.net", "GET",
        "/api/2.1/unity-catalog/permissions/table/main.bronze.events",
    )
    assert resp["privilege_assignments"][0]["principal"] == "alice@example.com"


# ---------------------------------------------------------------------------
# workspace_api — unknown endpoint falls back to raw HTTP
# ---------------------------------------------------------------------------

def test_workspace_api_unknown_endpoint_falls_back():
    client, _, ws = _make_client()
    ws.api_client.do.return_value = {"custom": "data"}

    resp = client.workspace_api(
        "https://ws.azuredatabricks.net", "GET", "/api/2.0/clusters/list",
    )
    ws.api_client.do.assert_called_once()
    assert resp == {"custom": "data"}


# ---------------------------------------------------------------------------
# scim_list_all
# ---------------------------------------------------------------------------

def test_scim_list_all_groups():
    client, acct, _ = _make_client()
    g = _sdk_obj(id="g1", displayName="eng")
    acct.groups.list.return_value = [g]

    result = client.scim_list_all("Groups")
    assert len(result) == 1
    assert result[0]["id"] == "g1"


def test_scim_list_all_users():
    client, acct, _ = _make_client()
    acct.users.list.return_value = [_sdk_obj(id="u1")]
    result = client.scim_list_all("Users")
    assert result[0]["id"] == "u1"


def test_scim_list_all_service_principals():
    client, acct, _ = _make_client()
    acct.service_principals.list.return_value = [_sdk_obj(id="sp1")]
    result = client.scim_list_all("ServicePrincipals")
    assert result[0]["id"] == "sp1"


def test_scim_list_all_unknown_resource_uses_account_api():
    client, acct, _ = _make_client()
    acct.api_client.do.return_value = {"Resources": [{"id": "x1"}]}

    result = client.scim_list_all("CustomResource")
    assert result[0]["id"] == "x1"


def test_scim_list_all_with_filter():
    client, acct, _ = _make_client()
    acct.groups.list.return_value = []
    client.scim_list_all("Groups", params={"filter": 'displayName eq "eng"'})
    acct.groups.list.assert_called_once_with(filter='displayName eq "eng"')


# ---------------------------------------------------------------------------
# for_cloud factory
# ---------------------------------------------------------------------------

def test_for_cloud_azure():
    with patch("databricks_group_audit.sdk_client.AccountClient"):
        c = DatabricksSDKClient.for_cloud("azure", "cid", "sec", "acct")
    assert "azuredatabricks.net" in c.account_host


def test_for_cloud_aws():
    with patch("databricks_group_audit.sdk_client.AccountClient"):
        c = DatabricksSDKClient.for_cloud("aws", "cid", "sec", "acct")
    assert "accounts.cloud.databricks.com" in c.account_host


def test_for_cloud_gcp():
    with patch("databricks_group_audit.sdk_client.AccountClient"):
        c = DatabricksSDKClient.for_cloud("gcp", "cid", "sec", "acct")
    assert "accounts.gcp.databricks.com" in c.account_host


# ---------------------------------------------------------------------------
# _get_ws_client caching
# ---------------------------------------------------------------------------

def test_ws_client_cached():
    client, _, _ = _make_client()
    with patch("databricks_group_audit.sdk_client.WorkspaceClient") as MockWC:
        MockWC.return_value = MagicMock()
        ws1 = client._get_ws_client("https://new-ws.azuredatabricks.net")
        ws2 = client._get_ws_client("https://new-ws.azuredatabricks.net")
    # WorkspaceClient should only be constructed once
    assert MockWC.call_count == 1
    assert ws1 is ws2


def test_ws_client_scheme_added():
    client, _, _ = _make_client()
    with patch("databricks_group_audit.sdk_client.WorkspaceClient") as MockWC:
        MockWC.return_value = MagicMock()
        client._get_ws_client("no-scheme.azuredatabricks.net")
    call_kwargs = MockWC.call_args[1]
    assert call_kwargs["host"].startswith("https://")


# ---------------------------------------------------------------------------
# _to_dict
# ---------------------------------------------------------------------------

def test_to_dict_with_as_dict():
    obj = MagicMock()
    obj.as_dict.return_value = {"k": "v"}
    assert DatabricksSDKClient._to_dict(obj) == {"k": "v"}


def test_to_dict_plain_dict():
    assert DatabricksSDKClient._to_dict({"a": 1}) == {"a": 1}


def test_to_dict_unknown_returns_empty():
    assert DatabricksSDKClient._to_dict(42) == {}
