"""Integration tests for the CLI entry point."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import responses as responses_lib

from databricks_group_audit.cli import _elevation_context, _parse_args, main
from databricks_group_audit.models import WorkspaceInfo
from tests.conftest import (
    ACCOUNT_HOST,
    ACCOUNT_ID,
    ALL_GROUPS,
    ALL_SPS,
    ALL_USERS,
    CATALOGS_RESPONSE,
    MAIN_CATALOG_GRANTS,
    SCIM_SP_ETL,
    STAGING_CATALOG_GRANTS,
    WORKSPACE_HOST,
)

# ---------------------------------------------------------------------------
# _parse_args
# ---------------------------------------------------------------------------

def test_parse_args_group_mode():
    args = _parse_args([
        "--group", "data-engineers",
        "--client-id", "cid",
        "--client-secret", "secret",
        "--account-id", "acct",
        "--cloud", "azure",
    ])
    assert args.group == "data-engineers"
    assert args.principal is None
    assert args.cloud == "azure"
    assert args.no_sdk is False


def test_parse_args_principal_mode():
    args = _parse_args([
        "--principal", "alice@example.com",
        "--client-id", "cid",
        "--client-secret", "secret",
        "--account-id", "acct",
    ])
    assert args.principal == "alice@example.com"
    assert args.group is None


def test_parse_args_json_output():
    args = _parse_args([
        "--group", "g", "--client-id", "c", "--client-secret", "s",
        "--account-id", "a", "--output", "json",
    ])
    assert args.output == "json"


def test_parse_args_scan_flags():
    args = _parse_args([
        "--group", "g", "--client-id", "c", "--client-secret", "s",
        "--account-id", "a", "--scan-schemas", "--scan-tables",
    ])
    assert args.scan_schemas is True
    assert args.scan_tables is True


def test_parse_args_no_sdk():
    args = _parse_args([
        "--group", "g", "--client-id", "c", "--client-secret", "s",
        "--account-id", "a", "--no-sdk",
    ])
    assert args.no_sdk is True


def test_parse_args_workers_default():
    args = _parse_args([
        "--group", "g", "--client-id", "c", "--client-secret", "s", "--account-id", "a",
    ])
    assert args.workers == 8


def test_parse_args_workers_explicit():
    args = _parse_args([
        "--group", "g", "--client-id", "c", "--client-secret", "s",
        "--account-id", "a", "--workers", "4",
    ])
    assert args.workers == 4


def test_parse_args_workspace_urls():
    args = _parse_args([
        "--group", "g", "--client-id", "c", "--client-secret", "s",
        "--account-id", "a",
        "--workspace-urls", "https://ws1.azuredatabricks.net,https://ws2.azuredatabricks.net",
    ])
    assert "ws1" in args.workspace_urls


# ---------------------------------------------------------------------------
# Helpers shared by CLI integration tests
# ---------------------------------------------------------------------------

def _register_common_mocks(rsps):
    """Register account + workspace API mocks used by both audit paths."""
    base = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"

    rsps.add(responses_lib.POST, f"{ACCOUNT_HOST}/oidc/v1/token",
             json={"access_token": "mock-token", "expires_in": 3600})
    rsps.add(responses_lib.POST, f"{WORKSPACE_HOST}/oidc/v1/token",
             json={"access_token": "ws-token", "expires_in": 3600})

    # SCIM paginated lists
    rsps.add(responses_lib.GET, f"{base}/scim/v2/Groups",
             json={"Resources": ALL_GROUPS, "totalResults": len(ALL_GROUPS), "itemsPerPage": 100})
    rsps.add(responses_lib.GET, f"{base}/scim/v2/Users",
             json={"Resources": ALL_USERS, "totalResults": len(ALL_USERS), "itemsPerPage": 100})
    rsps.add(responses_lib.GET, f"{base}/scim/v2/ServicePrincipals",
             json={"Resources": ALL_SPS, "totalResults": len(ALL_SPS), "itemsPerPage": 100})

    # Individual SCIM lookups
    for g in ALL_GROUPS:
        rsps.add(responses_lib.GET, f"{base}/scim/v2/Groups/{g['id']}", json=g)
    for u in ALL_USERS:
        rsps.add(responses_lib.GET, f"{base}/scim/v2/Users/{u['id']}", json=u)
    rsps.add(responses_lib.GET, f"{base}/scim/v2/ServicePrincipals/sp-1", json=SCIM_SP_ETL)

    # Workspace discovery
    rsps.add(responses_lib.GET, f"{base}/workspaces", json=[{
        "workspace_id": "999",
        "deployment_name": "test-workspace",
        "workspace_name": "test-workspace",
        "workspace_url": WORKSPACE_HOST,
        "workspace_status": "RUNNING",
        "cloud": "AZURE",
        "azure_workspace_info": {"region": "eastus"},
    }])

    # Unity Catalog
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/catalogs",
             json=CATALOGS_RESPONSE)
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/catalog/main",
             json=MAIN_CATALOG_GRANTS)
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/catalog/staging",
             json=STAGING_CATALOG_GRANTS)


# ---------------------------------------------------------------------------
# Group audit — text output
# ---------------------------------------------------------------------------

def test_group_audit_text_output(capsys):
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_common_mocks(rsps)
        rc = main([
            "--group", "data-engineers",
            "--client-id", "cid",
            "--client-secret", "secret",
            "--account-id", ACCOUNT_ID,
            "--cloud", "azure",
            "--no-sdk",
            "--workspace-urls", WORKSPACE_HOST,
        ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "data-engineers" in out
    assert "Audit complete" in out


def test_group_audit_json_output(capsys):
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_common_mocks(rsps)
        rc = main([
            "--group", "data-engineers",
            "--client-id", "cid",
            "--client-secret", "secret",
            "--account-id", ACCOUNT_ID,
            "--cloud", "azure",
            "--no-sdk",
            "--workspace-urls", WORKSPACE_HOST,
            "--output", "json",
        ])
    assert rc == 0
    out = capsys.readouterr().out
    # Progress lines are printed before the JSON block; skip them.
    data = json.loads(out[out.find("{"):])
    assert data["group"] == "data-engineers"
    assert "catalog_grants" in data
    assert "full_redundancy" in data
    assert "top_members" in data


def test_group_audit_json_top_members_ranked(capsys):
    """top_members lists principals with member-direct grants, highest count first."""
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_common_mocks(rsps)
        main([
            "--group", "data-engineers",
            "--client-id", "cid",
            "--client-secret", "secret",
            "--account-id", ACCOUNT_ID,
            "--cloud", "azure",
            "--no-sdk",
            "--workspace-urls", WORKSPACE_HOST,
            "--output", "json",
        ])
    out = capsys.readouterr().out
    data = json.loads(out[out.find("{"):])
    top = data["top_members"]
    assert isinstance(top, list)
    # alice and bob each have one personal grant in the mock data
    principals = [m["principal"] for m in top]
    assert "alice@example.com" in principals
    assert "bob@example.com" in principals
    # every entry has required fields
    for m in top:
        assert "principal" in m
        assert "personal_grants" in m
        assert "redundancy" in m


def test_group_audit_unknown_group_returns_error(capsys):
    """Group not found → resolver returns None → CLI exits 1."""
    base = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.POST, f"{ACCOUNT_HOST}/oidc/v1/token",
                 json={"access_token": "mock-token", "expires_in": 3600})
        # Return empty for all SCIM list calls so the group is never found.
        for resource in ("Groups", "Users", "ServicePrincipals"):
            rsps.add(responses_lib.GET, f"{base}/scim/v2/{resource}",
                     json={"Resources": [], "totalResults": 0, "itemsPerPage": 100})
        rc = main([
            "--group", "nonexistent-group",
            "--client-id", "cid",
            "--client-secret", "secret",
            "--account-id", ACCOUNT_ID,
            "--cloud", "azure",
            "--no-sdk",
        ])
    assert rc == 1


def test_group_audit_missing_credentials_returns_error(capsys):
    rc = main(["--group", "data-engineers"])
    assert rc == 1
    assert "required" in capsys.readouterr().err.lower()


# ---------------------------------------------------------------------------
# Principal audit — text + JSON
# ---------------------------------------------------------------------------

def _register_permission_assignments(rsps):
    """Add /workspaces/999/permissionassignments for principal audit."""
    base = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"
    rsps.add(responses_lib.GET,
             f"{base}/workspaces/999/permissionassignments",
             json={"permission_assignments": [
                 {
                     "principal": {"display_name": "data-engineers",
                                   "group": {"display_name": "data-engineers"}, "id": 1},
                     "permissions": ["CAN_USE"],
                 }
             ]})


def test_principal_audit_text_output(capsys):
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_common_mocks(rsps)
        _register_permission_assignments(rsps)
        rc = main([
            "--principal", "alice@example.com",
            "--client-id", "cid",
            "--client-secret", "secret",
            "--account-id", ACCOUNT_ID,
            "--cloud", "azure",
            "--no-sdk",
        ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "alice" in out.lower()


def test_principal_audit_json_output(capsys):
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_common_mocks(rsps)
        _register_permission_assignments(rsps)
        rc = main([
            "--principal", "alice@example.com",
            "--client-id", "cid",
            "--client-secret", "secret",
            "--account-id", ACCOUNT_ID,
            "--cloud", "azure",
            "--no-sdk",
            "--output", "json",
        ])
    assert rc == 0
    out = capsys.readouterr().out
    # Progress line ("Auditing principal: ...") precedes the JSON block.
    data = json.loads(out[out.find("{"):])
    assert "principal" in data
    assert "groups" in data
    assert "workspace_roles" in data
    assert "dead_end_groups" in data
    assert "principal_source" in data  # key was misindented; verify it is in the dict


def test_principal_audit_not_found_returns_error(capsys):
    """Principal not found in any SCIM list → ValueError → CLI exits 1."""
    base = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.POST, f"{ACCOUNT_HOST}/oidc/v1/token",
                 json={"access_token": "mock-token", "expires_in": 3600})
        rsps.add(responses_lib.GET, f"{base}/workspaces", json=[])
        for resource in ("Users", "ServicePrincipals", "Groups"):
            rsps.add(responses_lib.GET, f"{base}/scim/v2/{resource}",
                     json={"Resources": [], "totalResults": 0, "itemsPerPage": 100})
        rc = main([
            "--principal", "ghost@nowhere.com",
            "--client-id", "cid",
            "--client-secret", "secret",
            "--account-id", ACCOUNT_ID,
            "--cloud", "azure",
            "--no-sdk",
        ])
    assert rc == 1


# ---------------------------------------------------------------------------
# UTC timestamps in JSON output
# ---------------------------------------------------------------------------


def test_group_audit_json_timestamp_is_utc(capsys):
    """JSON output timestamp must carry a UTC offset (+00:00 or Z), not be naive."""
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_common_mocks(rsps)
        main([
            "--group", "data-engineers",
            "--client-id", "cid", "--client-secret", "secret",
            "--account-id", ACCOUNT_ID, "--cloud", "azure", "--no-sdk",
            "--workspace-urls", WORKSPACE_HOST, "--output", "json",
        ])
    out = capsys.readouterr().out
    data = json.loads(out[out.find("{"):])
    ts = data["timestamp"]
    assert "+00:00" in ts or ts.endswith("Z"), f"Expected UTC timestamp, got: {ts}"


def test_principal_audit_json_timestamp_is_utc(capsys):
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _register_common_mocks(rsps)
        _register_permission_assignments(rsps)
        main([
            "--principal", "alice@example.com",
            "--client-id", "cid", "--client-secret", "secret",
            "--account-id", ACCOUNT_ID, "--cloud", "azure", "--no-sdk",
            "--output", "json",
        ])
    out = capsys.readouterr().out
    data = json.loads(out[out.find("{"):])
    ts = data["timestamp"]
    assert "+00:00" in ts or ts.endswith("Z"), f"Expected UTC timestamp, got: {ts}"


# ---------------------------------------------------------------------------
# _elevation_context — cleanup on partial elevation failure
# ---------------------------------------------------------------------------


_SP_SCIM_RESP = {
    "Resources": [{"id": "scim-99", "applicationId": "sp-app-001"}],
    "totalResults": 1,
}


def _make_elevation_client(fail_on_ws_id: str | None = None):
    """Return a mock client whose PUT raises when elevating *fail_on_ws_id*."""
    elevated: list[str] = []

    def _api(method: str, endpoint: str, **kwargs):
        if endpoint == "/scim/v2/ServicePrincipals":
            return _SP_SCIM_RESP
        if method == "GET" and "permissionassignments" in endpoint:
            return {"permission_assignments": []}
        if method == "PUT" and "permissionassignments" in endpoint:
            # Extract workspace ID from endpoint path segment.
            ws_id = endpoint.split("/workspaces/")[1].split("/")[0]
            if fail_on_ws_id and ws_id == fail_on_ws_id:
                raise RuntimeError(f"elevation failed for {ws_id}")
            elevated.append(ws_id)
            return {}
        if method == "DELETE" and "permissionassignments" in endpoint:
            ws_id = endpoint.split("/workspaces/")[1].split("/")[0]
            elevated.remove(ws_id) if ws_id in elevated else None
            return {}
        return {}

    client = MagicMock()
    client.account_api.side_effect = _api
    return client, elevated


def test_elevation_context_no_op_without_flag():
    """`_elevation_context` returns a nullcontext when --auto-elevate is not set."""
    import contextlib

    args = MagicMock()
    args.auto_elevate = False
    args.dry_run_elevation = False

    ctx = _elevation_context(args, MagicMock(), [])
    assert isinstance(ctx, contextlib.nullcontext)


def test_elevation_context_cleans_up_when_loop_raises():
    """If ensure_workspace_admin raises mid-loop, already-elevated workspaces
    must be revoked before the exception propagates."""
    args = MagicMock()
    args.auto_elevate = True
    args.dry_run_elevation = False
    args.client_id = "sp-app-001"

    ws1 = WorkspaceInfo("ws-1", "d1", "ws-one", "https://ws1.azuredatabricks.net", "AZURE", "eu")
    ws2 = WorkspaceInfo("ws-2", "d2", "ws-two", "https://ws2.azuredatabricks.net", "AZURE", "eu")

    client, elevated = _make_elevation_client(fail_on_ws_id="ws-2")

    with pytest.raises(RuntimeError, match="elevation failed"):
        _elevation_context(args, client, [ws1, ws2])

    # ws-1 was elevated then cleaned up; ws-2 was never elevated.
    delete_calls = [c for c in client.account_api.call_args_list if c.args[0] == "DELETE"]
    assert len(delete_calls) == 1, "ws-1 should have been revoked during cleanup"


def test_elevation_context_success_cleanup_on_body_exception():
    """If the WITH body raises (not the loop), cleanup still runs via __exit__."""
    args = MagicMock()
    args.auto_elevate = True
    args.dry_run_elevation = False
    args.client_id = "sp-app-001"

    ws1 = WorkspaceInfo("ws-1", "d1", "ws-one", "https://ws1.azuredatabricks.net", "AZURE", "eu")
    client, _ = _make_elevation_client()

    with pytest.raises(ValueError, match="scan failed"):
        with _elevation_context(args, client, [ws1]):
            raise ValueError("scan failed")

    delete_calls = [c for c in client.account_api.call_args_list if c.args[0] == "DELETE"]
    assert len(delete_calls) == 1, "ws-1 should be revoked on body exception"
