"""Integration tests for the CLI entry point."""

import json

import responses as responses_lib

from databricks_group_audit.cli import _parse_args, main
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
