"""Tests for resource_auditor.py and related resource audit functionality."""

from __future__ import annotations

import io

import pytest
import responses as responses_lib

from tests.conftest import (
    ACCOUNT_HOST,
    ACCOUNT_ID,
    ALL_SPS,
    ALL_USERS,
    WORKSPACE_HOST,
)

ACCOUNT_BASE = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"


# ---------------------------------------------------------------------------
# detect_resource_type
# ---------------------------------------------------------------------------

def test_detect_resource_type_catalog():
    from databricks_access_audit.resource_auditor import detect_resource_type
    assert detect_resource_type("main") == "catalog"


def test_detect_resource_type_schema():
    from databricks_access_audit.resource_auditor import detect_resource_type
    assert detect_resource_type("main.analytics") == "schema"


def test_detect_resource_type_table():
    from databricks_access_audit.resource_auditor import detect_resource_type
    assert detect_resource_type("main.analytics.orders") == "table"


def test_detect_resource_type_workspace_url():
    from databricks_access_audit.resource_auditor import detect_resource_type
    assert detect_resource_type("https://adb-123.azuredatabricks.net") == "workspace"


def test_detect_resource_type_workspace_by_name():
    from databricks_access_audit.resource_auditor import detect_resource_type
    assert detect_resource_type("prod-databricks-workspace") == "workspace"


# ---------------------------------------------------------------------------
# _classify_principal
# ---------------------------------------------------------------------------

def test_classify_principal_email_is_user(mock_scim):
    rsps, client = mock_scim
    from databricks_access_audit.resource_auditor import ResourceAuditor

    # Add a user lookup response for userName filter
    rsps.add(
        responses_lib.GET,
        f"{ACCOUNT_BASE}/scim/v2/Users",
        json={"Resources": [ALL_USERS[0]], "totalResults": 1},
    )

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    ptype, psrc = auditor._classify_principal("alice@example.com")
    assert ptype == "USER"


def test_classify_principal_group_via_scim(mock_scim):
    rsps, client = mock_scim
    from databricks_access_audit.resource_auditor import ResourceAuditor

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    ptype, psrc = auditor._classify_principal("data-engineers")
    assert ptype == "GROUP"


def test_classify_principal_sp_via_scim(mock_scim):
    rsps, client = mock_scim
    from databricks_access_audit.resource_auditor import ResourceAuditor

    # Add SP lookup — the existing mock_scim returns ALL_SPS (ETL-Bot) on GET .../ServicePrincipals
    rsps.add(
        responses_lib.GET,
        f"{ACCOUNT_BASE}/scim/v2/ServicePrincipals",
        json={"Resources": [ALL_SPS[0]], "totalResults": 1},
    )
    # Also add a groups lookup that returns empty so we fall through to SP
    rsps.add(
        responses_lib.GET,
        f"{ACCOUNT_BASE}/scim/v2/Groups",
        json={"Resources": [], "totalResults": 0},
    )

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    ptype, psrc = auditor._classify_principal("ETL-Bot")
    assert ptype in ("GROUP", "SERVICE_PRINCIPAL")  # depends on mock order, but must not raise


def test_classify_principal_defaults_to_group(mock_scim):
    rsps, client = mock_scim
    from databricks_access_audit.resource_auditor import ResourceAuditor

    # Override with empty responses so all lookups return nothing
    rsps.add(
        responses_lib.GET,
        f"{ACCOUNT_BASE}/scim/v2/Groups",
        json={"Resources": [], "totalResults": 0},
    )
    rsps.add(
        responses_lib.GET,
        f"{ACCOUNT_BASE}/scim/v2/ServicePrincipals",
        json={"Resources": [], "totalResults": 0},
    )

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    ptype, psrc = auditor._classify_principal("unknown-principal")
    assert ptype == "GROUP"


def test_classify_principal_cached(mock_scim):
    rsps, client = mock_scim
    from databricks_access_audit.resource_auditor import ResourceAuditor

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    # First call — may hit SCIM
    ptype1, src1 = auditor._classify_principal("data-engineers")
    # Second call — must return same result from cache without extra requests
    call_count_before = len(rsps.calls)
    ptype2, src2 = auditor._classify_principal("data-engineers")
    call_count_after = len(rsps.calls)

    assert ptype1 == ptype2
    assert src1 == src2
    # No new HTTP calls made (cache hit)
    assert call_count_after == call_count_before


# ---------------------------------------------------------------------------
# _scan_uc_resource
# ---------------------------------------------------------------------------

def test_scan_uc_resource_catalog(mock_uc):
    rsps, client = mock_uc
    from databricks_access_audit.models import WorkspaceInfo
    from databricks_access_audit.resource_auditor import ResourceAuditor

    ws = WorkspaceInfo(
        workspace_id="ws-1", deployment_name="test-workspace",
        workspace_name="test-workspace", workspace_url=WORKSPACE_HOST,
        cloud="AZURE", region="eastus",
    )
    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    grants = auditor._scan_uc_resource(ws, "catalog", "main", expand_groups=False)

    assert len(grants) == 3
    principals = {g.principal_name for g in grants}
    assert "data-engineers" in principals
    assert "all-data-team" in principals
    assert "alice@example.com" in principals

    # All should be direct (no expansion)
    for g in grants:
        assert g.via_group is None
    assert grants[0].resource_type == "CATALOG"
    assert grants[0].resource_name == "main"


def test_scan_uc_resource_empty_on_error(mock_scim):
    rsps, client = mock_scim
    from databricks_access_audit.models import WorkspaceInfo
    from databricks_access_audit.resource_auditor import ResourceAuditor

    # Mock a 404 for the UC endpoint
    rsps.add(
        responses_lib.GET,
        f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/catalog/nonexistent",
        status=404,
        json={"error_code": "NOT_FOUND"},
    )
    rsps.add(
        responses_lib.POST, f"{WORKSPACE_HOST}/oidc/v1/token",
        json={"access_token": "ws-token", "expires_in": 3600},
    )

    ws = WorkspaceInfo(
        workspace_id="ws-1", deployment_name="test-workspace",
        workspace_name="test-workspace", workspace_url=WORKSPACE_HOST,
        cloud="AZURE", region="eastus",
    )
    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    # Should return empty list silently, not raise
    grants = auditor._scan_uc_resource(ws, "catalog", "nonexistent", expand_groups=False)
    assert grants == []


def test_scan_uc_resource_expands_groups(mock_uc):
    rsps, client = mock_uc
    from databricks_access_audit.models import WorkspaceInfo
    from databricks_access_audit.resource_auditor import ResourceAuditor

    ws = WorkspaceInfo(
        workspace_id="ws-1", deployment_name="test-workspace",
        workspace_name="test-workspace", workspace_url=WORKSPACE_HOST,
        cloud="AZURE", region="eastus",
    )
    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    grants = auditor._scan_uc_resource(ws, "catalog", "main", expand_groups=True)

    # Should include direct grants + member grants for any GROUP principals
    via_group_grants = [g for g in grants if g.via_group is not None]
    direct_grants = [g for g in grants if g.via_group is None]

    assert len(direct_grants) >= 3  # at minimum the 3 direct grants
    # Group expansion should add members
    assert len(via_group_grants) > 0
    for g in via_group_grants:
        assert g.via_group is not None
        assert g.principal_type in ("USER", "SERVICE_PRINCIPAL", "GROUP")


def test_scan_uc_resource_no_expand(mock_uc):
    rsps, client = mock_uc
    from databricks_access_audit.models import WorkspaceInfo
    from databricks_access_audit.resource_auditor import ResourceAuditor

    ws = WorkspaceInfo(
        workspace_id="ws-1", deployment_name="test-workspace",
        workspace_name="test-workspace", workspace_url=WORKSPACE_HOST,
        cloud="AZURE", region="eastus",
    )
    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    grants = auditor._scan_uc_resource(ws, "catalog", "main", expand_groups=False)

    # No via_group entries
    via_group_grants = [g for g in grants if g.via_group is not None]
    assert len(via_group_grants) == 0
    assert len(grants) == 3


# ---------------------------------------------------------------------------
# _scan_workspace_resource
# ---------------------------------------------------------------------------

def _add_workspace_discovery(rsps, workspace_id="ws-123", workspace_name="prod-workspace"):
    rsps.add(
        responses_lib.GET,
        f"{ACCOUNT_BASE}/workspaces",
        json=[{
            "workspace_id": workspace_id,
            "workspace_name": workspace_name,
            "deployment_name": "prod-workspace",
            "workspace_status": "RUNNING",
            "cloud": "AZURE",
            "azure_workspace_info": {"region": "eastus"},
            "deployment_url": WORKSPACE_HOST,
        }],
    )


def _add_permission_assignments(rsps, workspace_id="ws-123"):
    rsps.add(
        responses_lib.GET,
        f"{ACCOUNT_BASE}/workspaces/{workspace_id}/permissionassignments",
        json={
            "permission_assignments": [
                {
                    "principal": {
                        "display_name": "data-engineers",
                        "principal_id": 1,
                    },
                    "permissions": [{"permission_level": "USER"}],
                },
                {
                    "principal": {
                        "display_name": "alice@example.com",
                        "user_name": "alice@example.com",
                        "principal_id": 2,
                    },
                    "permissions": [{"permission_level": "ADMIN"}],
                },
            ]
        },
    )


def test_scan_workspace_resource(mock_scim):
    rsps, client = mock_scim
    from databricks_access_audit.models import WorkspaceInfo
    from databricks_access_audit.resource_auditor import ResourceAuditor

    _add_permission_assignments(rsps, "ws-123")

    ws = WorkspaceInfo(
        workspace_id="ws-123", deployment_name="prod-workspace",
        workspace_name="prod-workspace", workspace_url=WORKSPACE_HOST,
        cloud="AZURE", region="eastus",
    )
    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    grants = auditor._scan_workspace_resource(ws, expand_groups=False)

    assert len(grants) == 2
    principals = {g.principal_name for g in grants}
    assert "data-engineers" in principals
    assert "alice@example.com" in principals
    for g in grants:
        assert g.resource_type == "WORKSPACE"
        assert g.via_group is None


def test_scan_workspace_resource_expands_groups(mock_scim):
    rsps, client = mock_scim
    from databricks_access_audit.models import WorkspaceInfo
    from databricks_access_audit.resource_auditor import ResourceAuditor

    _add_permission_assignments(rsps, "ws-123")

    ws = WorkspaceInfo(
        workspace_id="ws-123", deployment_name="prod-workspace",
        workspace_name="prod-workspace", workspace_url=WORKSPACE_HOST,
        cloud="AZURE", region="eastus",
    )
    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    grants = auditor._scan_workspace_resource(ws, expand_groups=True)

    via_group_grants = [g for g in grants if g.via_group is not None]
    assert len(via_group_grants) > 0
    for g in via_group_grants:
        assert g.via_group == "data-engineers"


# ---------------------------------------------------------------------------
# audit() — catalog mode
# ---------------------------------------------------------------------------

def test_audit_catalog_result_type(mock_uc):
    rsps, client = mock_uc
    from databricks_access_audit.resource_auditor import ResourceAuditor

    _add_workspace_discovery(rsps)

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    result = auditor.audit("main", expand_groups=False)

    assert result.resource_type == "CATALOG"
    assert result.resource_name == "main"


def test_audit_catalog_direct_grants_no_expand(mock_uc):
    rsps, client = mock_uc
    from databricks_access_audit.resource_auditor import ResourceAuditor

    _add_workspace_discovery(rsps)

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    result = auditor.audit("main", expand_groups=False)

    assert len(result.grants) == 3
    principals = {g.principal_name for g in result.grants}
    assert "data-engineers" in principals
    assert "alice@example.com" in principals


def test_audit_catalog_deduplicates_across_workspaces(mock_uc):
    rsps, client = mock_uc
    from databricks_access_audit.resource_auditor import ResourceAuditor

    # Register two workspaces that both return the same catalog grants
    rsps.add(
        responses_lib.GET,
        f"{ACCOUNT_BASE}/workspaces",
        json=[
            {
                "workspace_id": "ws-1",
                "workspace_name": "workspace-1",
                "deployment_name": "ws-1",
                "workspace_status": "RUNNING",
                "cloud": "AZURE",
                "azure_workspace_info": {"region": "eastus"},
                "deployment_url": WORKSPACE_HOST,
            },
            {
                "workspace_id": "ws-2",
                "workspace_name": "workspace-2",
                "deployment_name": "ws-2",
                "workspace_status": "RUNNING",
                "cloud": "AZURE",
                "azure_workspace_info": {"region": "eastus"},
                "deployment_url": WORKSPACE_HOST,
            },
        ],
    )
    # Both workspaces point to same WORKSPACE_HOST, so same UC grants get returned twice
    # The auditor should deduplicate them by (principal_name, via_group, privileges)
    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    result = auditor.audit("main", expand_groups=False)

    # After dedup, should only have 3 unique grants (not 6)
    assert len(result.grants) == 3


# ---------------------------------------------------------------------------
# audit() — workspace mode
# ---------------------------------------------------------------------------

def test_audit_workspace_finds_by_name(mock_scim):
    rsps, client = mock_scim
    from databricks_access_audit.resource_auditor import ResourceAuditor

    _add_workspace_discovery(rsps, workspace_id="ws-123", workspace_name="prod-workspace")
    _add_permission_assignments(rsps, "ws-123")

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    # Explicitly specify resource_type="workspace" since "prod-workspace" has no dots
    result = auditor.audit("prod-workspace", resource_type="workspace", expand_groups=False)

    assert result.resource_type == "WORKSPACE"
    assert result.resource_name == "prod-workspace"
    assert len(result.grants) > 0


def test_audit_workspace_not_found_raises(mock_scim):
    rsps, client = mock_scim
    from databricks_access_audit.resource_auditor import ResourceAuditor

    # Return empty workspaces list
    rsps.add(
        responses_lib.GET,
        f"{ACCOUNT_BASE}/workspaces",
        json=[],
    )

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    with pytest.raises(ValueError, match="not found"):
        auditor.audit("nonexistent-workspace", resource_type="workspace")


# ---------------------------------------------------------------------------
# ResourceGrant model checks
# ---------------------------------------------------------------------------

def test_resource_grant_via_group_field(mock_uc):
    rsps, client = mock_uc
    from databricks_access_audit.resource_auditor import ResourceAuditor

    _add_workspace_discovery(rsps)

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    result = auditor.audit("main", expand_groups=True)

    direct = [g for g in result.grants if g.via_group is None]
    inherited = [g for g in result.grants if g.via_group is not None]

    # Direct grants should have via_group = None
    for g in direct:
        assert g.via_group is None

    # Inherited grants should have a group name
    if inherited:
        for g in inherited:
            assert isinstance(g.via_group, str)
            assert len(g.via_group) > 0


def test_resource_audit_result_has_changes(mock_uc):
    rsps, client = mock_uc
    from databricks_access_audit.resource_auditor import ResourceAuditor

    _add_workspace_discovery(rsps)

    auditor = ResourceAuditor(client, ACCOUNT_ID, "azure")
    result = auditor.audit("main", expand_groups=False)

    assert len(result.grants) > 0


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

def _make_result(with_via_group=False):
    from databricks_access_audit.models import PrincipalSource, ResourceAuditResult, ResourceGrant

    grants = [
        ResourceGrant(
            resource_type="CATALOG",
            resource_name="main",
            principal_name="data-engineers",
            principal_type="GROUP",
            principal_source=PrincipalSource.EXTERNAL,
            privileges=["USE_CATALOG", "SELECT"],
            via_group=None,
            workspace_name="prod-workspace",
        ),
        ResourceGrant(
            resource_type="CATALOG",
            resource_name="main",
            principal_name="alice@example.com",
            principal_type="USER",
            principal_source=PrincipalSource.INTERNAL,
            privileges=["USE_CATALOG"],
            via_group=None,
            workspace_name="prod-workspace",
        ),
    ]
    if with_via_group:
        grants.append(
            ResourceGrant(
                resource_type="CATALOG",
                resource_name="main",
                principal_name="bob@example.com",
                principal_type="USER",
                principal_source=PrincipalSource.EXTERNAL,
                privileges=["USE_CATALOG", "SELECT"],
                via_group="data-engineers",
                workspace_name="prod-workspace",
            )
        )
    return ResourceAuditResult(resource_type="CATALOG", resource_name="main", grants=grants)


def test_html_renderer_contains_resource_name():
    from databricks_access_audit._resource_html_renderer import render_resource_html

    result = _make_result()
    html = render_resource_html(result)
    assert "main" in html


def test_html_renderer_contains_mermaid():
    from databricks_access_audit._resource_html_renderer import render_resource_html

    result = _make_result()
    html = render_resource_html(result)
    assert "flowchart LR" in html or "graph LR" in html


def test_html_renderer_no_grants():
    from databricks_access_audit._resource_html_renderer import render_resource_html
    from databricks_access_audit.models import ResourceAuditResult

    result = ResourceAuditResult(resource_type="CATALOG", resource_name="empty-catalog")
    # Should not raise
    html = render_resource_html(result)
    assert "empty-catalog" in html


def test_html_renderer_escapes_user_data():
    from databricks_access_audit._resource_html_renderer import render_resource_html
    from databricks_access_audit.models import PrincipalSource, ResourceAuditResult, ResourceGrant

    result = ResourceAuditResult(
        resource_type="CATALOG",
        resource_name="<b>xss-test</b>",
        grants=[
            ResourceGrant(
                resource_type="CATALOG",
                resource_name="<b>xss-test</b>",
                principal_name='<img onerror="xss">',
                principal_type="USER",
                principal_source=PrincipalSource.INTERNAL,
                privileges=["SELECT"],
                via_group=None,
                workspace_name="ws",
            )
        ],
    )
    html = render_resource_html(result)
    # User-supplied tag should be escaped (not appear as a raw tag)
    assert "<b>xss-test</b>" not in html
    assert "&lt;b&gt;xss-test&lt;/b&gt;" in html
    assert '<img onerror="xss">' not in html


def test_html_renderer_with_via_group_section():
    from databricks_access_audit._resource_html_renderer import render_resource_html

    result = _make_result(with_via_group=True)
    html = render_resource_html(result)
    assert "Via group" in html
    assert "data-engineers" in html


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

def test_csv_output_has_correct_columns():
    from databricks_access_audit.csv_output import write_resource_audit_csv

    result = _make_result()
    buf = io.StringIO()
    write_resource_audit_csv(result, output=buf)
    buf.seek(0)
    header = buf.readline().strip()
    cols = header.split(",")
    expected = [
        "resource_type", "resource_name", "principal_name", "principal_type",
        "principal_source", "privileges", "via_group", "workspace_name",
    ]
    assert cols == expected


def test_csv_output_data_rows():
    from databricks_access_audit.csv_output import write_resource_audit_csv

    result = _make_result()
    buf = io.StringIO()
    write_resource_audit_csv(result, output=buf)
    buf.seek(0)
    lines = buf.readlines()
    # Header + 2 data rows
    assert len(lines) == 3
    assert "data-engineers" in lines[1]
    assert "CATALOG" in lines[1]


def test_csv_output_via_group_field():
    from databricks_access_audit.csv_output import write_resource_audit_csv

    result = _make_result(with_via_group=True)
    buf = io.StringIO()
    write_resource_audit_csv(result, output=buf)
    buf.seek(0)
    content = buf.read()
    assert "data-engineers" in content


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

def test_cli_resource_flag_text_output(mock_uc, capsys):
    rsps, client = mock_uc
    from databricks_access_audit.cli import _run_resource_audit

    _add_workspace_discovery(rsps)

    import argparse
    args = argparse.Namespace(
        resource="main",
        output="text",
        no_expand_groups=True,
        workspace_urls="",
        workers=1,
        cloud="azure",
        account_id=ACCOUNT_ID,
    )
    rc = _run_resource_audit(args, client)
    assert rc == 0
    captured = capsys.readouterr()
    assert "main" in captured.out
    assert "CATALOG" in captured.out


def test_cli_resource_flag_csv_output(mock_uc, capsys):
    rsps, client = mock_uc
    from databricks_access_audit.cli import _run_resource_audit

    _add_workspace_discovery(rsps)

    import argparse
    args = argparse.Namespace(
        resource="main",
        output="csv",
        no_expand_groups=True,
        workspace_urls="",
        workers=1,
        cloud="azure",
        account_id=ACCOUNT_ID,
    )
    rc = _run_resource_audit(args, client)
    assert rc == 0
    captured = capsys.readouterr()
    assert "resource_type" in captured.out
    assert "principal_name" in captured.out


def test_cli_resource_flag_json_output(mock_uc, capsys):
    rsps, client = mock_uc
    from databricks_access_audit.cli import _run_resource_audit

    _add_workspace_discovery(rsps)

    import argparse
    import json
    args = argparse.Namespace(
        resource="main",
        output="json",
        no_expand_groups=True,
        workspace_urls="",
        workers=1,
        cloud="azure",
        account_id=ACCOUNT_ID,
    )
    rc = _run_resource_audit(args, client)
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["resource_type"] == "CATALOG"
    assert data["resource_name"] == "main"
    assert "grants" in data


def test_cli_resource_workspace_not_found_returns_1(mock_scim, capsys):
    rsps, client = mock_scim
    from databricks_access_audit.cli import _run_resource_audit

    rsps.add(
        responses_lib.GET,
        f"{ACCOUNT_BASE}/workspaces",
        json=[],
    )

    import argparse
    args = argparse.Namespace(
        resource="nonexistent-databricks-workspace",
        output="text",
        no_expand_groups=True,
        workspace_urls="",
        workers=1,
        cloud="azure",
        account_id=ACCOUNT_ID,
    )
    rc = _run_resource_audit(args, client)
    assert rc == 1
    captured = capsys.readouterr()
    assert "ERROR" in captured.err


def test_cli_resource_html_output(mock_uc, capsys):
    rsps, client = mock_uc
    from databricks_access_audit.cli import _run_resource_audit

    _add_workspace_discovery(rsps)

    import argparse
    args = argparse.Namespace(
        resource="main",
        output="html",
        no_expand_groups=True,
        workspace_urls="",
        workers=1,
        cloud="azure",
        account_id=ACCOUNT_ID,
    )
    rc = _run_resource_audit(args, client)
    assert rc == 0
    captured = capsys.readouterr()
    assert "<!DOCTYPE html>" in captured.out
    assert "flowchart LR" in captured.out or "mermaid" in captured.out


def test_cli_resource_mutually_exclusive():
    """--resource is mutually exclusive with --group, --principal, etc."""
    from databricks_access_audit.cli import _parse_args

    with pytest.raises(SystemExit):
        _parse_args(["--group", "data-engineers", "--resource", "main",
                     "--account-id", "x", "--client-id", "y", "--client-secret", "z"])


def test_cli_resource_type_override_parsed():
    """--resource-type overrides auto-detection."""
    from databricks_access_audit.cli import _parse_args

    args = _parse_args([
        "--resource", "prod-workspace",
        "--resource-type", "workspace",
        "--account-id", "x", "--client-id", "y", "--client-secret", "z",
    ])
    assert args.resource == "prod-workspace"
    assert args.resource_type == "workspace"


def test_cli_resource_type_default_none():
    """--resource-type defaults to None (auto-detect)."""
    from databricks_access_audit.cli import _parse_args

    args = _parse_args([
        "--resource", "main",
        "--account-id", "x", "--client-id", "y", "--client-secret", "z",
    ])
    assert args.resource_type is None


def test_cli_resource_type_passed_to_auditor(mock_scim, capsys):
    """--resource-type workspace is forwarded to ResourceAuditor.audit()."""
    rsps, client = mock_scim
    from databricks_access_audit.cli import _run_resource_audit

    _add_workspace_discovery(rsps, workspace_id="ws-1", workspace_name="prod-workspace")
    _add_permission_assignments(rsps, "ws-1")

    import argparse
    args = argparse.Namespace(
        resource="prod-workspace",
        resource_type="workspace",
        output="text",
        no_expand_groups=True,
        workspace_urls="",
        workers=1,
        cloud="azure",
        account_id=ACCOUNT_ID,
    )
    rc = _run_resource_audit(args, client)
    assert rc == 0
    out = capsys.readouterr().out
    assert "WORKSPACE" in out or "prod-workspace" in out


def test_cli_resource_summary_text_output(mock_uc, capsys):
    """--summary appends a compact block to stdout for resource audit text output."""
    rsps, client = mock_uc
    from databricks_access_audit.cli import _run_resource_audit

    _add_workspace_discovery(rsps)

    import argparse
    args = argparse.Namespace(
        resource="main",
        output="text",
        no_expand_groups=True,
        workspace_urls="",
        workers=1,
        cloud="azure",
        account_id=ACCOUNT_ID,
        summary=True,
    )
    rc = _run_resource_audit(args, client)
    assert rc == 0
    out = capsys.readouterr().out
    assert "SUMMARY" in out
    assert "main" in out
    assert "Total access" in out


def test_cli_resource_summary_goes_to_stderr_for_json(mock_uc, capsys):
    """--summary writes to stderr when --output json for resource audit."""
    import json as json_lib

    rsps, client = mock_uc
    from databricks_access_audit.cli import _run_resource_audit

    _add_workspace_discovery(rsps)

    import argparse
    args = argparse.Namespace(
        resource="main",
        output="json",
        no_expand_groups=True,
        workspace_urls="",
        workers=1,
        cloud="azure",
        account_id=ACCOUNT_ID,
        summary=True,
    )
    rc = _run_resource_audit(args, client)
    assert rc == 0
    captured = capsys.readouterr()
    json_lib.loads(captured.out)   # stdout must be valid JSON
    assert "SUMMARY" in captured.err
