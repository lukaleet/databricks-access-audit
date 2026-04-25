"""Tests for CSV output (csv_output.py)."""

from __future__ import annotations

import csv
import io

from databricks_group_audit.csv_output import (
    write_diff_csv,
    write_group_audit_csv,
    write_principal_audit_csv,
)
from databricks_group_audit.models import (
    AuditDiff,
    CatalogGrant,
    EffectivePermission,
    EscalationFinding,
    GrantSource,
    GroupMembership,
    PrincipalAuditResult,
    RedundancyLevel,
    RedundancyResult,
    SchemaGrant,
    TableGrant,
    WorkspaceRole,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _catalog(name="main", principal="alice@example.com", privs=None):
    return CatalogGrant(
        catalog_name=name,
        workspace_name="ws1",
        workspace_url="https://ws1.azuredatabricks.net",
        principal=principal,
        principal_type="USER",
        privileges=privs or ["USE_CATALOG", "SELECT"],
        grant_source=GrantSource.MEMBER_DIRECT,
        inherited_from=None,
    )


def _schema(catalog="main", schema="default", principal="alice@example.com"):
    return SchemaGrant(
        catalog_name=catalog,
        schema_name=schema,
        workspace_name="ws1",
        workspace_url="https://ws1.azuredatabricks.net",
        principal=principal,
        principal_type="USER",
        privileges=["USE_SCHEMA"],
        grant_source=GrantSource.DIRECT,
        inherited_from="data-engineers",
    )


def _table():
    return TableGrant(
        catalog_name="main",
        schema_name="default",
        table_name="orders",
        full_name="main.default.orders",
        table_type="TABLE",
        workspace_name="ws1",
        workspace_url="https://ws1.azuredatabricks.net",
        principal="alice@example.com",
        principal_type="USER",
        privileges=["SELECT"],
        grant_source=GrantSource.DIRECT,
        inherited_from=None,
    )


def _redundancy():
    return RedundancyResult(
        catalog_name="main",
        principal="alice@example.com",
        principal_type="USER",
        member_privileges=["USE_CATALOG", "SELECT"],
        group_effective_privileges=["USE_CATALOG", "SELECT"],
        redundant_privileges=["USE_CATALOG", "SELECT"],
        additional_privileges=[],
        redundancy_level=RedundancyLevel.FULL,
        recommendation="REVOKE all personal grants",
    )


def _csv_rows(buf: io.StringIO):
    buf.seek(0)
    return list(csv.reader(buf))


# ---------------------------------------------------------------------------
# write_group_audit_csv
# ---------------------------------------------------------------------------

def test_group_csv_grant_headers():
    buf = io.StringIO()
    write_group_audit_csv([_catalog()], [], [], [], output=buf)
    rows = _csv_rows(buf)
    assert rows[0] == ["securable_type", "workspace", "securable_name",
                       "principal", "principal_type", "privileges",
                       "grant_source", "inherited_from"]


def test_group_csv_catalog_row():
    buf = io.StringIO()
    write_group_audit_csv([_catalog()], [], [], [], output=buf)
    rows = _csv_rows(buf)
    assert rows[1][0] == "CATALOG"
    assert rows[1][2] == "main"
    assert rows[1][3] == "alice@example.com"
    assert "USE_CATALOG" in rows[1][5]


def test_group_csv_schema_row():
    buf = io.StringIO()
    write_group_audit_csv([], [_schema()], [], [], output=buf)
    rows = _csv_rows(buf)
    assert rows[1][0] == "SCHEMA"
    assert rows[1][2] == "main.default"
    assert rows[1][7] == "data-engineers"  # inherited_from


def test_group_csv_table_row():
    buf = io.StringIO()
    write_group_audit_csv([], [], [_table()], [], output=buf)
    rows = _csv_rows(buf)
    assert rows[1][0] == "TABLE"
    assert rows[1][2] == "main.default.orders"


def test_group_csv_all_three_levels():
    buf = io.StringIO()
    write_group_audit_csv([_catalog()], [_schema()], [_table()], [], output=buf)
    rows = _csv_rows(buf)
    types = [r[0] for r in rows[1:]]
    assert "CATALOG" in types
    assert "SCHEMA" in types
    assert "TABLE" in types


def test_group_csv_no_redundancy_no_extra_rows():
    buf = io.StringIO()
    write_group_audit_csv([_catalog()], [], [], [], output=buf)
    rows = _csv_rows(buf)
    # Only header + 1 grant row, no blank/redundancy rows
    assert len(rows) == 2


def test_group_csv_redundancy_section():
    buf = io.StringIO()
    write_group_audit_csv([], [], [], [_redundancy()], output=buf)
    rows = _csv_rows(buf)
    # blank row, then redundancy header, then 1 redundancy row
    row_texts = [",".join(r) for r in rows]
    assert any("redundancy_level" in t for t in row_texts)
    assert any("Full" in t for t in row_texts)  # RedundancyLevel.FULL.value == "Full"


def test_group_csv_redundancy_level_full():
    buf = io.StringIO()
    write_group_audit_csv([], [], [], [_redundancy()], output=buf)
    rows = _csv_rows(buf)
    # find the data row after the redundancy header
    found = False
    for r in rows:
        if "Full" in r:
            found = True
            break
    assert found


def test_group_csv_privileges_pipe_separated():
    g = _catalog(privs=["USE_CATALOG", "SELECT", "MODIFY"])
    buf = io.StringIO()
    write_group_audit_csv([g], [], [], [], output=buf)
    rows = _csv_rows(buf)
    assert rows[1][5] == "USE_CATALOG|SELECT|MODIFY"


def test_group_csv_redundancy_header_has_additional_privileges():
    buf = io.StringIO()
    write_group_audit_csv([], [], [], [_redundancy()], output=buf)
    rows = _csv_rows(buf)
    headers = [r for r in rows if "redundancy_level" in r]
    assert headers, "redundancy header row not found"
    assert "additional_privileges" in headers[0]


def test_group_csv_redundancy_row_column_count():
    buf = io.StringIO()
    write_group_audit_csv([], [], [], [_redundancy()], output=buf)
    rows = _csv_rows(buf)
    data_rows = [r for r in rows if r and "Full" in r]
    assert data_rows, "redundancy data row not found"
    assert len(data_rows[0]) == 9  # 9 columns including additional_privileges


# ---------------------------------------------------------------------------
# write_principal_audit_csv
# ---------------------------------------------------------------------------

def _perm():
    return EffectivePermission(
        securable_type="CATALOG",
        securable_name="main",
        privileges=["USE_CATALOG", "SELECT"],
        via_group="data-engineers",
        workspace_name="ws1",
        workspace_url="https://ws1.azuredatabricks.net",
    )


def _group_membership():
    return GroupMembership(group_id="g-1", group_name="data-engineers", is_direct=True)


def _workspace_role():
    return WorkspaceRole(
        workspace_id="ws-1",
        workspace_name="ws1",
        workspace_url="https://ws1.azuredatabricks.net",
        permission_level="USER",
        via_group="data-engineers",
    )


def _principal_result(perms=None, escalations=None, groups=None, workspace_roles=None):
    r = PrincipalAuditResult(
        principal_type="USER",
        principal_id="u-1",
        principal_name="alice@example.com",
        permissions=perms or [_perm()],
        groups=groups or [],
        workspace_roles=workspace_roles or [],
    )
    r.escalation_findings = escalations or []
    return r


def test_principal_csv_group_memberships_header():
    buf = io.StringIO()
    write_principal_audit_csv(_principal_result(), [], output=buf)
    rows = _csv_rows(buf)
    assert rows[0] == ["group_id", "group_name", "is_direct", "path", "source"]


def test_principal_csv_workspace_roles_header():
    buf = io.StringIO()
    write_principal_audit_csv(_principal_result(), [], output=buf)
    rows = _csv_rows(buf)
    # blank at [1], then workspace_roles header
    assert rows[2] == ["workspace_id", "workspace_name", "permission_level", "via_group"]


def test_principal_csv_permissions_header():
    buf = io.StringIO()
    write_principal_audit_csv(_principal_result(), [], output=buf)
    rows = _csv_rows(buf)
    # groups_hdr[0], blank[1], roles_hdr[2], blank[3], perms_hdr[4]
    assert rows[4] == ["securable_type", "securable_name", "privileges", "via_group", "workspace"]


def test_principal_csv_permission_row():
    buf = io.StringIO()
    write_principal_audit_csv(_principal_result(), [], output=buf)
    rows = _csv_rows(buf)
    # groups_hdr[0], blank[1], roles_hdr[2], blank[3], perms_hdr[4], perm_row[5]
    assert rows[5][0] == "CATALOG"
    assert rows[5][1] == "main"
    assert rows[5][3] == "data-engineers"
    assert rows[5][4] == "ws1"


def test_principal_csv_no_escalations_section_count():
    buf = io.StringIO()
    write_principal_audit_csv(_principal_result(), [], output=buf)
    rows = _csv_rows(buf)
    # 3 sections: groups_hdr, blank, roles_hdr, blank, perms_hdr + 1 perm row = 6
    assert len(rows) == 6


def test_principal_csv_group_membership_row():
    result = _principal_result(groups=[_group_membership()])
    buf = io.StringIO()
    write_principal_audit_csv(result, [], output=buf)
    rows = _csv_rows(buf)
    assert rows[1][0] == "g-1"
    assert rows[1][1] == "data-engineers"
    assert rows[1][2] == "True"


def test_principal_csv_workspace_role_row():
    result = _principal_result(workspace_roles=[_workspace_role()])
    buf = io.StringIO()
    write_principal_audit_csv(result, [], output=buf)
    rows = _csv_rows(buf)
    # groups_hdr[0], blank[1], roles_hdr[2], role_row[3]
    assert rows[3][0] == "ws-1"
    assert rows[3][1] == "ws1"
    assert rows[3][2] == "USER"
    assert rows[3][3] == "data-engineers"


def test_principal_csv_escalation_section():
    esc = EscalationFinding(
        principal_name="alice@example.com",
        privilege="ALL_PRIVILEGES",
        securable_type="CATALOG",
        securable_name="main",
        via_group="data-engineers",
        is_transitive=True,
        workspace_name="ws1",
        workspace_url="https://ws1.azuredatabricks.net",
    )
    buf = io.StringIO()
    write_principal_audit_csv(_principal_result(), [esc], output=buf)
    rows = _csv_rows(buf)
    row_texts = [",".join(r) for r in rows]
    assert any("ALL_PRIVILEGES" in t for t in row_texts)
    assert any("privilege" in t for t in row_texts)  # escalation header present


# ---------------------------------------------------------------------------
# write_diff_csv
# ---------------------------------------------------------------------------

def _simple_diff(grants_added=None, grants_removed=None, members_added=None, members_removed=None):
    return AuditDiff(
        baseline_timestamp="2025-01-01T00:00:00Z",
        current_timestamp="2025-04-01T00:00:00Z",
        mode="group",
        target="data-engineers",
        grants_added=grants_added or [],
        grants_removed=grants_removed or [],
        members_added=members_added or [],
        members_removed=members_removed or [],
    )


def test_diff_csv_headers():
    buf = io.StringIO()
    write_diff_csv(_simple_diff(), output=buf)
    rows = _csv_rows(buf)
    assert rows[0][0] == "change_type"
    assert "securable_type" in rows[0]


def test_diff_csv_grant_added_row():
    diff = _simple_diff(grants_added=[{
        "securable_type": "CATALOG", "workspace_name": "ws1",
        "securable_name": "main", "principal": "bob@example.com",
        "principal_type": "USER", "privileges": ["SELECT"], "grant_source": "Direct",
    }])
    buf = io.StringIO()
    write_diff_csv(diff, output=buf)
    rows = _csv_rows(buf)
    assert any(r[0] == "GRANT_ADDED" for r in rows)


def test_diff_csv_grant_removed_row():
    diff = _simple_diff(grants_removed=[{
        "securable_type": "CATALOG", "workspace_name": "ws1",
        "securable_name": "main", "principal": "bob@example.com",
        "principal_type": "USER", "privileges": ["SELECT"], "grant_source": "Direct",
    }])
    buf = io.StringIO()
    write_diff_csv(diff, output=buf)
    rows = _csv_rows(buf)
    assert any(r[0] == "GRANT_REMOVED" for r in rows)


def test_diff_csv_member_added_row():
    diff = _simple_diff(members_added=[{
        "id": "u-99", "display_name": "NewUser", "type": "USER", "external_id": None,
    }])
    buf = io.StringIO()
    write_diff_csv(diff, output=buf)
    rows = _csv_rows(buf)
    # blank rows from w.writerow([]) are read back as [] — guard against them
    assert any(r and r[0] == "MEMBER_ADDED" for r in rows)
    assert any("NewUser" in r for r in rows)


def test_diff_csv_empty_diff_only_header():
    buf = io.StringIO()
    write_diff_csv(_simple_diff(), output=buf)
    rows = [r for r in _csv_rows(buf) if any(r)]  # skip blank rows
    assert len(rows) == 1  # just the header


def test_diff_csv_member_section_header_uses_external_id():
    diff = _simple_diff(members_added=[{
        "id": "u-99", "display_name": "NewUser", "type": "USER", "external_id": "ext-123",
    }])
    buf = io.StringIO()
    write_diff_csv(diff, output=buf)
    rows = _csv_rows(buf)
    headers = [r for r in rows if r and r[0] == "change_type" and "external_id" in r]
    assert headers, "member section header with 'external_id' not found"
