"""Tests for privilege escalation detection."""

from __future__ import annotations

import pytest

from databricks_group_audit.escalation import ESCALATION_PRIVILEGES, detect_escalations
from databricks_group_audit.models import EffectivePermission, PrincipalAuditResult


def _result(perms=None, name="alice@example.com", ptype="USER"):
    return PrincipalAuditResult(
        principal_type=ptype,
        principal_id="user-1",
        principal_name=name,
        permissions=perms or [],
    )


def _perm(privileges, securable_type="CATALOG", securable_name="main",
          via_group="data-engineers", ws_name="prod"):
    return EffectivePermission(
        securable_type=securable_type,
        securable_name=securable_name,
        privileges=privileges,
        via_group=via_group,
        workspace_name=ws_name,
        workspace_url="https://ws.azuredatabricks.net",
    )


# ---------------------------------------------------------------------------
# No escalation for regular privileges
# ---------------------------------------------------------------------------


def test_no_findings_for_normal_privileges():
    result = _result([_perm(["USE_CATALOG", "SELECT"])])
    assert detect_escalations(result) == []


def test_modify_not_escalation():
    result = _result([_perm(["MODIFY", "SELECT"])])
    assert detect_escalations(result) == []


def test_create_table_not_escalation():
    result = _result([_perm(["CREATE_TABLE", "USE_SCHEMA"])])
    assert detect_escalations(result) == []


# ---------------------------------------------------------------------------
# ALL_PRIVILEGES is escalation
# ---------------------------------------------------------------------------


def test_all_privileges_flagged():
    result = _result([_perm(["ALL_PRIVILEGES"])])
    findings = detect_escalations(result)
    assert len(findings) == 1
    assert findings[0].privilege == "ALL_PRIVILEGES"
    assert findings[0].securable_type == "CATALOG"
    assert findings[0].securable_name == "main"


def test_all_privileges_with_others_flagged():
    result = _result([_perm(["USE_CATALOG", "ALL_PRIVILEGES", "SELECT"])])
    findings = detect_escalations(result)
    assert len(findings) == 1
    assert findings[0].privilege == "ALL_PRIVILEGES"


# ---------------------------------------------------------------------------
# MANAGE is escalation
# ---------------------------------------------------------------------------


def test_manage_privilege_flagged():
    result = _result([_perm(["USE_CATALOG", "MANAGE"])])
    findings = detect_escalations(result)
    assert len(findings) == 1
    assert findings[0].privilege == "MANAGE"


# ---------------------------------------------------------------------------
# is_transitive flag
# ---------------------------------------------------------------------------


def test_grant_via_group_is_transitive():
    result = _result([_perm(["ALL_PRIVILEGES"], via_group="data-engineers")])
    findings = detect_escalations(result)
    assert findings[0].is_transitive is True


def test_grant_via_self_is_not_transitive():
    result = _result(
        [_perm(["MANAGE"], via_group="alice@example.com")],
        name="alice@example.com",
    )
    findings = detect_escalations(result)
    assert findings[0].is_transitive is False


def test_case_insensitive_self_match():
    result = _result(
        [_perm(["MANAGE"], via_group="Alice@Example.COM")],
        name="alice@example.com",
    )
    findings = detect_escalations(result)
    assert findings[0].is_transitive is False


# ---------------------------------------------------------------------------
# Multiple findings
# ---------------------------------------------------------------------------


def test_multiple_escalation_privileges():
    perms = [
        _perm(["ALL_PRIVILEGES"], securable_name="main"),
        _perm(["MANAGE"], securable_name="staging"),
    ]
    result = _result(perms)
    findings = detect_escalations(result)
    assert len(findings) == 2
    privileges = {f.privilege for f in findings}
    assert privileges == {"ALL_PRIVILEGES", "MANAGE"}


def test_same_privilege_on_multiple_objects():
    perms = [
        _perm(["MANAGE"], securable_type="CATALOG", securable_name="main"),
        _perm(["MANAGE"], securable_type="SCHEMA", securable_name="main.default"),
    ]
    result = _result(perms)
    findings = detect_escalations(result)
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# Schema and table level escalations
# ---------------------------------------------------------------------------


def test_escalation_at_schema_level():
    result = _result([_perm(["MANAGE"], securable_type="SCHEMA", securable_name="main.bronze")])
    findings = detect_escalations(result)
    assert len(findings) == 1
    assert findings[0].securable_type == "SCHEMA"


def test_escalation_at_table_level():
    result = _result([
        _perm(["ALL_PRIVILEGES"], securable_type="TABLE", securable_name="main.default.orders")
    ])
    findings = detect_escalations(result)
    assert len(findings) == 1
    assert findings[0].securable_type == "TABLE"


# ---------------------------------------------------------------------------
# Workspace metadata preserved in finding
# ---------------------------------------------------------------------------


def test_finding_carries_workspace_metadata():
    perm = EffectivePermission(
        securable_type="CATALOG", securable_name="main",
        privileges=["ALL_PRIVILEGES"], via_group="admins",
        workspace_name="prod-workspace",
        workspace_url="https://prod.azuredatabricks.net",
    )
    result = _result([perm])
    f = detect_escalations(result)[0]
    assert f.workspace_name == "prod-workspace"
    assert f.workspace_url == "https://prod.azuredatabricks.net"
    assert f.via_group == "admins"


# ---------------------------------------------------------------------------
# Empty permissions → no findings
# ---------------------------------------------------------------------------


def test_empty_permissions():
    assert detect_escalations(_result([])) == []


# ---------------------------------------------------------------------------
# ESCALATION_PRIVILEGES constant
# ---------------------------------------------------------------------------


def test_escalation_privileges_set():
    assert "ALL_PRIVILEGES" in ESCALATION_PRIVILEGES
    assert "MANAGE" in ESCALATION_PRIVILEGES
    assert "SELECT" not in ESCALATION_PRIVILEGES
    assert "USE_CATALOG" not in ESCALATION_PRIVILEGES
