"""Tests for SchemaPermissionScanner.scan_schemas and get_schemas."""

import pytest
import responses as responses_lib

from databricks_access_audit.models import GrantSource, GroupMember, MemberType, WorkspaceInfo
from databricks_access_audit.schema_scanner import SchemaPermissionScanner
from tests.conftest import WORKSPACE_HOST


def _ws(url=WORKSPACE_HOST):
    return WorkspaceInfo(
        workspace_id="1", deployment_name="test-workspace",
        workspace_name="test-workspace", workspace_url=url,
        cloud="AZURE", region="eastus",
    )


def _member(uid, display, email):
    return GroupMember(id=uid, display_name=display, member_type=MemberType.USER, email=email)


def _sp(sid, display, app_id=None):
    return GroupMember(id=sid, display_name=display,
                       member_type=MemberType.SERVICE_PRINCIPAL, application_id=app_id)


@pytest.fixture
def scanner(mock_uc):
    rsps, client = mock_uc
    return SchemaPermissionScanner(client), rsps


# ---------------------------------------------------------------------------
# get_schemas
# ---------------------------------------------------------------------------

def test_get_schemas_returns_list(scanner):
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas",
             json={"schemas": [{"name": "bronze"}, {"name": "silver"}]})
    result = sch.get_schemas(_ws(), "main")
    names = [s["name"] for s in result]
    assert names == ["bronze", "silver"]


def test_get_schemas_returns_empty_on_error(scanner):
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas", status=403)
    assert sch.get_schemas(_ws(), "restricted") == []


# ---------------------------------------------------------------------------
# scan_schemas — grant classification
# ---------------------------------------------------------------------------

def test_scan_schemas_direct_group_grant(scanner):
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas",
             json={"schemas": [{"name": "bronze"}]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.bronze",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["USE_SCHEMA", "SELECT"]},
             ]})

    grants = sch.scan_schemas(_ws(), "main", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert len(grants) == 1
    g = grants[0]
    assert g.schema_name == "bronze"
    assert g.grant_source == GrantSource.DIRECT
    assert "USE_SCHEMA" in g.privileges


def test_scan_schemas_upstream_group_grant(scanner):
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas",
             json={"schemas": [{"name": "silver"}]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.silver",
             json={"privilege_assignments": [
                 {"principal": "all-data-team", "privileges": ["ALL_PRIVILEGES"]},
             ]})

    upstream = {"all-data-team": "group-parent"}
    grants = sch.scan_schemas(_ws(), "main", "data-engineers",
                              {"users": [], "service_principals": []}, upstream)
    assert len(grants) == 1
    assert grants[0].grant_source == GrantSource.UPSTREAM
    assert grants[0].inherited_from == "all-data-team"


def test_scan_schemas_member_user_email_grant(scanner):
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas",
             json={"schemas": [{"name": "gold"}]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.gold",
             json={"privilege_assignments": [
                 {"principal": "alice@example.com", "privileges": ["SELECT"]},
             ]})

    members = {"users": [_member("u1", "Alice", "alice@example.com")],
               "service_principals": []}
    grants = sch.scan_schemas(_ws(), "main", "data-engineers", members, {})
    assert len(grants) == 1
    assert grants[0].grant_source == GrantSource.MEMBER_DIRECT
    assert grants[0].member_of_target is True


def test_scan_schemas_unrelated_principal_excluded(scanner):
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas",
             json={"schemas": [{"name": "bronze"}]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.bronze",
             json={"privilege_assignments": [
                 {"principal": "some-other-team", "privileges": ["SELECT"]},
             ]})

    grants = sch.scan_schemas(_ws(), "main", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert grants == []


def test_scan_schemas_empty_privileges_skipped(scanner):
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas",
             json={"schemas": [{"name": "bronze"}]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.bronze",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": []},
             ]})

    grants = sch.scan_schemas(_ws(), "main", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert grants == []


def test_scan_schemas_multiple_schemas_and_grants(scanner):
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas",
             json={"schemas": [{"name": "a"}, {"name": "b"}]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.a",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["USE_SCHEMA"]},
             ]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.b",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["SELECT"]},
                 {"principal": "alice@example.com", "privileges": ["SELECT"]},
             ]})

    members = {"users": [_member("u1", "Alice", "alice@example.com")],
               "service_principals": []}
    grants = sch.scan_schemas(_ws(), "main", "data-engineers", members, {})
    assert len(grants) == 3
    schemas = {g.schema_name for g in grants}
    assert schemas == {"a", "b"}


def test_scan_schemas_api_error_on_grants_skips_schema(scanner):
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas",
             json={"schemas": [{"name": "broken"}, {"name": "ok"}]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.broken",
             status=500)
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.ok",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["USE_SCHEMA"]},
             ]})

    grants = sch.scan_schemas(_ws(), "main", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert len(grants) == 1
    assert grants[0].schema_name == "ok"


def test_scan_schemas_sp_by_display_name(scanner):
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas",
             json={"schemas": [{"name": "bronze"}]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.bronze",
             json={"privilege_assignments": [
                 {"principal": "ETL-Bot", "privileges": ["USE_SCHEMA"]},
             ]})

    members = {"users": [], "service_principals": [_sp("sp1", "ETL-Bot", "app-001")]}
    grants = sch.scan_schemas(_ws(), "main", "data-engineers", members, {})
    assert len(grants) == 1
    assert grants[0].grant_source == GrantSource.MEMBER_DIRECT
    assert grants[0].principal_type == "SERVICE_PRINCIPAL"


def test_scan_schemas_workspace_name_propagated(scanner):
    """workspace_name in SchemaGrant must match the WorkspaceInfo passed in.

    The CLI builds a stub WorkspaceInfo with the correct workspace_name from a
    URL→name mapping; this test verifies that the scanner faithfully carries it
    through to the grant objects (so CSV and snapshot output are correct).
    """
    sch, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/schemas",
             json={"schemas": [{"name": "bronze"}]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/schema/main.bronze",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["USE_SCHEMA"]},
             ]})

    ws = WorkspaceInfo("1", "test-ws", "prod-workspace", WORKSPACE_HOST, "AZURE", "eastus")
    grants = sch.scan_schemas(ws, "main", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert len(grants) == 1
    assert grants[0].workspace_name == "prod-workspace"
