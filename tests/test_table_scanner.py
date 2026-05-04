"""Tests for TablePermissionScanner.scan_tables."""

import pytest
import responses as responses_lib

from databricks_access_audit.models import GrantSource, GroupMember, MemberType, WorkspaceInfo
from databricks_access_audit.table_scanner import TablePermissionScanner
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
    return TablePermissionScanner(client), rsps


def _table(name, ttype="MANAGED"):
    return {"name": name, "table_type": ttype}


# ---------------------------------------------------------------------------
# scan_tables — happy paths
# ---------------------------------------------------------------------------

def test_scan_tables_direct_group_grant(scanner):
    tbl, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/tables",
             json={"tables": [_table("events")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/table/main.bronze.events",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["SELECT", "MODIFY"]},
             ]})

    grants = tbl.scan_tables(_ws(), "main", "bronze", "data-engineers",
                             {"users": [], "service_principals": []}, {})
    assert len(grants) == 1
    g = grants[0]
    assert g.table_name == "events"
    assert g.full_name == "main.bronze.events"
    assert g.grant_source == GrantSource.DIRECT
    assert "SELECT" in g.privileges


def test_scan_tables_upstream_group_grant(scanner):
    tbl, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/tables",
             json={"tables": [_table("users")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/table/main.bronze.users",
             json={"privilege_assignments": [
                 {"principal": "all-data-team", "privileges": ["ALL_PRIVILEGES"]},
             ]})

    upstream = {"all-data-team": "group-parent"}
    grants = tbl.scan_tables(_ws(), "main", "bronze", "data-engineers",
                             {"users": [], "service_principals": []}, upstream)
    assert len(grants) == 1
    assert grants[0].grant_source == GrantSource.UPSTREAM
    assert grants[0].inherited_from == "all-data-team"


def test_scan_tables_member_user_grant(scanner):
    tbl, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/tables",
             json={"tables": [_table("events")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/table/main.bronze.events",
             json={"privilege_assignments": [
                 {"principal": "bob@example.com", "privileges": ["SELECT"]},
             ]})

    members = {"users": [_member("u2", "Bob Jones", "bob@example.com")],
               "service_principals": []}
    grants = tbl.scan_tables(_ws(), "main", "bronze", "data-engineers", members, {})
    assert len(grants) == 1
    assert grants[0].grant_source == GrantSource.MEMBER_DIRECT
    assert grants[0].member_of_target is True


def test_scan_tables_unrelated_principal_excluded(scanner):
    tbl, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/tables",
             json={"tables": [_table("events")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/table/main.bronze.events",
             json={"privilege_assignments": [
                 {"principal": "finance-team", "privileges": ["SELECT"]},
             ]})

    grants = tbl.scan_tables(_ws(), "main", "bronze", "data-engineers",
                             {"users": [], "service_principals": []}, {})
    assert grants == []


def test_scan_tables_empty_privileges_skipped(scanner):
    tbl, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/tables",
             json={"tables": [_table("events")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/table/main.bronze.events",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": []},
             ]})

    grants = tbl.scan_tables(_ws(), "main", "bronze", "data-engineers",
                             {"users": [], "service_principals": []}, {})
    assert grants == []


def test_scan_tables_table_type_preserved(scanner):
    tbl, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/tables",
             json={"tables": [_table("v_events", ttype="VIEW")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/table/main.bronze.v_events",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["SELECT"]},
             ]})

    grants = tbl.scan_tables(_ws(), "main", "bronze", "data-engineers",
                             {"users": [], "service_principals": []}, {})
    assert len(grants) == 1
    assert grants[0].table_type == "VIEW"


def test_scan_tables_multiple_tables(scanner):
    tbl, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/tables",
             json={"tables": [_table("t1"), _table("t2"), _table("t3")]})
    for t in ["t1", "t2", "t3"]:
        rsps.add(responses_lib.GET,
                 f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/table/main.bronze.{t}",
                 json={"privilege_assignments": [
                     {"principal": "data-engineers", "privileges": ["SELECT"]},
                 ]})

    grants = tbl.scan_tables(_ws(), "main", "bronze", "data-engineers",
                             {"users": [], "service_principals": []}, {})
    assert len(grants) == 3
    assert {g.table_name for g in grants} == {"t1", "t2", "t3"}


def test_scan_tables_api_error_returns_empty(scanner):
    tbl, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/tables", status=403)

    grants = tbl.scan_tables(_ws(), "main", "bronze", "data-engineers",
                             {"users": [], "service_principals": []}, {})
    assert grants == []


def test_scan_tables_grant_api_error_skips_table(scanner):
    tbl, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/tables",
             json={"tables": [_table("bad"), _table("good")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/table/main.bronze.bad",
             status=500)
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/table/main.bronze.good",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["SELECT"]},
             ]})

    grants = tbl.scan_tables(_ws(), "main", "bronze", "data-engineers",
                             {"users": [], "service_principals": []}, {})
    assert len(grants) == 1
    assert grants[0].table_name == "good"


def test_scan_tables_full_name_format(scanner):
    tbl, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/tables",
             json={"tables": [_table("daily_runs")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/table/staging.silver.daily_runs",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["SELECT"]},
             ]})

    grants = tbl.scan_tables(_ws(), "staging", "silver", "data-engineers",
                             {"users": [], "service_principals": []}, {})
    assert grants[0].catalog_name == "staging"
    assert grants[0].schema_name == "silver"
    assert grants[0].full_name == "staging.silver.daily_runs"
