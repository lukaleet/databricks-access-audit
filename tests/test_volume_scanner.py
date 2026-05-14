"""Tests for VolumePermissionScanner.scan_volumes."""

import pytest
import responses as responses_lib

from databricks_access_audit.models import (
    GrantSource,
    GroupMember,
    MemberType,
    VolumeGrant,
    WorkspaceInfo,
)
from databricks_access_audit.volume_scanner import VolumePermissionScanner
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
    return VolumePermissionScanner(client), rsps


def _vol(name):
    return {"name": name}


# ---------------------------------------------------------------------------
# scan_volumes — happy paths
# ---------------------------------------------------------------------------

def test_scan_volumes_direct_group_grant(scanner):
    vol, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"volumes": [_vol("raw_data")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/volume/main.bronze.raw_data",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["READ_VOLUME", "WRITE_VOLUME"]},
             ]})

    grants = vol.scan_volumes(_ws(), "main", "bronze", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert len(grants) == 1
    g = grants[0]
    assert g.volume_name == "raw_data"
    assert g.full_name == "main.bronze.raw_data"
    assert g.grant_source == GrantSource.DIRECT
    assert "READ_VOLUME" in g.privileges


def test_scan_volumes_upstream_group_grant(scanner):
    vol, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"volumes": [_vol("events")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/volume/main.bronze.events",
             json={"privilege_assignments": [
                 {"principal": "all-data-team", "privileges": ["ALL_PRIVILEGES"]},
             ]})

    upstream = {"all-data-team": "group-parent"}
    grants = vol.scan_volumes(_ws(), "main", "bronze", "data-engineers",
                              {"users": [], "service_principals": []}, upstream)
    assert len(grants) == 1
    assert grants[0].grant_source == GrantSource.UPSTREAM
    assert grants[0].inherited_from == "all-data-team"


def test_scan_volumes_member_user_grant(scanner):
    vol, rsps = scanner
    m = _member("u1", "Alice", "alice@example.com")
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"volumes": [_vol("files")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/volume/main.bronze.files",
             json={"privilege_assignments": [
                 {"principal": "alice@example.com", "privileges": ["READ_VOLUME"]},
             ]})

    grants = vol.scan_volumes(_ws(), "main", "bronze", "data-engineers",
                              {"users": [m], "service_principals": []}, {})
    assert len(grants) == 1
    assert grants[0].grant_source == GrantSource.MEMBER_DIRECT
    assert grants[0].principal == "alice@example.com"


def test_scan_volumes_unrelated_principal_excluded(scanner):
    vol, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"volumes": [_vol("raw")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/volume/main.bronze.raw",
             json={"privilege_assignments": [
                 {"principal": "other-group", "privileges": ["READ_VOLUME"]},
             ]})

    grants = vol.scan_volumes(_ws(), "main", "bronze", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert grants == []


def test_scan_volumes_empty_privileges_skipped(scanner):
    vol, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"volumes": [_vol("raw")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/volume/main.bronze.raw",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": []},
             ]})

    grants = vol.scan_volumes(_ws(), "main", "bronze", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert grants == []


def test_scan_volumes_multiple_volumes(scanner):
    vol, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"volumes": [_vol("vol_a"), _vol("vol_b")]})
    for vname in ["vol_a", "vol_b"]:
        rsps.add(responses_lib.GET,
                 f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/volume/main.bronze.{vname}",
                 json={"privilege_assignments": [
                     {"principal": "data-engineers", "privileges": ["READ_VOLUME"]},
                 ]})

    grants = vol.scan_volumes(_ws(), "main", "bronze", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert len(grants) == 2
    names = {g.volume_name for g in grants}
    assert names == {"vol_a", "vol_b"}


def test_scan_volumes_api_error_on_list_returns_empty(scanner):
    vol, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"error": "forbidden"}, status=403)

    grants = vol.scan_volumes(_ws(), "main", "bronze", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert grants == []


def test_scan_volumes_api_error_on_grants_skips_volume(scanner):
    vol, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"volumes": [_vol("raw")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/volume/main.bronze.raw",
             json={"error": "forbidden"}, status=403)

    grants = vol.scan_volumes(_ws(), "main", "bronze", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert grants == []


def test_scan_volumes_full_name_format(scanner):
    vol, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"volumes": [_vol("my_vol")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/volume/prod.silver.my_vol",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["READ_VOLUME"]},
             ]})

    grants = vol.scan_volumes(_ws(), "prod", "silver", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert grants[0].full_name == "prod.silver.my_vol"
    assert grants[0].catalog_name == "prod"
    assert grants[0].schema_name == "silver"


def test_scan_volumes_no_table_type_field(scanner):
    """VolumeGrant has no table_type field — volumes are not tables."""
    vol, rsps = scanner
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"volumes": [_vol("v1")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/volume/main.bronze.v1",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["READ_VOLUME"]},
             ]})

    grants = vol.scan_volumes(_ws(), "main", "bronze", "data-engineers",
                              {"users": [], "service_principals": []}, {})
    assert isinstance(grants[0], VolumeGrant)
    assert not hasattr(grants[0], "table_type")


def test_scan_volumes_sp_grant(scanner):
    vol, rsps = scanner
    sp = _sp("sp1", "etl-bot", app_id="app-123")
    rsps.add(responses_lib.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/volumes",
             json={"volumes": [_vol("raw")]})
    rsps.add(responses_lib.GET,
             f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/volume/main.bronze.raw",
             json={"privilege_assignments": [
                 {"principal": "app-123", "privileges": ["READ_VOLUME"]},
             ]})

    grants = vol.scan_volumes(_ws(), "main", "bronze", "data-engineers",
                              {"users": [], "service_principals": [sp]}, {})
    assert len(grants) == 1
    assert grants[0].grant_source == GrantSource.MEMBER_DIRECT
    assert grants[0].principal_type == "SERVICE_PRINCIPAL"
