"""Tests for CatalogPermissionScanner."""

from databricks_group_audit.catalog_scanner import CatalogPermissionScanner, classify_catalog_grant
from databricks_group_audit.group_resolver import GroupMembershipResolver
from databricks_group_audit.models import GrantSource, WorkspaceInfo
from tests.conftest import WORKSPACE_HOST


def _ws():
    return WorkspaceInfo(
        workspace_id="1", deployment_name="test-workspace",
        workspace_name="test-workspace", workspace_url=WORKSPACE_HOST,
        cloud="AZURE", region="eastus",
    )


def test_classify_direct_grant():
    g = classify_catalog_grant(
        "data-engineers", ["USE_CATALOG"], "main", _ws(),
        "data-engineers", {}, set(), set(), set(), set(),
    )
    assert g is not None
    assert g.grant_source == GrantSource.DIRECT
    assert g.principal_type == "GROUP"


def test_classify_upstream_grant():
    g = classify_catalog_grant(
        "all-data-team", ["ALL_PRIVILEGES"], "main", _ws(),
        "data-engineers", {"all-data-team": "group-parent"},
        set(), set(), set(), set(),
    )
    assert g is not None
    assert g.grant_source == GrantSource.UPSTREAM
    assert g.inherited_from == "all-data-team"


def test_classify_member_user_by_email():
    g = classify_catalog_grant(
        "alice@example.com", ["SELECT"], "main", _ws(),
        "data-engineers", {},
        {"alice@example.com"}, set(), set(), set(),
    )
    assert g is not None
    assert g.grant_source == GrantSource.MEMBER_DIRECT
    assert g.principal_type == "USER"


def test_classify_member_sp():
    g = classify_catalog_grant(
        "ETL-Bot", ["SELECT"], "main", _ws(),
        "data-engineers", {},
        set(), set(), {"ETL-Bot"}, set(),
    )
    assert g is not None
    assert g.grant_source == GrantSource.MEMBER_DIRECT
    assert g.principal_type == "SERVICE_PRINCIPAL"


def test_classify_unrelated_principal_returns_none():
    g = classify_catalog_grant(
        "random-user@corp.com", ["SELECT"], "main", _ws(),
        "data-engineers", {},
        set(), set(), set(), set(),
    )
    assert g is None


def test_scan_deduplicates_catalogs(mock_uc):
    rsps, client = mock_uc
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
    members = resolver.get_all_members_flat(node)

    scanner = CatalogPermissionScanner(client, resolver)
    ws = _ws()

    # Scan same workspace twice - catalogs should be deduplicated
    grants1 = scanner.scan_workspace(ws, "data-engineers", node, members)
    grants2 = scanner.scan_workspace(ws, "data-engineers", node, members)

    assert len(grants1) > 0
    assert len(grants2) == 0  # All catalogs already scanned


def test_scan_finds_all_grant_types(mock_uc):
    rsps, client = mock_uc
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
    members = resolver.get_all_members_flat(node)

    scanner = CatalogPermissionScanner(client, resolver)
    grants = scanner.scan_all_workspaces([_ws()], "data-engineers", node, members)

    sources = {g.grant_source for g in grants}
    assert GrantSource.DIRECT in sources
    assert GrantSource.UPSTREAM in sources
    assert GrantSource.MEMBER_DIRECT in sources
