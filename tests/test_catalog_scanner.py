"""Tests for CatalogPermissionScanner."""

from databricks_group_audit.catalog_scanner import CatalogPermissionScanner, classify_catalog_grant
from databricks_group_audit._classification import classify_grant, build_member_lookups
from databricks_group_audit.group_resolver import GroupMembershipResolver
from databricks_group_audit.models import GrantSource, WorkspaceInfo
from tests.conftest import WORKSPACE_HOST


def _ws():
    return WorkspaceInfo(
        workspace_id="1", deployment_name="test-workspace",
        workspace_name="test-workspace", workspace_url=WORKSPACE_HOST,
        cloud="AZURE", region="eastus",
    )


# --- classify_grant tests (shared helper) ---

def test_classify_direct_grant():
    result = classify_grant(
        "data-engineers", "data-engineers", {}, set(), set(), set(), set(),
    )
    assert result is not None
    source, ptype, inherited, member = result
    assert source == GrantSource.DIRECT
    assert ptype == "GROUP"


def test_classify_upstream_grant():
    result = classify_grant(
        "all-data-team", "data-engineers",
        {"all-data-team": "group-parent"},
        set(), set(), set(), set(),
    )
    assert result is not None
    source, ptype, inherited, member = result
    assert source == GrantSource.UPSTREAM
    assert inherited == "all-data-team"


def test_classify_member_user_by_email():
    result = classify_grant(
        "alice@example.com", "data-engineers", {},
        {"alice@example.com"}, set(), set(), set(),
    )
    assert result is not None
    source, ptype, _, member = result
    assert source == GrantSource.MEMBER_DIRECT
    assert ptype == "USER"
    assert member is True


def test_classify_member_sp():
    result = classify_grant(
        "ETL-Bot", "data-engineers", {},
        set(), set(), {"ETL-Bot"}, set(),
    )
    assert result is not None
    source, ptype, _, _ = result
    assert source == GrantSource.MEMBER_DIRECT
    assert ptype == "SERVICE_PRINCIPAL"


def test_classify_unrelated_returns_none():
    result = classify_grant(
        "random-user@corp.com", "data-engineers", {},
        set(), set(), set(), set(),
    )
    assert result is None


def test_classify_backtick_principal():
    """Principals with backticks should be cleaned for matching."""
    result = classify_grant(
        "`Alice Smith`", "data-engineers", {},
        set(), {"Alice Smith"}, set(), set(),
    )
    assert result is not None
    assert result[1] == "USER"


# --- classify_catalog_grant wrapper ---

def test_classify_catalog_grant_returns_dataclass():
    g = classify_catalog_grant(
        "data-engineers", ["USE_CATALOG"], "main", _ws(),
        "data-engineers", {}, set(), set(), set(), set(),
    )
    assert g is not None
    assert g.grant_source == GrantSource.DIRECT
    assert g.catalog_name == "main"
    assert g.principal_type == "GROUP"


# --- build_member_lookups ---

def test_build_member_lookups(mock_scim):
    rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
    members = resolver.get_all_members_flat(node)
    emails, names, sp_names, sp_ids = build_member_lookups(members)
    assert "alice@example.com" in emails
    assert "Bob Jones" in names
    assert "ETL-Bot" in sp_names
    assert "app-etl-001" in sp_ids


# --- Recursive upstream detection ---

def test_upstream_finds_direct_parent(mock_uc):
    rsps, client = mock_uc
    resolver = GroupMembershipResolver(client)
    scanner = CatalogPermissionScanner(client, resolver)
    upstream = scanner.get_groups_containing_target("data-engineers")
    assert "all-data-team" in upstream


def test_upstream_finds_grandparent_recursively(mock_uc):
    """org-all contains all-data-team contains data-engineers.
    Both should appear as upstream groups.
    """
    rsps, client = mock_uc
    resolver = GroupMembershipResolver(client)
    scanner = CatalogPermissionScanner(client, resolver)
    upstream = scanner.get_groups_containing_target("data-engineers")
    assert "all-data-team" in upstream, "Direct parent should be found"
    assert "org-all" in upstream, "Grandparent should be found recursively"


def test_upstream_nonexistent_group(mock_uc):
    rsps, client = mock_uc
    resolver = GroupMembershipResolver(client)
    scanner = CatalogPermissionScanner(client, resolver)
    upstream = scanner.get_groups_containing_target("no-such-group")
    assert upstream == {}


# --- Workspace scanning ---

def test_scan_deduplicates_catalogs(mock_uc):
    rsps, client = mock_uc
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
    members = resolver.get_all_members_flat(node)
    scanner = CatalogPermissionScanner(client, resolver)
    ws = _ws()
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
