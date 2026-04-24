"""Tests for CatalogPermissionScanner and classify_grant."""

import responses as responses_lib

from databricks_group_audit.catalog_scanner import CatalogPermissionScanner, classify_catalog_grant
from databricks_group_audit._classification import classify_grant, build_member_lookups
from databricks_group_audit.group_resolver import GroupMembershipResolver
from databricks_group_audit.models import GrantSource, WorkspaceInfo
from tests.conftest import WORKSPACE_HOST


def _ws(url=WORKSPACE_HOST):
    host = url.replace("https://", "").split(".")[0]
    return WorkspaceInfo(
        workspace_id="1", deployment_name=host,
        workspace_name=host, workspace_url=url,
        cloud="AZURE", region="eastus",
    )


# ---------------------------------------------------------------------------
# classify_grant — normal cases
# ---------------------------------------------------------------------------

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
    result = classify_grant(
        "`Alice Smith`", "data-engineers", {},
        set(), {"Alice Smith"}, set(), set(),
    )
    assert result is not None
    assert result[1] == "USER"


# ---------------------------------------------------------------------------
# classify_grant — edge / corner cases
# ---------------------------------------------------------------------------

def test_classify_empty_principal_returns_none():
    assert classify_grant("", "data-engineers", {}, set(), set(), set(), set()) is None


def test_classify_whitespace_principal_returns_none():
    assert classify_grant("   ", "data-engineers", {}, set(), set(), set(), set()) is None


def test_classify_case_insensitive_email():
    """Azure AD sometimes normalises email casing differently across APIs."""
    result = classify_grant(
        "ALICE@EXAMPLE.COM", "data-engineers", {},
        {"alice@example.com"}, set(), set(), set(),
    )
    assert result is not None
    source, ptype, _, _ = result
    assert source == GrantSource.MEMBER_DIRECT
    assert ptype == "USER"


def test_classify_user_by_display_name():
    """Some setups grant using display name rather than email."""
    result = classify_grant(
        "Alice Smith", "data-engineers", {},
        set(), {"Alice Smith"}, set(), set(),
    )
    assert result is not None
    assert result[0] == GrantSource.MEMBER_DIRECT
    assert result[1] == "USER"


def test_classify_user_display_name_case_insensitive():
    result = classify_grant(
        "alice smith", "data-engineers", {},
        set(), {"Alice Smith"}, set(), set(),
    )
    assert result is not None
    assert result[0] == GrantSource.MEMBER_DIRECT


def test_classify_sp_by_app_id():
    result = classify_grant(
        "app-etl-001", "data-engineers", {},
        set(), set(), set(), {"app-etl-001"},
    )
    assert result is not None
    assert result[0] == GrantSource.MEMBER_DIRECT
    assert result[1] == "SERVICE_PRINCIPAL"


def test_classify_backtick_upstream():
    """Backtick-quoted upstream group name should still match."""
    result = classify_grant(
        "`all-data-team`", "data-engineers",
        {"all-data-team": "group-parent"},
        set(), set(), set(), set(),
    )
    assert result is not None
    assert result[0] == GrantSource.UPSTREAM


def test_classify_backtick_direct():
    result = classify_grant(
        "`data-engineers`", "data-engineers", {}, set(), set(), set(), set(),
    )
    assert result is not None
    assert result[0] == GrantSource.DIRECT


# ---------------------------------------------------------------------------
# classify_catalog_grant wrapper
# ---------------------------------------------------------------------------

def test_classify_catalog_grant_returns_dataclass():
    g = classify_catalog_grant(
        "data-engineers", ["USE_CATALOG"], "main", _ws(),
        "data-engineers", {}, set(), set(), set(), set(),
    )
    assert g is not None
    assert g.grant_source == GrantSource.DIRECT
    assert g.catalog_name == "main"
    assert g.principal_type == "GROUP"


# ---------------------------------------------------------------------------
# build_member_lookups
# ---------------------------------------------------------------------------

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


def test_build_member_lookups_empty():
    emails, names, sp_names, sp_ids = build_member_lookups({})
    assert emails == set()
    assert names == set()
    assert sp_names == set()
    assert sp_ids == set()


def test_build_member_lookups_user_no_email():
    from databricks_group_audit.models import GroupMember, MemberType
    u = GroupMember(id="u1", display_name="No Email User", member_type=MemberType.USER, email=None)
    emails, names, _, _ = build_member_lookups({"users": [u], "service_principals": []})
    assert "No Email User" in names
    assert len(emails) == 0


def test_build_member_lookups_sp_no_app_id():
    from databricks_group_audit.models import GroupMember, MemberType
    sp = GroupMember(id="sp1", display_name="Anon-SP", member_type=MemberType.SERVICE_PRINCIPAL,
                     application_id=None)
    _, _, sp_names, sp_ids = build_member_lookups({"users": [], "service_principals": [sp]})
    assert "Anon-SP" in sp_names
    assert len(sp_ids) == 0


# ---------------------------------------------------------------------------
# Upstream detection
# ---------------------------------------------------------------------------

def test_upstream_finds_direct_parent(mock_uc):
    rsps, client = mock_uc
    resolver = GroupMembershipResolver(client)
    scanner = CatalogPermissionScanner(client, resolver)
    upstream = scanner.get_groups_containing_target("data-engineers")
    assert "all-data-team" in upstream


def test_upstream_finds_grandparent_recursively(mock_uc):
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


# ---------------------------------------------------------------------------
# Workspace scanning — deduplication
# ---------------------------------------------------------------------------

def test_scan_deduplicates_catalogs_within_same_workspace(mock_uc):
    """Scanning the same workspace twice should not return grants on the second call."""
    rsps, client = mock_uc
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
    members = resolver.get_all_members_flat(node)
    scanner = CatalogPermissionScanner(client, resolver)
    ws = _ws()
    grants1 = scanner.scan_workspace(ws, "data-engineers", node, members)
    grants2 = scanner.scan_workspace(ws, "data-engineers", node, members)
    assert len(grants1) > 0
    assert len(grants2) == 0  # Same (workspace_url, catalog_name) already scanned


def test_scan_different_workspaces_same_catalog_name(mock_uc):
    """Same catalog name in two different workspaces must both be scanned.

    Unity Catalog catalogs are attached to a metastore, not a workspace.
    Two workspaces backed by different metastores can each have a catalog
    called 'main' with completely different grants — the scanner must not
    skip the second one just because it saw the name before.
    """
    rsps, client = mock_uc
    WS2 = "https://test-workspace-2.azuredatabricks.net"

    rsps.add(responses_lib.POST, f"{WS2}/oidc/v1/token",
             json={"access_token": "ws2-token", "expires_in": 3600})
    rsps.add(responses_lib.GET, f"{WS2}/api/2.1/unity-catalog/catalogs",
             json={"catalogs": [{"name": "main"}]})
    rsps.add(responses_lib.GET, f"{WS2}/api/2.1/unity-catalog/permissions/catalog/main",
             json={"privilege_assignments": [
                 {"principal": "data-engineers", "privileges": ["ALL_PRIVILEGES"]},
             ]})

    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
    members = resolver.get_all_members_flat(node)
    scanner = CatalogPermissionScanner(client, resolver)

    ws1 = _ws(WORKSPACE_HOST)
    ws2 = _ws(WS2)

    grants = scanner.scan_all_workspaces([ws1, ws2], "data-engineers", node, members)
    ws_urls = {g.workspace_url for g in grants}
    assert WORKSPACE_HOST in ws_urls, "Workspace 1 grants should be present"
    assert WS2 in ws_urls, "Workspace 2 grants for same-named catalog must not be skipped"


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
