"""Tests for GroupMembershipResolver."""

from unittest.mock import MagicMock, patch

from databricks_group_audit.client import _scim_filter_escape
from databricks_group_audit.group_resolver import GroupMembershipResolver
from databricks_group_audit.models import MemberType

# ---------------------------------------------------------------------------
# _scim_filter_escape — unit tests
# ---------------------------------------------------------------------------


def test_scim_filter_escape_plain_string():
    assert _scim_filter_escape("data-engineers") == "data-engineers"


def test_scim_filter_escape_double_quote():
    assert _scim_filter_escape('group"with"quotes') == 'group\\"with\\"quotes'


def test_scim_filter_escape_backslash():
    assert _scim_filter_escape("back\\slash") == "back\\\\slash"


def test_scim_filter_escape_both():
    assert _scim_filter_escape('back\\"slash') == 'back\\\\\\"slash'


def test_scim_filter_escape_empty():
    assert _scim_filter_escape("") == ""


def test_resolve_group_finds_direct_members(mock_scim):
    _rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")

    assert node is not None
    assert node.display_name == "data-engineers"
    assert len(node.direct_users) == 2
    assert len(node.direct_service_principals) == 1


def test_resolve_group_walks_nested_groups(mock_scim):
    _rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")

    assert len(node.nested_groups) == 1
    nested = list(node.nested_groups.values())[0]
    assert nested.display_name == "data-analysts"
    assert len(nested.direct_users) == 1
    assert nested.direct_users[0].display_name == "Charlie Brown"


def test_flat_members_deduplicates(mock_scim):
    _rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
    members = resolver.get_all_members_flat(node)

    # 2 direct users + 1 from nested group = 3 unique users
    assert len(members["users"]) == 3
    assert len(members["service_principals"]) == 1

    user_names = {u.display_name for u in members["users"]}
    assert "Alice Smith" in user_names
    assert "Charlie Brown" in user_names


def test_resolve_nonexistent_group(mock_scim):
    rsps, client = mock_scim
    # Override the group listing to return empty for a specific filter
    import responses as _r
    rsps.replace(
        _r.GET,
        "https://accounts.azuredatabricks.net/api/2.0/accounts/test-account-id/scim/v2/Groups",
        json={"Resources": [], "totalResults": 0},
    )
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("nonexistent-group")
    assert node is None


def test_member_types_are_correct(mock_scim):
    _rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
    members = resolver.get_all_members_flat(node)

    for u in members["users"]:
        assert u.member_type == MemberType.USER
    for sp in members["service_principals"]:
        assert sp.member_type == MemberType.SERVICE_PRINCIPAL
        assert sp.application_id is not None


def test_membership_paths_are_populated(mock_scim):
    _rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
    members = resolver.get_all_members_flat(node)

    alice = [u for u in members["users"] if "Alice" in u.display_name][0]
    assert alice.parent_groups == ["data-engineers"]

    charlie = [u for u in members["users"] if "Charlie" in u.display_name][0]
    assert charlie.parent_groups == ["data-engineers", "data-analysts"]


# ---------------------------------------------------------------------------
# get_group_membership_map — correctness, caching, parallel fetch
# ---------------------------------------------------------------------------

def test_get_group_membership_map_returns_all_groups(mock_scim):
    """id_to_name contains every group returned by scim_list_all."""
    _rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)
    id_to_name, _, _ = resolver.get_group_membership_map()

    assert "group-1" in id_to_name
    assert id_to_name["group-1"] == "data-engineers"
    assert "group-2" in id_to_name
    assert id_to_name["group-2"] == "data-analysts"
    assert "group-parent" in id_to_name
    assert id_to_name["group-parent"] == "all-data-team"


def test_get_group_membership_map_builds_child_to_parents(mock_scim):
    """child_to_parents reflects actual group membership from individual GETs."""
    _rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)
    _, _, child_to_parents = resolver.get_group_membership_map()

    # data-engineers (group-1) is a member of all-data-team (group-parent)
    assert "group-parent" in child_to_parents.get("group-1", set())
    # all-data-team (group-parent) is a member of org-all (group-grandparent)
    assert "group-grandparent" in child_to_parents.get("group-parent", set())


def test_get_group_membership_map_cached_on_second_call(mock_scim):
    """Second call returns the cached result without additional API requests."""
    rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)

    result_first = resolver.get_group_membership_map()
    calls_after_first = len(rsps.calls)

    result_second = resolver.get_group_membership_map()
    assert len(rsps.calls) == calls_after_first  # no new HTTP calls
    assert result_first is result_second          # exact same object


def test_get_group_membership_map_warms_group_cache(mock_scim):
    """Parallel fetch also populates _group_cache so _get_group_by_id hits it."""
    _rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)
    resolver.get_group_membership_map()

    # _group_cache should now hold all four groups
    assert "group-1" in resolver._group_cache
    assert "group-parent" in resolver._group_cache


def test_clear_caches_resets_group_membership_map(mock_scim):
    """clear_caches() forces a full re-fetch on the next call."""
    rsps, client = mock_scim
    resolver = GroupMembershipResolver(client)

    resolver.get_group_membership_map()
    calls_after_first = len(rsps.calls)

    resolver.clear_caches()
    assert resolver._group_membership_map_cache is None

    resolver.get_group_membership_map()
    assert len(rsps.calls) > calls_after_first  # re-fetched


def test_get_group_membership_map_empty_account():
    """An account with no groups returns three empty dicts."""
    client = MagicMock()
    client.scim_list_all.return_value = []
    resolver = GroupMembershipResolver(client)

    id_to_name, id_to_external, child_to_parents = resolver.get_group_membership_map()

    assert id_to_name == {}
    assert id_to_external == {}
    assert child_to_parents == {}
    # account_api should never be called when there are no groups to fetch
    client.account_api.assert_not_called()


def test_get_group_membership_map_individual_get_error_is_skipped():
    """A failed individual GET is silently skipped; the rest still process."""
    client = MagicMock()
    client.scim_list_all.return_value = [
        {"id": "g1", "displayName": "good-group"},
        {"id": "g2", "displayName": "bad-group"},
    ]

    def _side_effect(method, endpoint):
        if "g2" in endpoint:
            raise RuntimeError("simulated 500")
        return {"id": "g1", "displayName": "good-group", "members": [
            {"value": "u1"},
        ]}

    client.account_api.side_effect = _side_effect
    resolver = GroupMembershipResolver(client)
    id_to_name, _, child_to_parents = resolver.get_group_membership_map()

    # Both groups are in the name map (from the list call)
    assert "g1" in id_to_name
    assert "g2" in id_to_name
    # Only the successful GET contributed to child_to_parents
    assert "g1" in child_to_parents.get("u1", set())


# ---------------------------------------------------------------------------
# PrincipalAuditor — shared resolver integration
# ---------------------------------------------------------------------------

def test_principal_auditor_accepts_shared_group_resolver(mock_client):
    """PrincipalAuditor stores a provided group_resolver instead of creating its own."""
    from databricks_group_audit.principal_auditor import PrincipalAuditor

    resolver = GroupMembershipResolver(mock_client)
    auditor = PrincipalAuditor(mock_client, group_resolver=resolver)

    assert auditor._group_resolver is resolver


def test_principal_auditor_creates_resolver_when_none_provided(mock_client):
    """PrincipalAuditor creates its own GroupMembershipResolver when none is passed."""
    from databricks_group_audit.principal_auditor import PrincipalAuditor

    auditor = PrincipalAuditor(mock_client)

    assert isinstance(auditor._group_resolver, GroupMembershipResolver)


def test_shared_resolver_group_map_fetched_once(mock_scim):
    """When resolver is shared between CatalogPermissionScanner and PrincipalAuditor,
    the group membership map API calls happen exactly once."""
    rsps, client = mock_scim
    from databricks_group_audit.catalog_scanner import CatalogPermissionScanner
    from databricks_group_audit.principal_auditor import PrincipalAuditor

    resolver = GroupMembershipResolver(client)
    _scanner = CatalogPermissionScanner(client, resolver)
    _auditor = PrincipalAuditor(client, group_resolver=resolver)

    # First caller fetches and caches
    resolver.get_group_membership_map()
    calls_after_first = len(rsps.calls)

    # Second caller hits cache — no new API calls
    resolver.get_group_membership_map()
    assert len(rsps.calls) == calls_after_first
