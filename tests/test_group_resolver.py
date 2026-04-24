"""Tests for GroupMembershipResolver."""

from databricks_group_audit.group_resolver import GroupMembershipResolver
from databricks_group_audit.models import MemberType


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
