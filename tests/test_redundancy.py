"""Tests for RedundancyDetector and privilege expansion."""

from databricks_group_audit.models import (
    CatalogGrant, GrantSource, RedundancyLevel,
)
from databricks_group_audit.redundancy import RedundancyDetector, expand_privileges


# ---------------------------------------------------------------------------
# expand_privileges
# ---------------------------------------------------------------------------

def test_expand_all_privileges():
    expanded = expand_privileges(["ALL_PRIVILEGES"])
    assert "USE_CATALOG" in expanded
    assert "SELECT" in expanded
    assert "MODIFY" in expanded
    assert "CREATE_SCHEMA" in expanded
    assert "ALL_PRIVILEGES" in expanded


def test_expand_modify_implies_select():
    expanded = expand_privileges(["MODIFY"])
    assert "SELECT" in expanded
    assert "MODIFY" in expanded


def test_expand_no_hierarchy():
    expanded = expand_privileges(["SELECT"])
    assert expanded == {"SELECT"}


# ---------------------------------------------------------------------------
# RedundancyDetector
# ---------------------------------------------------------------------------

def _grant(principal, privileges, source, catalog="main"):
    return CatalogGrant(
        catalog_name=catalog, workspace_name="ws", workspace_url="https://ws",
        principal=principal, principal_type="USER" if "@" in principal else "GROUP",
        privileges=privileges, grant_source=source,
        member_of_target=(source == GrantSource.MEMBER_DIRECT),
    )


def test_full_redundancy():
    grants = [
        _grant("data-engineers", ["ALL_PRIVILEGES"], GrantSource.DIRECT),
        _grant("alice@example.com", ["USE_CATALOG", "SELECT"], GrantSource.MEMBER_DIRECT),
    ]
    results = RedundancyDetector().detect_redundancy(grants, "data-engineers")

    assert len(results) == 1
    assert results[0].redundancy_level == RedundancyLevel.FULL
    assert set(results[0].redundant_privileges) == {"SELECT", "USE_CATALOG"}
    assert results[0].additional_privileges == []


def test_partial_redundancy():
    grants = [
        _grant("data-engineers", ["USE_CATALOG"], GrantSource.DIRECT),
        _grant("alice@example.com", ["USE_CATALOG", "MODIFY"], GrantSource.MEMBER_DIRECT),
    ]
    results = RedundancyDetector().detect_redundancy(grants, "data-engineers")

    assert len(results) == 1
    assert results[0].redundancy_level == RedundancyLevel.PARTIAL
    assert "USE_CATALOG" in results[0].redundant_privileges
    assert "MODIFY" in results[0].additional_privileges


def test_no_redundancy():
    grants = [
        _grant("data-engineers", ["USE_CATALOG"], GrantSource.DIRECT),
        _grant("alice@example.com", ["MODIFY"], GrantSource.MEMBER_DIRECT),
    ]
    results = RedundancyDetector().detect_redundancy(grants, "data-engineers")

    assert len(results) == 1
    # MODIFY implies SELECT, but group only has USE_CATALOG
    # So MODIFY itself is not in group effective -> None
    assert results[0].redundancy_level == RedundancyLevel.NONE


def test_upstream_privileges_counted():
    grants = [
        _grant("parent-group", ["ALL_PRIVILEGES"], GrantSource.UPSTREAM),
        _grant("alice@example.com", ["SELECT"], GrantSource.MEMBER_DIRECT),
    ]
    results = RedundancyDetector().detect_redundancy(grants, "data-engineers")

    assert len(results) == 1
    assert results[0].redundancy_level == RedundancyLevel.FULL


def test_no_member_grants_no_results():
    grants = [
        _grant("data-engineers", ["ALL_PRIVILEGES"], GrantSource.DIRECT),
    ]
    results = RedundancyDetector().detect_redundancy(grants, "data-engineers")
    assert len(results) == 0
