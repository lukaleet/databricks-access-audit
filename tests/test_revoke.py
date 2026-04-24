"""Tests for RevokeScriptGenerator."""

from databricks_group_audit.models import RedundancyLevel, RedundancyResult
from databricks_group_audit.revoke import RevokeScriptGenerator


def _result(principal, level, catalog="main", redundant=None, additional=None):
    return RedundancyResult(
        catalog_name=catalog,
        principal=principal,
        principal_type="USER",
        member_privileges=redundant or [],
        group_effective_privileges=[],
        redundant_privileges=redundant or [],
        additional_privileges=additional or [],
        redundancy_level=level,
        recommendation="",
    )


def test_full_redundancy_generates_revoke():
    results = [_result("alice@example.com", RedundancyLevel.FULL, redundant=["SELECT", "USE_CATALOG"])]
    sql = RevokeScriptGenerator.generate(results)

    assert "REVOKE SELECT, USE_CATALOG ON CATALOG `main`" in sql
    assert "`alice@example.com`" in sql


def test_partial_redundancy_commented_out_by_default():
    results = [_result("bob@example.com", RedundancyLevel.PARTIAL,
                       redundant=["SELECT"], additional=["MODIFY"])]
    sql = RevokeScriptGenerator.generate(results, include_partial=False)
    assert "REVOKE" not in sql or "No redundant grants" in sql


def test_partial_redundancy_included_when_requested():
    results = [_result("bob@example.com", RedundancyLevel.PARTIAL,
                       redundant=["SELECT"], additional=["MODIFY"])]
    sql = RevokeScriptGenerator.generate(results, include_partial=True)
    assert "-- REVOKE SELECT ON CATALOG `main`" in sql


def test_no_results_clean_message():
    sql = RevokeScriptGenerator.generate([])
    assert "No redundant grants" in sql


def test_principal_with_spaces_is_quoted():
    results = [_result("John Doe", RedundancyLevel.FULL, redundant=["SELECT"])]
    sql = RevokeScriptGenerator.generate(results)
    assert "`John Doe`" in sql
