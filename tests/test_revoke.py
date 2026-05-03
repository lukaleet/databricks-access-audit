"""Tests for RevokeScriptGenerator."""

import pytest

from databricks_access_audit.models import RedundancyLevel, RedundancyResult
from databricks_access_audit.revoke import RevokeScriptGenerator, _bt


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


# ---------------------------------------------------------------------------
# _bt helper
# ---------------------------------------------------------------------------

def test_bt_wraps_in_backticks():
    assert _bt("main") == "`main`"


def test_bt_escapes_embedded_backtick():
    assert _bt("foo`bar") == "`foo``bar`"


def test_bt_escapes_multiple_backticks():
    assert _bt("a`b`c") == "`a``b``c`"


def test_bt_plain_name_unchanged_content():
    assert _bt("data-engineers") == "`data-engineers`"


# ---------------------------------------------------------------------------
# RevokeScriptGenerator.generate
# ---------------------------------------------------------------------------

def test_full_redundancy_generates_revoke():
    results = [
        _result("alice@example.com", RedundancyLevel.FULL, redundant=["SELECT", "USE_CATALOG"])
    ]
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


def test_principal_with_hyphen_is_quoted():
    """Group names like 'data-engineers' need backtick quoting in SQL."""
    results = [_result("data-engineers", RedundancyLevel.FULL, redundant=["SELECT"])]
    sql = RevokeScriptGenerator.generate(results)
    assert "`data-engineers`" in sql


def test_principal_without_special_chars_still_quoted():
    """All principals are quoted unconditionally for consistency."""
    results = [_result("plaingroup", RedundancyLevel.FULL, redundant=["SELECT"])]
    sql = RevokeScriptGenerator.generate(results)
    assert "`plaingroup`" in sql


@pytest.mark.parametrize("principal", [
    "alice@example.com",
    "data-engineers",
    "sp.name",
    "John Doe",
    "group with spaces",
])
def test_principal_always_backtick_quoted(principal):
    results = [_result(principal, RedundancyLevel.FULL, redundant=["SELECT"])]
    sql = RevokeScriptGenerator.generate(results)
    assert f"`{principal}`" in sql


def test_principal_with_embedded_backtick_escaped():
    """A principal name containing a backtick produces valid SQL via doubling."""
    results = [_result("alice`s-bot", RedundancyLevel.FULL, redundant=["SELECT"])]
    sql = RevokeScriptGenerator.generate(results)
    # Escaped form: embedded ` becomes ``
    assert "`alice``s-bot`" in sql
    # The raw unescaped form must NOT appear (that would be broken SQL)
    assert "`alice`s-bot`" not in sql.replace("`alice``s-bot`", "")


def test_catalog_with_embedded_backtick_escaped():
    """A catalog name containing a backtick is safely escaped."""
    results = [_result("alice@example.com", RedundancyLevel.FULL,
                       catalog="cat`alog", redundant=["SELECT"])]
    sql = RevokeScriptGenerator.generate(results)
    assert "`cat``alog`" in sql
