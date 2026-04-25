"""Tests for StaleGrantChecker (system.access.audit cross-reference)."""

from __future__ import annotations

from datetime import date, timedelta
from unittest.mock import MagicMock

import pytest

from databricks_group_audit.models import CatalogGrant, GrantSource
from databricks_group_audit.stale_checker import StaleGrantChecker

# Dates relative to today so that active/stale classification stays correct
# regardless of when the test suite runs.
_TODAY = date.today().isoformat()
_RECENT = (date.today() - timedelta(days=10)).isoformat()   # within 90-day window
_OLD = (date.today() - timedelta(days=180)).isoformat()     # outside 90-day window

WS_URL = "https://adb-123.azuredatabricks.net"
WAREHOUSE_ID = "wh-abc123"


def _make_checker(ws_api_responses=None, stale_days=90, poll_interval=0.0,
                  max_lookback_days=0):
    """Return a StaleGrantChecker backed by a mock client."""
    client = MagicMock()
    if ws_api_responses is not None:
        client.workspace_api.side_effect = ws_api_responses
    checker = StaleGrantChecker(
        api_client=client,
        workspace_url=WS_URL,
        warehouse_id=WAREHOUSE_ID,
        stale_days=stale_days,
        poll_interval=poll_interval,
        max_lookback_days=max_lookback_days,
    )
    return checker, client


def _succeeded_response(rows=None, columns=None):
    """Build a SUCCEEDED Statement Execution API response."""
    cols = columns or ["principal", "last_seen_date"]
    return {
        "statement_id": "stmt-1",
        "status": {"state": "SUCCEEDED"},
        "manifest": {
            "schema": {
                "columns": [{"name": c} for c in cols],
            }
        },
        "result": {
            "data_array": rows or [],
        },
    }


def _member_grant(principal, principal_type="USER", catalog="main",
                  privileges=None):
    return CatalogGrant(
        catalog_name=catalog,
        workspace_name="prod",
        workspace_url=WS_URL,
        principal=principal,
        principal_type=principal_type,
        privileges=privileges or ["SELECT", "USE_CATALOG"],
        grant_source=GrantSource.MEMBER_DIRECT,
    )


def _group_grant(principal="data-engineers", catalog="main"):
    return CatalogGrant(
        catalog_name=catalog,
        workspace_name="prod",
        workspace_url=WS_URL,
        principal=principal,
        principal_type="GROUP",
        privileges=["ALL_PRIVILEGES"],
        grant_source=GrantSource.DIRECT,
    )


# ---------------------------------------------------------------------------
# _execute_statement — response parsing
# ---------------------------------------------------------------------------


def test_execute_statement_already_succeeded():
    resp = _succeeded_response(rows=[["alice@example.com", "2024-01-15"]])
    checker, client = _make_checker(ws_api_responses=[resp])

    rows = checker._execute_statement("SELECT 1")
    assert rows == [{"principal": "alice@example.com", "last_seen_date": "2024-01-15"}]


def test_execute_statement_polls_until_succeeded():
    running = {"statement_id": "stmt-1", "status": {"state": "RUNNING"}}
    succeeded = _succeeded_response(rows=[["bob@example.com", "2024-03-10"]])

    checker, client = _make_checker(
        ws_api_responses=[running, succeeded],
        poll_interval=0.0,
    )
    rows = checker._execute_statement("SELECT 1")
    assert rows == [{"principal": "bob@example.com", "last_seen_date": "2024-03-10"}]
    assert client.workspace_api.call_count == 2


def test_execute_statement_failed_raises():
    resp = {
        "statement_id": "stmt-1",
        "status": {"state": "FAILED", "error": {"message": "table not found"}},
    }
    checker, client = _make_checker(ws_api_responses=[resp])
    with pytest.raises(RuntimeError, match="table not found"):
        checker._execute_statement("SELECT 1")


def test_execute_statement_no_statement_id_raises():
    checker, client = _make_checker(ws_api_responses=[{}])
    with pytest.raises(RuntimeError, match="no statement_id"):
        checker._execute_statement("SELECT 1")


def test_execute_statement_api_error_raises():
    client = MagicMock()
    client.workspace_api.side_effect = RuntimeError("network error")
    checker = StaleGrantChecker(client, WS_URL, WAREHOUSE_ID, poll_interval=0.0)
    with pytest.raises(RuntimeError, match="network error"):
        checker._execute_statement("SELECT 1")


def test_execute_statement_empty_columns_returns_empty():
    resp = {
        "statement_id": "stmt-1",
        "status": {"state": "SUCCEEDED"},
        "manifest": {"schema": {"columns": []}},
        "result": {"data_array": [["alice@example.com"]]},
    }
    checker, client = _make_checker(ws_api_responses=[resp])
    assert checker._execute_statement("SELECT 1") == []


# ---------------------------------------------------------------------------
# get_active_principals
# ---------------------------------------------------------------------------


def test_get_active_principals_returns_set():
    resp = _succeeded_response(rows=[
        ["alice@example.com", _RECENT],
        ["sp-etl-bot", _RECENT],
    ])
    checker, _ = _make_checker(ws_api_responses=[resp])
    active = checker.get_active_principals()
    assert "alice@example.com" in active
    assert "sp-etl-bot" in active


def test_get_active_principals_case_insensitive():
    resp = _succeeded_response(rows=[["Alice@Example.COM", _RECENT]])
    checker, _ = _make_checker(ws_api_responses=[resp])
    active = checker.get_active_principals()
    # Both original and lowercased should be present
    assert "alice@example.com" in active


def test_get_active_principals_skips_null_principal():
    resp = _succeeded_response(rows=[[None, _RECENT], ["alice@example.com", _RECENT]])
    checker, _ = _make_checker(ws_api_responses=[resp])
    active = checker.get_active_principals()
    # None-principal row is skipped; alice@example.com (+ its lowercase) are present
    assert "alice@example.com" in active
    assert None not in active


def test_get_active_principals_excludes_old_activity():
    """Principals whose last activity predates the stale threshold are NOT active."""
    resp = _succeeded_response(rows=[["alice@example.com", _OLD]])
    checker, _ = _make_checker(ws_api_responses=[resp])
    active = checker.get_active_principals()
    assert "alice@example.com" not in active


# ---------------------------------------------------------------------------
# check_catalog_grants
# ---------------------------------------------------------------------------


def test_no_member_grants_returns_empty():
    checker, _ = _make_checker(ws_api_responses=[])
    grants = [_group_grant()]  # only group grant, no MEMBER_DIRECT
    assert checker.check_catalog_grants(grants, "prod", WS_URL) == []


def test_active_principal_not_stale():
    resp = _succeeded_response(rows=[["alice@example.com", _RECENT]])
    checker, _ = _make_checker(ws_api_responses=[resp])

    grants = [_member_grant("alice@example.com")]
    findings = checker.check_catalog_grants(grants, "prod", WS_URL)
    assert findings == []


def test_inactive_principal_flagged():
    resp = _succeeded_response(rows=[])  # no active principals
    checker, _ = _make_checker(ws_api_responses=[resp])

    grants = [_member_grant("bob@example.com")]
    findings = checker.check_catalog_grants(grants, "prod", WS_URL)
    assert len(findings) == 1
    assert findings[0].principal == "bob@example.com"
    assert findings[0].last_access is None
    assert findings[0].stale_days == 90


def test_stale_finding_carries_grant_metadata():
    resp = _succeeded_response(rows=[])
    checker, _ = _make_checker(ws_api_responses=[resp], stale_days=60)

    grants = [_member_grant("bob@example.com", catalog="staging",
                            privileges=["MODIFY"])]
    f = checker.check_catalog_grants(grants, "staging-ws", WS_URL)[0]
    assert f.catalog_name == "staging"
    assert f.privileges == ["MODIFY"]
    assert f.workspace_name == "staging-ws"
    assert f.stale_days == 60


def test_mixed_active_and_inactive():
    resp = _succeeded_response(rows=[["alice@example.com", _RECENT]])
    checker, _ = _make_checker(ws_api_responses=[resp])

    grants = [
        _member_grant("alice@example.com"),
        _member_grant("bob@example.com"),
    ]
    findings = checker.check_catalog_grants(grants, "prod", WS_URL)
    assert len(findings) == 1
    assert findings[0].principal == "bob@example.com"


def test_case_insensitive_match_prevents_false_stale():
    resp = _succeeded_response(rows=[["Alice@Example.COM", _RECENT]])
    checker, _ = _make_checker(ws_api_responses=[resp])

    grants = [_member_grant("alice@example.com")]
    # Case-insensitive match: alice@example.com should be considered active
    findings = checker.check_catalog_grants(grants, "prod", WS_URL)
    assert findings == []


def test_audit_query_error_returns_empty_stale():
    client = MagicMock()
    client.workspace_api.side_effect = RuntimeError("access denied")
    checker = StaleGrantChecker(client, WS_URL, WAREHOUSE_ID, poll_interval=0.0)

    grants = [_member_grant("alice@example.com")]
    # Error during query → no findings (conservative: don't flag stale on error)
    findings = checker.check_catalog_grants(grants, "prod", WS_URL)
    assert findings == []


def test_stale_principal_last_access_populated():
    """last_access is the ISO date from the audit log when the principal has
    some history but outside the stale threshold."""
    resp = _succeeded_response(rows=[["bob@example.com", _OLD]])
    checker, _ = _make_checker(ws_api_responses=[resp])

    grants = [_member_grant("bob@example.com")]
    findings = checker.check_catalog_grants(grants, "prod", WS_URL)
    assert len(findings) == 1
    assert findings[0].last_access == _OLD


def test_stale_principal_no_history_last_access_none():
    """last_access is None when the principal does not appear in the audit log
    at all (never seen within max_lookback_days)."""
    resp = _succeeded_response(rows=[])  # bob has no audit history
    checker, _ = _make_checker(ws_api_responses=[resp])

    grants = [_member_grant("bob@example.com")]
    findings = checker.check_catalog_grants(grants, "prod", WS_URL)
    assert len(findings) == 1
    assert findings[0].last_access is None


def test_max_lookback_days_default_is_at_least_stale_days():
    """Default max_lookback_days is ≥ stale_days (avoids missing recent history)."""
    checker, _ = _make_checker(stale_days=90)
    assert checker.max_lookback_days >= 90


def test_max_lookback_days_explicit_override():
    checker, _ = _make_checker(stale_days=30, max_lookback_days=180)
    assert checker.max_lookback_days == 180


def test_mixed_last_access_some_with_date_some_none():
    """alice has known old history; bob has no history at all."""
    resp = _succeeded_response(rows=[["alice@example.com", _OLD]])
    checker, _ = _make_checker(ws_api_responses=[resp])

    grants = [
        _member_grant("alice@example.com"),
        _member_grant("bob@example.com"),
    ]
    findings = checker.check_catalog_grants(grants, "prod", WS_URL)
    assert len(findings) == 2
    alice_f = next(f for f in findings if f.principal == "alice@example.com")
    bob_f = next(f for f in findings if f.principal == "bob@example.com")
    assert alice_f.last_access == _OLD
    assert bob_f.last_access is None


def test_sp_principal_type_preserved():
    resp = _succeeded_response(rows=[])
    checker, _ = _make_checker(ws_api_responses=[resp])

    grant = CatalogGrant(
        catalog_name="main", workspace_name="prod", workspace_url=WS_URL,
        principal="etl-bot", principal_type="SERVICE_PRINCIPAL",
        privileges=["USE_CATALOG"], grant_source=GrantSource.MEMBER_DIRECT,
    )
    findings = checker.check_catalog_grants([grant], "prod", WS_URL)
    assert findings[0].principal_type == "SERVICE_PRINCIPAL"
