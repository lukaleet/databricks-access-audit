"""Unit tests for DatabricksAPIClient internals (client.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import responses

from databricks_access_audit.client import DatabricksAPIClient, TokenCache, _scim_filter_escape

_WS_HOST = "https://adb-123.9.azuredatabricks.net"
_INVALID_CLIENT_BODY = {
    "error": "invalid_client",
    "error_description": "Client authentication failed",
}

# ---------------------------------------------------------------------------
# TokenCache
# ---------------------------------------------------------------------------


class TestTokenCache:
    def test_empty_cache_returns_none(self):
        cache = TokenCache()
        assert cache.get_token() is None

    def test_valid_token_returned(self):
        cache = TokenCache()
        cache.set_token("tok-abc", expires_in=3600)
        assert cache.get_token() == "tok-abc"

    def test_expired_token_returns_none(self):
        cache = TokenCache()
        cache.set_token("tok-abc", expires_in=3600)
        # Wind the expiry into the past.
        cache.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert cache.get_token() is None

    def test_set_token_uses_utc(self):
        """expires_at must be timezone-aware (UTC) so comparisons are unambiguous."""
        cache = TokenCache()
        cache.set_token("tok", expires_in=3600)
        assert cache.expires_at is not None
        assert cache.expires_at.tzinfo is not None, (
            "expires_at must be timezone-aware; got naive datetime"
        )

    def test_minimum_expiry_floor(self):
        """expires_in values ≤ 60 s are floored to 10 s to avoid immediate expiry."""
        cache = TokenCache()
        before = datetime.now(timezone.utc)
        cache.set_token("tok", expires_in=30)  # 30 - 60 = -30 → floored to 10
        assert cache.expires_at >= before + timedelta(seconds=9)

    def test_token_replaced_on_second_set(self):
        cache = TokenCache()
        cache.set_token("first", expires_in=3600)
        cache.set_token("second", expires_in=3600)
        assert cache.get_token() == "second"

    def test_thread_safe_concurrent_reads(self):
        """Multiple threads reading a valid token must all get the same value."""
        import threading

        cache = TokenCache()
        cache.set_token("shared-tok", expires_in=3600)
        results = []
        errors = []

        def read():
            try:
                results.append(cache.get_token())
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=read) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert all(r == "shared-tok" for r in results)


# ---------------------------------------------------------------------------
# _scim_filter_escape (re-tested here for completeness; primary tests in
# test_group_resolver.py)
# ---------------------------------------------------------------------------


def test_scim_filter_escape_backslash_then_quote():
    """Input containing both \\ and \" must escape backslash first."""
    # Input chars: a \ " b  →  expected filter chars: a \\ \" b
    assert _scim_filter_escape('a\\"b') == 'a\\\\\\"b'


# ---------------------------------------------------------------------------
# _get_workspace_token — post-elevation invalid_client retry
# ---------------------------------------------------------------------------

def _make_ws_client() -> DatabricksAPIClient:
    return DatabricksAPIClient(
        client_id="sp-id",
        client_secret="sp-secret",
        account_id="acct-1",
        account_host="https://accounts.azuredatabricks.net",
        base_delay=1.0,
        max_delay=30.0,
    )


@responses.activate
def test_workspace_token_succeeds_immediately():
    """Happy path: workspace OIDC returns a token on the first call."""
    responses.add(
        responses.POST, f"{_WS_HOST}/oidc/v1/token",
        json={"access_token": "tok-ok", "expires_in": 3600},
    )
    client = _make_ws_client()
    assert client._get_workspace_token(_WS_HOST) == "tok-ok"


_ACCOUNT_HOST = "https://accounts.azuredatabricks.net"
_ACCOUNT_ID = "acct-1"
_ACCOUNT_TOKEN_URL = f"{_ACCOUNT_HOST}/oidc/accounts/{_ACCOUNT_ID}/v1/token"


@responses.activate
def test_workspace_token_falls_back_to_account_token_on_invalid_client():
    """invalid_client from workspace OIDC → immediate fallback to account token."""
    responses.add(
        responses.POST, f"{_WS_HOST}/oidc/v1/token",
        json=_INVALID_CLIENT_BODY, status=400,
    )
    responses.add(
        responses.POST, _ACCOUNT_TOKEN_URL,
        json={"access_token": "acct-tok", "expires_in": 3600},
    )
    client = _make_ws_client()
    token = client._get_workspace_token(_WS_HOST)
    assert token == "acct-tok"
    # Only one workspace OIDC attempt — no retries/sleep
    ws_calls = [c for c in responses.calls if _WS_HOST in c.request.url]
    assert len(ws_calls) == 1


@responses.activate
def test_workspace_token_fallback_is_cached():
    """Account-token fallback is cached; second call does not hit OIDC again."""
    responses.add(
        responses.POST, f"{_WS_HOST}/oidc/v1/token",
        json=_INVALID_CLIENT_BODY, status=400,
    )
    responses.add(
        responses.POST, _ACCOUNT_TOKEN_URL,
        json={"access_token": "acct-tok", "expires_in": 3600},
    )
    client = _make_ws_client()
    t1 = client._get_workspace_token(_WS_HOST)
    t2 = client._get_workspace_token(_WS_HOST)
    assert t1 == t2 == "acct-tok"
    assert len(responses.calls) == 2  # workspace OIDC + account OIDC, not three


@responses.activate
def test_workspace_token_raises_on_non_invalid_client_400():
    """Non-invalid_client 400 errors (e.g. invalid_grant) are raised immediately."""
    responses.add(
        responses.POST, f"{_WS_HOST}/oidc/v1/token",
        json={"error": "invalid_grant", "error_description": "Bad credentials"}, status=400,
    )
    client = _make_ws_client()
    with pytest.raises(Exception):
        client._get_workspace_token(_WS_HOST)
    assert len(responses.calls) == 1


@responses.activate
def test_workspace_token_cached_after_success():
    """After a successful OIDC call the token is cached; second call skips OIDC."""
    responses.add(
        responses.POST, f"{_WS_HOST}/oidc/v1/token",
        json={"access_token": "cached-tok", "expires_in": 3600},
    )
    client = _make_ws_client()
    t1 = client._get_workspace_token(_WS_HOST)
    t2 = client._get_workspace_token(_WS_HOST)
    assert t1 == t2 == "cached-tok"
    assert len(responses.calls) == 1
