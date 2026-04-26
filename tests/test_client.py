"""Unit tests for DatabricksAPIClient internals (client.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from databricks_group_audit.client import TokenCache, _scim_filter_escape

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
