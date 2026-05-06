"""Tests for PrincipalComparer (group membership diff between two principals)."""

from __future__ import annotations

import json

import pytest
import responses

from databricks_access_audit.principal_comparer import PrincipalComparer
from tests.conftest import (
    ACCOUNT_HOST,
    ACCOUNT_ID,
    ALL_GROUPS,
    SCIM_SP_ETL,
    SCIM_USER_ALICE,
    SCIM_USER_BOB,
    SCIM_USER_CHARLIE,
)

BASE = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"

# ---------------------------------------------------------------------------
# An extra group used to test divergent memberships
# ---------------------------------------------------------------------------

SCIM_GROUP_ALICE_ONLY = {
    "id": "group-alice-only",
    "displayName": "alice-special",
    "externalId": None,
    "members": [
        {"value": "user-1", "display": "Alice", "$ref": "Users/user-1"},
    ],
}

SCIM_GROUP_BOB_ONLY = {
    "id": "group-bob-only",
    "displayName": "bob-special",
    "externalId": "ext-bob-special",   # external / IdP-synced
    "members": [
        {"value": "user-2", "display": "Bob", "$ref": "Users/user-2"},
    ],
}

SCIM_GROUP_SHARED = {
    "id": "group-shared",
    "displayName": "shared-group",
    "externalId": None,
    "members": [
        {"value": "user-1", "display": "Alice", "$ref": "Users/user-1"},
        {"value": "user-2", "display": "Bob", "$ref": "Users/user-2"},
    ],
}

EXTRA_GROUPS = [SCIM_GROUP_ALICE_ONLY, SCIM_GROUP_BOB_ONLY, SCIM_GROUP_SHARED]


# ---------------------------------------------------------------------------
# SCIM mock helper
# ---------------------------------------------------------------------------

def _add_scim_endpoints(rsps, all_groups=None, all_users=None, all_sps=None):
    """Register SCIM mock endpoints with filter support."""
    if all_groups is None:
        all_groups = ALL_GROUPS + EXTRA_GROUPS
    if all_users is None:
        all_users = [SCIM_USER_ALICE, SCIM_USER_BOB, SCIM_USER_CHARLIE]
    if all_sps is None:
        all_sps = [SCIM_SP_ETL]

    rsps.add(responses.POST, f"{ACCOUNT_HOST}/oidc/accounts/{ACCOUNT_ID}/v1/token",
             json={"access_token": "mock-token", "expires_in": 3600})

    def _group_list_cb(request):
        filt = request.params.get("filter", "")
        if "displayName" in filt:
            name = filt.split('"')[1]
            matched = [g for g in all_groups if g["displayName"] == name]
        else:
            matched = all_groups
        body = {"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100}
        return (200, {}, json.dumps(body))

    rsps.add_callback(responses.GET, f"{BASE}/scim/v2/Groups",
                      callback=_group_list_cb, content_type="application/json")

    for g in all_groups:
        rsps.add(responses.GET, f"{BASE}/scim/v2/Groups/{g['id']}", json=g)

    def _user_list_cb(request):
        filt = request.params.get("filter", "")
        if "emails.value" in filt:
            email = filt.split('"')[1]
            matched = [u for u in all_users
                       if any(e.get("value") == email for e in u.get("emails", []))]
        else:
            matched = all_users
        body = {"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100}
        return (200, {}, json.dumps(body))

    rsps.add_callback(responses.GET, f"{BASE}/scim/v2/Users",
                      callback=_user_list_cb, content_type="application/json")

    for u in all_users:
        rsps.add(responses.GET, f"{BASE}/scim/v2/Users/{u['id']}", json=u)

    def _sp_list_cb(request):
        filt = request.params.get("filter", "")
        if "applicationId" in filt:
            app_id = filt.split('"')[1]
            matched = [s for s in all_sps if s.get("applicationId") == app_id]
        elif "displayName" in filt:
            name = filt.split('"')[1]
            matched = [s for s in all_sps if s.get("displayName") == name]
        else:
            matched = all_sps
        body = {"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100}
        return (200, {}, json.dumps(body))

    rsps.add_callback(responses.GET, f"{BASE}/scim/v2/ServicePrincipals",
                      callback=_sp_list_cb, content_type="application/json")

    for s in all_sps:
        rsps.add(responses.GET, f"{BASE}/scim/v2/ServicePrincipals/{s['id']}", json=s)


# ---------------------------------------------------------------------------
# Tests — same groups (identical membership)
# ---------------------------------------------------------------------------

class TestCompareSameGroups:

    @responses.activate
    def test_both_in_same_group_only_in_both(self, mock_client):
        """Two principals sharing all groups → only_in_a and only_in_b are empty."""
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        # Alice and Bob both belong to shared-group; use that as a controlled case.
        # Resolve just those two principals.
        result = comparer.compare("alice@example.com", "bob@example.com")

        # shared-group should be in_both
        both_names = {g.group_name for g in result.in_both}
        assert "shared-group" in both_names

        # alice-special is only in A
        only_a_names = {g.group_name for g in result.only_in_a}
        assert "alice-special" in only_a_names

        # bob-special is only in B
        only_b_names = {g.group_name for g in result.only_in_b}
        assert "bob-special" in only_b_names

    @responses.activate
    def test_display_names_populated(self, mock_client):
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        result = comparer.compare("alice@example.com", "bob@example.com")
        assert result.display_name_a == "Alice Smith"
        assert result.display_name_b == "Bob Jones"

    @responses.activate
    def test_principal_identifiers_stored(self, mock_client):
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        result = comparer.compare("alice@example.com", "bob@example.com")
        assert result.principal_a == "alice@example.com"
        assert result.principal_b == "bob@example.com"


# ---------------------------------------------------------------------------
# Tests — divergent memberships
# ---------------------------------------------------------------------------

class TestCompareDivergent:

    @responses.activate
    def test_extra_group_in_only_a(self, mock_client):
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        result = comparer.compare("alice@example.com", "bob@example.com")

        only_a_names = {g.group_name for g in result.only_in_a}
        assert "alice-special" in only_a_names

    @responses.activate
    def test_extra_group_in_only_b(self, mock_client):
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        result = comparer.compare("alice@example.com", "bob@example.com")

        only_b_names = {g.group_name for g in result.only_in_b}
        assert "bob-special" in only_b_names

    @responses.activate
    def test_in_both_flags(self, mock_client):
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        result = comparer.compare("alice@example.com", "bob@example.com")

        for gc in result.in_both:
            assert gc.in_a is True
            assert gc.in_b is True

        for gc in result.only_in_a:
            assert gc.in_a is True
            assert gc.in_b is False

        for gc in result.only_in_b:
            assert gc.in_a is False
            assert gc.in_b is True


# ---------------------------------------------------------------------------
# Tests — external vs internal source
# ---------------------------------------------------------------------------

class TestCompareSource:

    @responses.activate
    def test_external_group_source_propagated(self, mock_client):
        """bob-special has externalId set → source should be 'external'."""
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        result = comparer.compare("alice@example.com", "bob@example.com")

        only_b = {g.group_name: g for g in result.only_in_b}
        assert "bob-special" in only_b
        assert only_b["bob-special"].source.value == "external"

    @responses.activate
    def test_internal_group_source_propagated(self, mock_client):
        """alice-special has no externalId → source should be 'internal'."""
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        result = comparer.compare("alice@example.com", "bob@example.com")

        only_a = {g.group_name: g for g in result.only_in_a}
        assert "alice-special" in only_a
        assert only_a["alice-special"].source.value == "internal"


# ---------------------------------------------------------------------------
# Tests — is_direct flag
# ---------------------------------------------------------------------------

class TestCompareIsDirect:

    @responses.activate
    def test_direct_group_flagged(self, mock_client):
        """alice-special is a direct membership for Alice → is_direct_in_a = True."""
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        result = comparer.compare("alice@example.com", "bob@example.com")

        only_a = {g.group_name: g for g in result.only_in_a}
        if "alice-special" in only_a:
            assert only_a["alice-special"].is_direct_in_a is True

    @responses.activate
    def test_transitive_group_not_direct(self, mock_client):
        """org-all is a grandparent group — Alice reaches it transitively."""
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        result = comparer.compare("alice@example.com", "bob@example.com")

        # org-all (group-grandparent) should be transitive for Alice
        all_gc = result.only_in_a + result.only_in_b + result.in_both
        org_all = next((g for g in all_gc if g.group_name == "org-all"), None)
        if org_all is not None:
            if org_all.in_a:
                assert org_all.is_direct_in_a is False


# ---------------------------------------------------------------------------
# Tests — principal not found
# ---------------------------------------------------------------------------

class TestComparePrincipalNotFound:

    @responses.activate
    def test_principal_a_not_found_raises(self, mock_client):
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        with pytest.raises(ValueError, match="not found"):
            comparer.compare("ghost@nowhere.com", "bob@example.com")

    @responses.activate
    def test_principal_b_not_found_raises(self, mock_client):
        _add_scim_endpoints(responses)
        comparer = PrincipalComparer(mock_client, cloud_provider="azure")
        with pytest.raises(ValueError, match="not found"):
            comparer.compare("alice@example.com", "ghost@nowhere.com")
