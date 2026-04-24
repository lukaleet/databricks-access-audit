"""Shared test fixtures with mocked SCIM and Unity Catalog API responses."""

import pytest
import responses

ACCOUNT_HOST = "https://accounts.azuredatabricks.net"
ACCOUNT_ID = "test-account-id"
WORKSPACE_HOST = "https://test-workspace.azuredatabricks.net"


# ---------------------------------------------------------------------------
# SCIM mock data
# ---------------------------------------------------------------------------

SCIM_GROUP_DATA_ENGINEERS = {
    "id": "group-1",
    "displayName": "data-engineers",
    "members": [
        {"value": "user-1", "display": "Alice", "$ref": "Users/user-1"},
        {"value": "user-2", "display": "Bob", "$ref": "Users/user-2"},
        {"value": "sp-1", "display": "ETL-Bot", "$ref": "ServicePrincipals/sp-1"},
        {"value": "group-2", "display": "data-analysts", "$ref": "Groups/group-2"},
    ],
}

SCIM_GROUP_DATA_ANALYSTS = {
    "id": "group-2",
    "displayName": "data-analysts",
    "members": [
        {"value": "user-3", "display": "Charlie", "$ref": "Users/user-3"},
    ],
}

SCIM_GROUP_PARENT = {
    "id": "group-parent",
    "displayName": "all-data-team",
    "members": [
        {"value": "group-1", "display": "data-engineers", "$ref": "Groups/group-1"},
    ],
}

SCIM_USER_ALICE = {
    "id": "user-1", "displayName": "Alice Smith",
    "emails": [{"value": "alice@example.com"}],
}
SCIM_USER_BOB = {
    "id": "user-2", "displayName": "Bob Jones",
    "emails": [{"value": "bob@example.com"}],
}
SCIM_USER_CHARLIE = {
    "id": "user-3", "displayName": "Charlie Brown",
    "emails": [{"value": "charlie@example.com"}],
}
SCIM_SP_ETL = {
    "id": "sp-1", "displayName": "ETL-Bot", "applicationId": "app-etl-001",
}

ALL_GROUPS = [SCIM_GROUP_DATA_ENGINEERS, SCIM_GROUP_DATA_ANALYSTS, SCIM_GROUP_PARENT]


# ---------------------------------------------------------------------------
# Unity Catalog mock data
# ---------------------------------------------------------------------------

CATALOGS_RESPONSE = {
    "catalogs": [
        {"name": "main"},
        {"name": "staging"},
    ]
}

MAIN_CATALOG_GRANTS = {
    "privilege_assignments": [
        {"principal": "data-engineers", "privileges": ["USE_CATALOG", "SELECT"]},
        {"principal": "all-data-team", "privileges": ["ALL_PRIVILEGES"]},
        {"principal": "alice@example.com", "privileges": ["USE_CATALOG", "SELECT"]},
    ]
}

STAGING_CATALOG_GRANTS = {
    "privilege_assignments": [
        {"principal": "bob@example.com", "privileges": ["MODIFY"]},
    ]
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_client():
    """Return a DatabricksAPIClient pointed at mocked endpoints."""
    from databricks_group_audit.client import DatabricksAPIClient
    return DatabricksAPIClient(
        client_id="test-id",
        client_secret="test-secret",
        account_id=ACCOUNT_ID,
        account_host=ACCOUNT_HOST,
    )


@pytest.fixture
def mock_scim(mock_client):
    """Activate responses mock with SCIM endpoints pre-loaded."""
    with responses.RequestsMock() as rsps:
        base = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"

        # Token endpoint
        rsps.add(responses.POST, f"{ACCOUNT_HOST}/oidc/v1/token",
                 json={"access_token": "mock-token", "expires_in": 3600})

        # Group filter by name
        rsps.add(responses.GET, f"{base}/scim/v2/Groups",
                 json={"Resources": ALL_GROUPS, "totalResults": 3, "itemsPerPage": 100})

        # Individual group lookups
        for g in ALL_GROUPS:
            rsps.add(responses.GET, f"{base}/scim/v2/Groups/{g['id']}", json=g)

        # User lookups
        for u in [SCIM_USER_ALICE, SCIM_USER_BOB, SCIM_USER_CHARLIE]:
            rsps.add(responses.GET, f"{base}/scim/v2/Users/{u['id']}", json=u)

        # SP lookups
        rsps.add(responses.GET, f"{base}/scim/v2/ServicePrincipals/sp-1", json=SCIM_SP_ETL)

        yield rsps, mock_client


@pytest.fixture
def mock_uc(mock_scim):
    """Extend SCIM mock with Unity Catalog workspace endpoints."""
    rsps, client = mock_scim

    # Workspace token
    rsps.add(responses.POST, f"{WORKSPACE_HOST}/oidc/v1/token",
             json={"access_token": "ws-token", "expires_in": 3600})

    # Catalogs
    rsps.add(responses.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/catalogs",
             json=CATALOGS_RESPONSE)

    # Catalog grants
    rsps.add(responses.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/catalog/main",
             json=MAIN_CATALOG_GRANTS)
    rsps.add(responses.GET, f"{WORKSPACE_HOST}/api/2.1/unity-catalog/permissions/catalog/staging",
             json=STAGING_CATALOG_GRANTS)

    yield rsps, client
