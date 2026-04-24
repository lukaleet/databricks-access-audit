"""Tests for WorkspaceDiscovery, especially _resolve_workspace_url."""

import pytest
import responses

from databricks_group_audit.workspace import WorkspaceDiscovery, WORKSPACE_DOMAIN_MAP
from tests.conftest import ACCOUNT_HOST, ACCOUNT_ID


@pytest.fixture
def discovery(mock_scim):
    """WorkspaceDiscovery backed by mock SCIM (for token auth)."""
    rsps, client = mock_scim
    yield WorkspaceDiscovery(client, cloud_provider="AZURE"), rsps


# ---------------------------------------------------------------------------
# _resolve_workspace_url
# ---------------------------------------------------------------------------

class TestResolveWorkspaceUrl:
    """Unit tests for _resolve_workspace_url, the AWS-fix method."""

    def _disco(self, cloud="AZURE"):
        """Minimal WorkspaceDiscovery without a real client (only testing URL logic)."""
        return WorkspaceDiscovery.__new__(WorkspaceDiscovery)

    def setup_method(self):
        # Patch a lightweight instance for URL-only tests
        self.d = WorkspaceDiscovery.__new__(WorkspaceDiscovery)
        self.d.cloud_provider = "AZURE"

    def test_prefers_deployment_url(self):
        """When the API returns deployment_url, use it directly."""
        ws = {"deployment_url": "https://adb-12345.cloud.databricks.com",
              "deployment_name": "old-name"}
        url = self.d._resolve_workspace_url(ws, "AWS")
        assert url == "https://adb-12345.cloud.databricks.com"

    def test_deployment_url_without_scheme(self):
        """deployment_url without https:// should be auto-prefixed."""
        ws = {"deployment_url": "adb-12345.cloud.databricks.com"}
        url = self.d._resolve_workspace_url(ws, "AWS")
        assert url == "https://adb-12345.cloud.databricks.com"

    def test_deployment_url_strips_trailing_slash(self):
        ws = {"deployment_url": "https://adb-12345.cloud.databricks.com/"}
        url = self.d._resolve_workspace_url(ws, "AWS")
        assert url == "https://adb-12345.cloud.databricks.com"

    def test_falls_back_to_deployment_name_azure(self):
        """Without deployment_url, construct from deployment_name."""
        ws = {"deployment_name": "adb-999.9"}
        url = self.d._resolve_workspace_url(ws, "AZURE")
        assert url == "https://adb-999.9.azuredatabricks.net"

    def test_falls_back_to_deployment_name_gcp(self):
        ws = {"deployment_name": "my-gcp-ws"}
        url = self.d._resolve_workspace_url(ws, "GCP")
        assert url == "https://my-gcp-ws.gcp.databricks.com"

    def test_aws_fallback_to_workspace_id(self):
        """AWS without deployment_url or deployment_name -> adb-<workspace_id>."""
        ws = {"workspace_id": "9876543210"}
        url = self.d._resolve_workspace_url(ws, "AWS")
        assert url == "https://adb-9876543210.cloud.databricks.com"

    def test_non_aws_without_deployment_returns_empty(self):
        """Azure/GCP without deployment_url or deployment_name -> empty string."""
        ws = {"workspace_id": "999"}
        url = self.d._resolve_workspace_url(ws, "AZURE")
        assert url == ""

    def test_empty_deployment_url_ignored(self):
        """Whitespace-only deployment_url should be skipped."""
        ws = {"deployment_url": "   ", "deployment_name": "real-name"}
        url = self.d._resolve_workspace_url(ws, "AZURE")
        assert url == "https://real-name.azuredatabricks.net"


# ---------------------------------------------------------------------------
# get_all_workspaces (integration with mock API)
# ---------------------------------------------------------------------------

def test_get_all_workspaces_uses_resolve(discovery):
    """get_all_workspaces should use _resolve_workspace_url (not raw _build_url)."""
    disco, rsps = discovery
    base = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}"

    rsps.add(
        responses.GET, f"{base}/workspaces",
        json=[
            {
                "workspace_id": "111",
                "deployment_url": "https://adb-111.cloud.databricks.com",
                "deployment_name": "should-not-use-this",
                "workspace_name": "ws-aws",
                "cloud": "AWS",
                "aws_region": "us-east-1",
            },
            {
                "workspace_id": "222",
                "deployment_name": "adb-222.3",
                "workspace_name": "ws-azure",
                "cloud": "AZURE",
                "azure_workspace_info": {"region": "westeurope"},
            },
        ],
    )

    workspaces = disco.get_all_workspaces()
    assert len(workspaces) == 2

    aws_ws = next(w for w in workspaces if w.cloud == "AWS")
    assert aws_ws.workspace_url == "https://adb-111.cloud.databricks.com"
    assert aws_ws.region == "us-east-1"

    azure_ws = next(w for w in workspaces if w.cloud == "AZURE")
    assert azure_ws.workspace_url == "https://adb-222.3.azuredatabricks.net"
    assert azure_ws.region == "westeurope"


# ---------------------------------------------------------------------------
# parse_workspace_urls
# ---------------------------------------------------------------------------

def test_parse_workspace_urls_detects_cloud(discovery):
    disco, _ = discovery
    result = disco.parse_workspace_urls(
        "https://my-ws.azuredatabricks.net, https://adb-123.cloud.databricks.com"
    )
    assert len(result) == 2
    assert result[0].cloud == "AZURE"
    assert result[1].cloud == "AWS"


def test_parse_workspace_urls_adds_scheme(discovery):
    disco, _ = discovery
    result = disco.parse_workspace_urls("my-ws.gcp.databricks.com")
    assert result[0].workspace_url == "https://my-ws.gcp.databricks.com"
    assert result[0].cloud == "GCP"


def test_parse_empty_string(discovery):
    disco, _ = discovery
    assert disco.parse_workspace_urls("") == []
    assert disco.parse_workspace_urls("   ") == []
