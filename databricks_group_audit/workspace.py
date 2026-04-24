"""Workspace discovery from Account API or explicit URLs."""

from __future__ import annotations

from typing import List, Optional

from databricks_group_audit.client import AuditClient
from databricks_group_audit.models import WorkspaceInfo

WORKSPACE_DOMAIN_MAP = {
    "AZURE": ".azuredatabricks.net",
    "AWS": ".cloud.databricks.com",
    "GCP": ".gcp.databricks.com",
}


class WorkspaceDiscovery:
    """Discover Databricks workspaces (auto or manual)."""

    def __init__(self, api_client: AuditClient, cloud_provider: str = "AZURE"):
        self.api_client = api_client
        self.cloud_provider = cloud_provider.upper()

    def _build_url(self, deployment_name: str, cloud: str | None = None) -> str:
        """Construct workspace URL from deployment name and cloud.

        Only used as a fallback when the API does not return a direct URL.
        """
        cloud = (cloud or self.cloud_provider).upper()
        domain = WORKSPACE_DOMAIN_MAP.get(cloud, WORKSPACE_DOMAIN_MAP["AZURE"])
        return f"https://{deployment_name}{domain}"

    def _resolve_workspace_url(self, ws: dict, cloud: str) -> str:
        """Resolve the actual workspace URL.

        Prefers the ``deployment_url`` field returned by the Account API (which
        is the canonical URL for AWS ``adb-<id>`` style workspaces).  Falls
        back to constructing from ``deployment_name`` when unavailable.
        """
        # The Account API may return the full URL directly
        api_url = ws.get("deployment_url", "").strip()
        if api_url:
            if not api_url.startswith("https://"):
                api_url = f"https://{api_url}"
            return api_url.rstrip("/")

        deployment_name = ws.get("deployment_name", "")
        if deployment_name:
            return self._build_url(deployment_name, cloud)

        # Last resort: reconstruct from workspace_id for AWS
        if cloud == "AWS":
            wid = ws.get("workspace_id", "")
            if wid:
                return f"https://adb-{wid}.cloud.databricks.com"

        return ""

    def get_all_workspaces(self) -> List[WorkspaceInfo]:
        response = self.api_client.account_api("GET", "/workspaces")
        workspaces: List[WorkspaceInfo] = []
        for ws in response:
            deployment = ws.get("deployment_name", "")
            name = ws.get("workspace_name", deployment)
            cloud = ws.get("cloud", self.cloud_provider).upper()

            url = self._resolve_workspace_url(ws, cloud)

            if cloud == "AZURE":
                region = ws.get("azure_workspace_info", {}).get("region", "unknown")
            elif cloud == "GCP":
                region = ws.get("gcp_workspace_info", {}).get("region", ws.get("cloud_region", "unknown"))
            else:
                region = ws.get("aws_region", ws.get("cloud_region", "unknown"))

            workspaces.append(WorkspaceInfo(
                workspace_id=str(ws.get("workspace_id", "")),
                deployment_name=deployment, workspace_name=name,
                workspace_url=url, cloud=cloud, region=region,
            ))
        return workspaces

    def parse_workspace_urls(self, urls_str: str) -> List[WorkspaceInfo]:
        workspaces: List[WorkspaceInfo] = []
        for raw in urls_str.split(","):
            url = raw.strip()
            if not url:
                continue
            if not url.startswith("https://"):
                url = f"https://{url}"
            host = url.replace("https://", "").split("/")[0]
            detected_cloud = self.cloud_provider
            deployment = host
            for cloud_key, domain in WORKSPACE_DOMAIN_MAP.items():
                if host.endswith(domain):
                    detected_cloud = cloud_key
                    deployment = host.replace(domain, "")
                    break
            workspaces.append(WorkspaceInfo(
                workspace_id="manual", deployment_name=deployment,
                workspace_name=deployment, workspace_url=url.rstrip("/"),
                cloud=detected_cloud, region="unknown",
            ))
        return workspaces

    def discover(self, explicit_urls: str = "") -> List[WorkspaceInfo]:
        if explicit_urls.strip():
            return self.parse_workspace_urls(explicit_urls)
        return self.get_all_workspaces()
