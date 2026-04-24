"""Workspace discovery from Account API or explicit URLs."""

from __future__ import annotations

from typing import List

from databricks_group_audit.client import DatabricksAPIClient
from databricks_group_audit.models import WorkspaceInfo

WORKSPACE_DOMAIN_MAP = {
    "AZURE": ".azuredatabricks.net",
    "AWS": ".cloud.databricks.com",
    "GCP": ".gcp.databricks.com",
}


class WorkspaceDiscovery:
    """Discover Databricks workspaces (auto or manual)."""

    def __init__(self, api_client: DatabricksAPIClient, cloud_provider: str = "AZURE"):
        self.api_client = api_client
        self.cloud_provider = cloud_provider.upper()

    def _build_url(self, deployment_name: str, cloud: str | None = None) -> str:
        cloud = (cloud or self.cloud_provider).upper()
        domain = WORKSPACE_DOMAIN_MAP.get(cloud, WORKSPACE_DOMAIN_MAP["AZURE"])
        return f"https://{deployment_name}{domain}"

    def get_all_workspaces(self) -> List[WorkspaceInfo]:
        response = self.api_client.account_api("GET", "/workspaces")
        workspaces: List[WorkspaceInfo] = []
        for ws in response:
            deployment = ws.get("deployment_name", "")
            name = ws.get("workspace_name", deployment)
            cloud = ws.get("cloud", self.cloud_provider).upper()
            url = self._build_url(deployment, cloud)

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
