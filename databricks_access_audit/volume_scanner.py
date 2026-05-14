"""Volume-level permission scanner for Unity Catalog volumes."""

from __future__ import annotations

from typing import Dict, List

from databricks_access_audit._classification import build_member_lookups, classify_grant
from databricks_access_audit.client import AuditClient
from databricks_access_audit.models import GroupMember, VolumeGrant, WorkspaceInfo


class VolumePermissionScanner:
    """Scan volume-level permissions within schemas."""

    def __init__(self, api_client: AuditClient):
        self.api_client = api_client

    def _get_volumes(self, ws: WorkspaceInfo, catalog: str, schema: str) -> List[dict]:
        try:
            return self.api_client.workspace_api(
                ws.workspace_url, "GET", "/api/2.1/unity-catalog/volumes",
                params={"catalog_name": catalog, "schema_name": schema},
            ).get("volumes", [])
        except Exception:
            return []

    def _get_volume_grants(self, ws: WorkspaceInfo, full_name: str) -> List[dict]:
        try:
            return self.api_client.workspace_api(
                ws.workspace_url, "GET",
                f"/api/2.1/unity-catalog/permissions/volume/{full_name}",
            ).get("privilege_assignments", [])
        except Exception:
            return []

    def scan_volumes(
        self, ws: WorkspaceInfo, catalog: str, schema: str,
        target_group: str, all_members: Dict[str, List[GroupMember]],
        upstream_groups: Dict[str, str],
    ) -> List[VolumeGrant]:
        grants: List[VolumeGrant] = []
        lookups = build_member_lookups(all_members)

        for vol in self._get_volumes(ws, catalog, schema):
            vname = vol.get("name", "")
            if not vname:
                continue
            full = f"{catalog}.{schema}.{vname}"
            for g in self._get_volume_grants(ws, full):
                privs = g.get("privileges", [])
                if not privs:
                    continue
                result = classify_grant(
                    g.get("principal", ""), target_group,
                    upstream_groups, *lookups,
                )
                if result is None:
                    continue
                source, ptype, inherited, member = result
                grants.append(VolumeGrant(
                    catalog_name=catalog,
                    schema_name=schema,
                    volume_name=vname,
                    full_name=full,
                    workspace_name=ws.workspace_name,
                    workspace_url=ws.workspace_url,
                    principal=g.get("principal", ""),
                    principal_type=ptype,
                    privileges=privs,
                    grant_source=source,
                    inherited_from=inherited,
                    member_of_target=member,
                ))
        return grants
