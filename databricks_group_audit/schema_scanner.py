"""Schema-level permission scanner."""

from __future__ import annotations

from typing import Dict, List, Optional

from databricks_group_audit.client import AuditClient
from databricks_group_audit.models import GrantSource, GroupMember, SchemaGrant, WorkspaceInfo
from databricks_group_audit._classification import build_member_lookups, classify_grant


class SchemaPermissionScanner:
    """Scan schema-level permissions within accessible catalogs."""

    def __init__(self, api_client: AuditClient):
        self.api_client = api_client

    def get_schemas(self, workspace: WorkspaceInfo, catalog_name: str) -> List[dict]:
        try:
            return self.api_client.workspace_api(
                workspace.workspace_url, "GET",
                "/api/2.1/unity-catalog/schemas",
                params={"catalog_name": catalog_name},
            ).get("schemas", [])
        except Exception:
            return []

    def _get_schema_grants(self, workspace: WorkspaceInfo, catalog: str, schema: str) -> List[dict]:
        try:
            return self.api_client.workspace_api(
                workspace.workspace_url, "GET",
                f"/api/2.1/unity-catalog/permissions/schema/{catalog}.{schema}",
            ).get("privilege_assignments", [])
        except Exception:
            return []

    def scan_schemas(
        self, workspace: WorkspaceInfo, catalog_name: str,
        target_group_name: str, all_members: Dict[str, List[GroupMember]],
        upstream_groups: Dict[str, str],
    ) -> List[SchemaGrant]:
        grants: List[SchemaGrant] = []
        lookups = build_member_lookups(all_members)

        for schema in self.get_schemas(workspace, catalog_name):
            sname = schema.get("name", "")
            for g in self._get_schema_grants(workspace, catalog_name, sname):
                privs = g.get("privileges", [])
                if not privs:
                    continue
                result = classify_grant(
                    g.get("principal", ""), target_group_name,
                    upstream_groups, *lookups,
                )
                if result is None:
                    continue
                source, ptype, inherited, member = result
                grants.append(SchemaGrant(
                    catalog_name=catalog_name,
                    schema_name=sname,
                    workspace_name=workspace.workspace_name,
                    workspace_url=workspace.workspace_url,
                    principal=g.get("principal", ""),
                    principal_type=ptype,
                    privileges=privs,
                    grant_source=source,
                    inherited_from=inherited,
                    member_of_target=member,
                ))
        return grants
