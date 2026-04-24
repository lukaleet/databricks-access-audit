"""Schema-level permission scanner."""

from __future__ import annotations

from typing import Dict, List, Optional

from databricks_group_audit.client import DatabricksAPIClient
from databricks_group_audit.models import GrantSource, GroupMember, SchemaGrant, WorkspaceInfo


class SchemaPermissionScanner:
    """Scan schema-level permissions within accessible catalogs."""

    def __init__(self, api_client: DatabricksAPIClient):
        self.api_client = api_client

    def _get_schemas(self, workspace: WorkspaceInfo, catalog_name: str) -> List[dict]:
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

    def _classify(
        self, principal: str, privileges: List[str],
        catalog: str, schema: str, workspace: WorkspaceInfo,
        target_group: str, upstream: Dict[str, str],
        m_emails: set, m_names: set, sp_names: set, sp_ids: set,
    ) -> Optional[SchemaGrant]:
        base = dict(
            catalog_name=catalog, schema_name=schema,
            workspace_name=workspace.workspace_name,
            workspace_url=workspace.workspace_url, privileges=privileges,
        )
        if principal == target_group:
            return SchemaGrant(**base, principal=principal, principal_type="GROUP",
                               grant_source=GrantSource.DIRECT, member_of_target=False)
        if principal in upstream:
            return SchemaGrant(**base, principal=principal, principal_type="GROUP",
                               grant_source=GrantSource.UPSTREAM, inherited_from=principal,
                               member_of_target=False)
        p_lower = principal.lower()
        if p_lower in m_emails or principal in m_names:
            return SchemaGrant(**base, principal=principal, principal_type="USER",
                               grant_source=GrantSource.MEMBER_DIRECT, member_of_target=True)
        if principal in sp_names or principal in sp_ids:
            return SchemaGrant(**base, principal=principal, principal_type="SERVICE_PRINCIPAL",
                               grant_source=GrantSource.MEMBER_DIRECT, member_of_target=True)
        return None

    def scan_schemas(
        self, workspace: WorkspaceInfo, catalog_name: str,
        target_group_name: str, all_members: Dict[str, List[GroupMember]],
        upstream_groups: Dict[str, str],
    ) -> List[SchemaGrant]:
        grants: List[SchemaGrant] = []
        m_emails = {m.email.lower() for m in all_members["users"] if m.email}
        m_names = {m.display_name for m in all_members["users"]}
        sp_names = {sp.display_name for sp in all_members["service_principals"]}
        sp_ids = {sp.application_id for sp in all_members["service_principals"] if sp.application_id}

        for schema in self._get_schemas(workspace, catalog_name):
            sname = schema.get("name", "")
            for g in self._get_schema_grants(workspace, catalog_name, sname):
                privs = g.get("privileges", [])
                if not privs:
                    continue
                obj = self._classify(
                    g.get("principal", ""), privs, catalog_name, sname,
                    workspace, target_group_name, upstream_groups,
                    m_emails, m_names, sp_names, sp_ids,
                )
                if obj:
                    grants.append(obj)
        return grants
