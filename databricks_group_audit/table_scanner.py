"""Table / view level permission scanner."""

from __future__ import annotations

from typing import Dict, List, Optional

from databricks_group_audit.client import DatabricksAPIClient
from databricks_group_audit.models import GrantSource, GroupMember, TableGrant, WorkspaceInfo


class TablePermissionScanner:
    """Scan table/view-level permissions within schemas."""

    def __init__(self, api_client: DatabricksAPIClient):
        self.api_client = api_client

    def _get_tables(self, ws: WorkspaceInfo, catalog: str, schema: str) -> List[dict]:
        try:
            return self.api_client.workspace_api(
                ws.workspace_url, "GET", "/api/2.1/unity-catalog/tables",
                params={"catalog_name": catalog, "schema_name": schema},
            ).get("tables", [])
        except Exception:
            return []

    def _get_table_grants(self, ws: WorkspaceInfo, full_name: str) -> List[dict]:
        try:
            return self.api_client.workspace_api(
                ws.workspace_url, "GET",
                f"/api/2.1/unity-catalog/permissions/table/{full_name}",
            ).get("privilege_assignments", [])
        except Exception:
            return []

    def _classify(
        self, principal: str, privileges: List[str],
        catalog: str, schema: str, table: str, table_type: str,
        ws: WorkspaceInfo, target_group: str, upstream: Dict[str, str],
        m_emails: set, m_names: set, sp_names: set, sp_ids: set,
    ) -> Optional[TableGrant]:
        full_name = f"{catalog}.{schema}.{table}"
        base = dict(
            catalog_name=catalog, schema_name=schema, table_name=table,
            full_name=full_name, table_type=table_type,
            workspace_name=ws.workspace_name, workspace_url=ws.workspace_url,
            privileges=privileges,
        )
        if principal == target_group:
            return TableGrant(**base, principal=principal, principal_type="GROUP",
                              grant_source=GrantSource.DIRECT, member_of_target=False)
        if principal in upstream:
            return TableGrant(**base, principal=principal, principal_type="GROUP",
                              grant_source=GrantSource.UPSTREAM, inherited_from=principal,
                              member_of_target=False)
        p_lower = principal.lower()
        if p_lower in m_emails or principal in m_names:
            return TableGrant(**base, principal=principal, principal_type="USER",
                              grant_source=GrantSource.MEMBER_DIRECT, member_of_target=True)
        if principal in sp_names or principal in sp_ids:
            return TableGrant(**base, principal=principal, principal_type="SERVICE_PRINCIPAL",
                              grant_source=GrantSource.MEMBER_DIRECT, member_of_target=True)
        return None

    def scan_tables(
        self, ws: WorkspaceInfo, catalog: str, schema: str,
        target_group: str, all_members: Dict[str, List[GroupMember]],
        upstream_groups: Dict[str, str],
    ) -> List[TableGrant]:
        grants: List[TableGrant] = []
        m_emails = {m.email.lower() for m in all_members["users"] if m.email}
        m_names = {m.display_name for m in all_members["users"]}
        sp_names = {sp.display_name for sp in all_members["service_principals"]}
        sp_ids = {sp.application_id for sp in all_members["service_principals"] if sp.application_id}

        for tbl in self._get_tables(ws, catalog, schema):
            tname = tbl.get("name", "")
            ttype = tbl.get("table_type", "TABLE")
            full = f"{catalog}.{schema}.{tname}"
            for g in self._get_table_grants(ws, full):
                privs = g.get("privileges", [])
                if not privs:
                    continue
                obj = self._classify(
                    g.get("principal", ""), privs, catalog, schema, tname, ttype,
                    ws, target_group, upstream_groups,
                    m_emails, m_names, sp_names, sp_ids,
                )
                if obj:
                    grants.append(obj)
        return grants
