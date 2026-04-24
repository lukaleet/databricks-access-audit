"""Table / view level permission scanner."""

from __future__ import annotations

from typing import Dict, List

from databricks_group_audit._classification import build_member_lookups, classify_grant
from databricks_group_audit.client import AuditClient
from databricks_group_audit.models import GroupMember, TableGrant, WorkspaceInfo


class TablePermissionScanner:
    """Scan table/view-level permissions within schemas."""

    def __init__(self, api_client: AuditClient):
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

    def scan_tables(
        self, ws: WorkspaceInfo, catalog: str, schema: str,
        target_group: str, all_members: Dict[str, List[GroupMember]],
        upstream_groups: Dict[str, str],
    ) -> List[TableGrant]:
        grants: List[TableGrant] = []
        lookups = build_member_lookups(all_members)

        for tbl in self._get_tables(ws, catalog, schema):
            tname = tbl.get("name", "")
            ttype = tbl.get("table_type", "TABLE")
            full = f"{catalog}.{schema}.{tname}"
            for g in self._get_table_grants(ws, full):
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
                grants.append(TableGrant(
                    catalog_name=catalog,
                    schema_name=schema,
                    table_name=tname,
                    full_name=full,
                    table_type=ttype,
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
