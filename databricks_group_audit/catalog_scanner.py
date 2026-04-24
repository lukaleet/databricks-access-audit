"""Cross-workspace catalog permission scanner with deduplication."""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from databricks_group_audit.client import DatabricksAPIClient
from databricks_group_audit.group_resolver import GroupMembershipResolver
from databricks_group_audit.models import (
    CatalogGrant,
    GrantSource,
    GroupMember,
    GroupNode,
    WorkspaceInfo,
)


def _build_member_lookups(all_members: Dict[str, List[GroupMember]]) -> tuple:
    """Build lookup sets from member lists."""
    member_emails = {m.email.lower() for m in all_members["users"] if m.email}
    member_names = {m.display_name for m in all_members["users"]}
    sp_names = {sp.display_name for sp in all_members["service_principals"]}
    sp_app_ids = {sp.application_id for sp in all_members["service_principals"] if sp.application_id}
    return member_emails, member_names, sp_names, sp_app_ids


def classify_catalog_grant(
    principal: str,
    privileges: List[str],
    catalog_name: str,
    workspace: WorkspaceInfo,
    target_group_name: str,
    upstream_groups: Dict[str, str],
    member_emails: set,
    member_names: set,
    sp_names: set,
    sp_app_ids: set,
) -> Optional[CatalogGrant]:
    """Classify a grant as Direct / Upstream / Member Direct."""
    base = dict(
        catalog_name=catalog_name,
        workspace_name=workspace.workspace_name,
        workspace_url=workspace.workspace_url,
        privileges=privileges,
    )
    if principal == target_group_name:
        return CatalogGrant(**base, principal=principal, principal_type="GROUP",
                            grant_source=GrantSource.DIRECT, member_of_target=False)
    if principal in upstream_groups:
        return CatalogGrant(**base, principal=principal, principal_type="GROUP",
                            grant_source=GrantSource.UPSTREAM, inherited_from=principal,
                            member_of_target=False)
    p_lower = principal.lower()
    p_clean = principal.replace("`", "")
    if p_lower in member_emails or principal in member_names or p_clean in member_names:
        return CatalogGrant(**base, principal=principal, principal_type="USER",
                            grant_source=GrantSource.MEMBER_DIRECT, member_of_target=True)
    if principal in sp_names or principal in sp_app_ids or p_clean in sp_names:
        return CatalogGrant(**base, principal=principal, principal_type="SERVICE_PRINCIPAL",
                            grant_source=GrantSource.MEMBER_DIRECT, member_of_target=True)
    return None


class CatalogPermissionScanner:
    """Scan catalog permissions across workspaces with deduplication."""

    def __init__(self, api_client: DatabricksAPIClient, group_resolver: GroupMembershipResolver):
        self.api_client = api_client
        self.group_resolver = group_resolver
        self._scanned_catalogs: Set[str] = set()

    def _get_catalogs(self, workspace: WorkspaceInfo) -> List[dict]:
        try:
            return self.api_client.workspace_api(
                workspace.workspace_url, "GET", "/api/2.1/unity-catalog/catalogs"
            ).get("catalogs", [])
        except Exception:
            return []

    def _get_catalog_grants(self, workspace: WorkspaceInfo, catalog_name: str) -> List[dict]:
        try:
            return self.api_client.workspace_api(
                workspace.workspace_url, "GET",
                f"/api/2.1/unity-catalog/permissions/catalog/{catalog_name}",
            ).get("privilege_assignments", [])
        except Exception:
            return []

    def get_groups_containing_target(self, target_group_name: str) -> Dict[str, str]:
        """Find upstream groups (parents of the target). Uses paginated SCIM."""
        upstream: Dict[str, str] = {}
        all_groups = self.api_client.scim_list_all("Groups")
        target_id = None
        for g in all_groups:
            if g.get("displayName") == target_group_name:
                target_id = g.get("id")
                break
        if not target_id:
            return upstream
        for g in all_groups:
            for m in g.get("members", []):
                if m.get("value") == target_id:
                    upstream[g.get("displayName")] = g.get("id")
                    break
        return upstream

    def scan_workspace(
        self, workspace: WorkspaceInfo, target_group_name: str,
        group_node: GroupNode, all_members: Dict[str, List[GroupMember]],
    ) -> List[CatalogGrant]:
        grants: List[CatalogGrant] = []
        catalogs = self._get_catalogs(workspace)
        upstream_groups = self.get_groups_containing_target(target_group_name)
        lookups = _build_member_lookups(all_members)

        for cat in catalogs:
            name = cat.get("name", "")
            if name in self._scanned_catalogs:
                continue
            self._scanned_catalogs.add(name)
            for g in self._get_catalog_grants(workspace, name):
                privs = g.get("privileges", [])
                if not privs:
                    continue
                obj = classify_catalog_grant(
                    g.get("principal", ""), privs, name, workspace,
                    target_group_name, upstream_groups, *lookups,
                )
                if obj:
                    grants.append(obj)
        return grants

    def scan_all_workspaces(
        self, workspaces: List[WorkspaceInfo], target_group_name: str,
        group_node: GroupNode, all_members: Dict[str, List[GroupMember]],
    ) -> List[CatalogGrant]:
        self._scanned_catalogs.clear()
        all_grants: List[CatalogGrant] = []
        for ws in workspaces:
            try:
                all_grants.extend(self.scan_workspace(ws, target_group_name, group_node, all_members))
            except Exception:
                pass
        return all_grants
