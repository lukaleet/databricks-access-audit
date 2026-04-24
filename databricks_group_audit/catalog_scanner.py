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
from databricks_group_audit._classification import build_member_lookups, classify_grant


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
    """Classify a grant as Direct / Upstream / Member Direct.

    Thin wrapper around :func:`classify_grant` that constructs a
    :class:`CatalogGrant` dataclass.
    """
    result = classify_grant(
        principal, target_group_name, upstream_groups,
        member_emails, member_names, sp_names, sp_app_ids,
    )
    if result is None:
        return None
    source, ptype, inherited, member = result
    return CatalogGrant(
        catalog_name=catalog_name,
        workspace_name=workspace.workspace_name,
        workspace_url=workspace.workspace_url,
        principal=principal,
        principal_type=ptype,
        privileges=privileges,
        grant_source=source,
        inherited_from=inherited,
        member_of_target=member,
    )


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
        """Find ALL upstream groups — recursive parents of the target.

        Builds a child-to-parents adjacency map from the full SCIM group list,
        then walks upward via BFS so that transitive ancestors are captured.
        E.g. if A contains B contains target, both A and B are returned.
        """
        all_groups = self.api_client.scim_list_all("Groups")

        # Build lookup maps
        id_to_name: Dict[str, str] = {}
        child_to_parents: Dict[str, Set[str]] = {}
        target_id: Optional[str] = None

        for g in all_groups:
            gid = g.get("id")
            gname = g.get("displayName", "")
            id_to_name[gid] = gname
            if gname == target_group_name:
                target_id = gid
            for m in g.get("members", []):
                child_id = m.get("value")
                if child_id:
                    child_to_parents.setdefault(child_id, set()).add(gid)

        if not target_id:
            return {}

        # BFS upward from target
        upstream: Dict[str, str] = {}
        queue = [target_id]
        visited = {target_id}

        while queue:
            current = queue.pop(0)
            for parent_id in child_to_parents.get(current, set()):
                if parent_id not in visited:
                    visited.add(parent_id)
                    upstream[id_to_name.get(parent_id, parent_id)] = parent_id
                    queue.append(parent_id)

        return upstream

    def scan_workspace(
        self, workspace: WorkspaceInfo, target_group_name: str,
        group_node: GroupNode, all_members: Dict[str, List[GroupMember]],
    ) -> List[CatalogGrant]:
        grants: List[CatalogGrant] = []
        catalogs = self._get_catalogs(workspace)
        upstream_groups = self.get_groups_containing_target(target_group_name)
        lookups = build_member_lookups(all_members)

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
