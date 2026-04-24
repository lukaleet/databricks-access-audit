"""Cross-workspace catalog permission scanner."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Tuple

from databricks_group_audit._classification import build_member_lookups, classify_grant
from databricks_group_audit.client import AuditClient
from databricks_group_audit.group_resolver import GroupMembershipResolver
from databricks_group_audit.models import (
    CatalogGrant,
    GroupMember,
    GroupNode,
    WorkspaceInfo,
)

log = logging.getLogger(__name__)


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
    """Classify a grant as Direct / Upstream / Member Direct and wrap in CatalogGrant."""
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
    """Scan catalog permissions across workspaces.

    Deduplication is keyed on ``(workspace_url, catalog_name)`` so that
    identically-named catalogs attached to different metastores (different
    workspaces) are each scanned independently.  A single workspace seeing
    the same catalog twice is still deduplicated.
    """

    def __init__(self, api_client: AuditClient, group_resolver: GroupMembershipResolver):
        self.api_client = api_client
        self.group_resolver = group_resolver
        # (workspace_url, catalog_name) — prevents re-scanning the same
        # catalog from the same workspace context while allowing the same
        # catalog name to be scanned from a different workspace/metastore.
        self._scanned_catalogs: Set[Tuple[str, str]] = set()

    def _get_catalogs(self, workspace: WorkspaceInfo) -> List[dict]:
        try:
            return self.api_client.workspace_api(
                workspace.workspace_url, "GET", "/api/2.1/unity-catalog/catalogs"
            ).get("catalogs", [])
        except Exception as exc:
            log.warning(
                "Failed to list catalogs for workspace %s: %s", workspace.workspace_name, exc
            )
            return []

    def _get_catalog_grants(self, workspace: WorkspaceInfo, catalog_name: str) -> List[dict]:
        try:
            resp = self.api_client.workspace_api(
                workspace.workspace_url, "GET",
                f"/api/2.1/unity-catalog/permissions/catalog/{catalog_name}",
            )
            return resp.get("privilege_assignments") or []
        except Exception as exc:
            log.warning(
                "Failed to get grants for catalog %s on workspace %s: %s",
                catalog_name, workspace.workspace_name, exc,
            )
            return []

    def get_groups_containing_target(self, target_group_name: str) -> Dict[str, str]:
        """Find ALL upstream (ancestor) groups of the target via BFS.

        Fetches the full SCIM group list once and builds a child-to-parents
        adjacency map, then walks upward so transitive ancestors are captured.
        For example: if org-all → all-data-team → target, both are returned.
        """
        all_groups = self.api_client.scim_list_all("Groups")

        id_to_name: Dict[str, str] = {}
        child_to_parents: Dict[str, Set[str]] = {}
        target_id: Optional[str] = None

        for g in all_groups:
            gid = g.get("id")
            gname = g.get("displayName", "")
            if not gid:
                continue
            id_to_name[gid] = gname
            if gname == target_group_name:
                target_id = gid
            for m in g.get("members", []):
                child_id = m.get("value")
                if child_id:
                    child_to_parents.setdefault(child_id, set()).add(gid)

        if not target_id:
            return {}

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
        self,
        workspace: WorkspaceInfo,
        target_group_name: str,
        group_node: GroupNode,
        all_members: Dict[str, List[GroupMember]],
        upstream_groups: Optional[Dict[str, str]] = None,
    ) -> List[CatalogGrant]:
        """Scan a single workspace for catalog grants related to target_group_name.

        Parameters
        ----------
        upstream_groups:
            Pre-computed ancestor group map from :meth:`get_groups_containing_target`.
            When *None* the map is computed on demand (adds one SCIM list call).
            Pass it explicitly when scanning multiple workspaces to avoid N+1 fetches.
        """
        if upstream_groups is None:
            upstream_groups = self.get_groups_containing_target(target_group_name)

        grants: List[CatalogGrant] = []
        catalogs = self._get_catalogs(workspace)
        lookups = build_member_lookups(all_members)

        for cat in catalogs:
            name = cat.get("name", "")
            if not name:
                continue
            key = (workspace.workspace_url, name)
            if key in self._scanned_catalogs:
                continue
            self._scanned_catalogs.add(key)

            for g in self._get_catalog_grants(workspace, name):
                privs = g.get("privileges") or []
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
        self,
        workspaces: List[WorkspaceInfo],
        target_group_name: str,
        group_node: GroupNode,
        all_members: Dict[str, List[GroupMember]],
    ) -> List[CatalogGrant]:
        """Scan all workspaces, computing upstream groups exactly once."""
        self._scanned_catalogs.clear()
        # Fetch upstream groups once — the SCIM hierarchy is account-level and
        # does not change between workspaces, so fetching N times would be wasteful.
        upstream_groups = self.get_groups_containing_target(target_group_name)

        all_grants: List[CatalogGrant] = []
        for ws in workspaces:
            try:
                all_grants.extend(
                    self.scan_workspace(
                        ws, target_group_name, group_node, all_members, upstream_groups
                    )
                )
            except Exception as exc:
                log.warning("Skipping workspace %s due to error: %s", ws.workspace_name, exc)
        return all_grants
