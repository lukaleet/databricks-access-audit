"""Cross-workspace catalog permission scanner."""

from __future__ import annotations

import logging
import sys
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

from databricks_access_audit._classification import build_member_lookups, classify_grant
from databricks_access_audit.client import AuditClient
from databricks_access_audit.group_resolver import GroupMembershipResolver
from databricks_access_audit.models import (
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

    Each workspace is scanned independently so that workspace-catalog bindings
    are respected: the same catalog name can be attached to different subsets
    of workspaces, and must be scanned from every workspace that can see it.

    Duplicate workspace URLs in the input list are silently deduplicated by
    :meth:`scan_all_workspaces` before dispatch.  Within a single
    :meth:`scan_workspace` call, duplicate catalog names from the UC API
    response are skipped via a local seen-set.
    """

    def __init__(self, api_client: AuditClient, group_resolver: GroupMembershipResolver):
        self.api_client = api_client
        self.group_resolver = group_resolver

    def _get_catalogs(self, workspace: WorkspaceInfo) -> List[dict]:
        try:
            return self.api_client.workspace_api(
                workspace.workspace_url, "GET", "/api/2.1/unity-catalog/catalogs"
            ).get("catalogs", [])
        except Exception as exc:
            log.warning(
                "Failed to list catalogs for workspace %s: %s", workspace.workspace_name, exc
            )
            print(
                f"WARNING  workspace '{workspace.workspace_name}' UC scan skipped: {exc}",
                file=sys.stderr,
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

        Delegates the O(N) group-membership fetch to
        :meth:`~databricks_access_audit.group_resolver.GroupMembershipResolver.get_group_membership_map`,
        which parallelises the individual GETs and caches the result for the
        lifetime of the resolver instance.  Multiple callers within the same
        audit session (catalog scanner, schema scanner, principal auditor) share
        the cached map without redundant API calls.
        """
        id_to_name, _, child_to_parents = self.group_resolver.get_group_membership_map()

        target_id = next(
            (gid for gid, name in id_to_name.items() if name == target_group_name), None
        )
        if not target_id:
            return {}

        upstream: Dict[str, str] = {}
        queue: deque = deque([target_id])
        visited = {target_id}

        while queue:
            current = queue.popleft()
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
        seen_names: Set[str] = set()  # guard against duplicate catalog names in the API response

        for cat in catalogs:
            name = cat.get("name", "")
            if not name or name in seen_names:
                continue
            seen_names.add(name)

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
        max_workers: int = 8,
    ) -> List[CatalogGrant]:
        """Scan all workspaces in parallel, computing upstream groups exactly once.

        Duplicate workspace URLs are silently deduplicated before dispatch so
        that a workspace listed more than once is only scanned once.
        Workers are capped at the number of unique workspaces to avoid
        spawning idle threads.
        """
        # Fetch upstream groups once — the SCIM hierarchy is account-level and
        # does not change between workspaces, so fetching N times would be wasteful.
        upstream_groups = self.get_groups_containing_target(target_group_name)

        # Deduplicate by URL while preserving order.
        seen_urls: Set[str] = set()
        unique_workspaces: List[WorkspaceInfo] = []
        for ws in workspaces:
            if ws.workspace_url not in seen_urls:
                seen_urls.add(ws.workspace_url)
                unique_workspaces.append(ws)

        n = len(unique_workspaces)
        if n == 0:
            return []

        all_grants: List[CatalogGrant] = []
        workers = min(max_workers, n)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    self.scan_workspace,
                    ws, target_group_name, group_node, all_members, upstream_groups,
                ): ws
                for ws in unique_workspaces
            }
            for fut in as_completed(futures):
                ws = futures[fut]
                try:
                    all_grants.extend(fut.result())
                except Exception as exc:
                    log.warning("Skipping workspace %s due to error: %s", ws.workspace_name, exc)
                    print(
                        f"WARNING  workspace '{ws.workspace_name}' skipped: {exc}",
                        file=sys.stderr,
                    )

        return all_grants
