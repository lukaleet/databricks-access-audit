"""Access cloning — replicate one principal's group memberships to another."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set

from databricks_access_audit.client import AuditClient
from databricks_access_audit.models import (
    CloneAction,
    CloneActionType,
    CloneReport,
    WorkspaceInfo,
)
from databricks_access_audit.principal_auditor import PrincipalAuditor
from databricks_access_audit.workspace import WorkspaceDiscovery

log = logging.getLogger(__name__)


class AccessCloner:
    """Build a provisioning report to replicate one principal's group access.

    For each direct group membership of the *source* principal the report
    classifies the required action:

    ``IDP_REQUIRED``
        The group is externally managed (Entra, Okta, …).  The target must be
        added in the external identity provider — Databricks has no write access
        to IdP-synced group membership.

    ``DATABRICKS``
        The group is Databricks-managed AND provides effective access
        (workspace assignment or Unity Catalog grants).  The tool can perform
        the SCIM ``PATCH`` when ``--apply`` is passed.

    ``UNVERIFIED``
        The group is Databricks-managed but has no detected workspace
        assignment.  UC grants are not scanned by default (expensive at scale).
        Pass ``scan_uc=True`` to resolve these into ``DATABRICKS`` (has UC
        grants) or ``SKIPPED`` (dead-end, no grants anywhere).

    ``SKIPPED``
        Verified dead-end: no workspace assignment and no UC grants.  Adding
        the target would have no effect.
    """

    def __init__(
        self,
        api_client: AuditClient,
        cloud_provider: str = "azure",
    ):
        self.api = api_client
        self._auditor = PrincipalAuditor(api_client, cloud_provider=cloud_provider)
        self._ws_discovery = WorkspaceDiscovery(api_client, cloud_provider)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_report(
        self,
        source: str,
        target: str,
        scan_uc: bool = False,
        explicit_workspace_urls: str = "",
        max_workers: int = 8,
    ) -> CloneReport:
        """Analyse source's direct group memberships and classify each action.

        Parameters
        ----------
        source:
            Identifier (email / app-ID / display name) of the reference
            principal whose access should be replicated.
        target:
            Identifier of the principal who should receive the same access.
        scan_uc:
            When *True*, groups with no workspace assignment are additionally
            checked for Unity Catalog grants to distinguish UC-only groups
            (``DATABRICKS``) from dead-end groups (``SKIPPED``).  Adds
            catalog-scan API calls for each workspace.
        explicit_workspace_urls:
            Comma-separated workspace URLs (empty = discover all).
        max_workers:
            Parallel threads for workspace scans.
        """
        # Resolve source principal
        ptype_s, pid_s, pname_s, _, _ = self._auditor.find_principal(source)
        log.info("Source: %s (%s, id=%s)", pname_s, ptype_s, pid_s)

        # Resolve target principal (just to confirm it exists and get display name)
        ptype_t, pid_t, pname_t, _, _ = self._auditor.find_principal(target)
        log.info("Target: %s (%s, id=%s)", pname_t, ptype_t, pid_t)

        # BFS group memberships for source — only direct ones are cloned
        memberships, _ = self._auditor.resolve_group_memberships(pid_s, ptype_s, pname_s)
        direct = [m for m in memberships if m.is_direct]
        log.info("Source has %d direct group membership(s)", len(direct))

        # Discover workspaces
        workspaces = self._ws_discovery.discover(explicit_workspace_urls)

        # Map group_id → list of workspace names where it has an assignment
        ws_access = self._workspace_access_map(
            {m.group_id for m in direct}, workspaces, max_workers
        )

        # Optional UC scan for groups with no workspace assignment
        no_ws_ids = {m.group_id for m in direct if not ws_access.get(m.group_id)}
        uc_groups: Set[str] = set()
        if scan_uc and no_ws_ids:
            uc_groups = self._groups_with_uc_grants(no_ws_ids, workspaces, max_workers)

        # Classify each direct group
        actions: List[CloneAction] = []
        for m in direct:
            ws_names = ws_access.get(m.group_id, [])

            if m.source.value == "external":
                actions.append(CloneAction(
                    action_type=CloneActionType.IDP_REQUIRED,
                    group_id=m.group_id,
                    group_name=m.group_name,
                    external_id=m.external_id,
                    path=m.path,
                    workspace_accesses=ws_names,
                ))
            elif ws_names:
                actions.append(CloneAction(
                    action_type=CloneActionType.DATABRICKS,
                    group_id=m.group_id,
                    group_name=m.group_name,
                    external_id=m.external_id,
                    path=m.path,
                    workspace_accesses=ws_names,
                ))
            elif m.group_id in uc_groups:
                actions.append(CloneAction(
                    action_type=CloneActionType.DATABRICKS,
                    group_id=m.group_id,
                    group_name=m.group_name,
                    external_id=m.external_id,
                    path=m.path,
                    workspace_accesses=[],
                    uc_grants_summary="UC grants detected (no workspace assignment)",
                ))
            elif scan_uc:
                # UC scan ran and found nothing — verified dead-end
                actions.append(CloneAction(
                    action_type=CloneActionType.SKIPPED,
                    group_id=m.group_id,
                    group_name=m.group_name,
                    external_id=m.external_id,
                    path=m.path,
                ))
            else:
                # No workspace assignment, UC not scanned — unverified
                actions.append(CloneAction(
                    action_type=CloneActionType.UNVERIFIED,
                    group_id=m.group_id,
                    group_name=m.group_name,
                    external_id=m.external_id,
                    path=m.path,
                ))

        return CloneReport(
            source_principal=source,
            target_principal=target,
            source_display_name=pname_s,
            target_display_name=pname_t,
            actions=actions,
        )

    def apply(self, report: CloneReport, target_id: str) -> None:
        """SCIM PATCH the target into every DATABRICKS-classified group.

        Mutates *report* in place: sets ``action.applied = True`` on success,
        ``action.error`` on failure.  IDP_REQUIRED, UNVERIFIED, and SKIPPED
        actions are left untouched.
        """
        for action in report.databricks_actions:
            try:
                self.api.account_api(
                    "PATCH",
                    f"/scim/v2/Groups/{action.group_id}",
                    json={
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [{
                            "op": "add",
                            "path": "members",
                            "value": [{"value": target_id}],
                        }],
                    },
                )
                action.applied = True
                log.info("Added target to group %s (%s)", action.group_name, action.group_id)
            except Exception as exc:
                action.error = str(exc)
                log.debug("Failed to add target to group %s: %s", action.group_name, exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _workspace_access_map(
        self,
        group_ids: Set[str],
        workspaces: List[WorkspaceInfo],
        max_workers: int,
    ) -> Dict[str, List[str]]:
        """Return {group_id: [workspace_name, ...]} for groups with workspace assignments."""
        result: Dict[str, List[str]] = {}

        def _check(ws: WorkspaceInfo) -> List[tuple]:
            found = []
            try:
                resp = self.api.account_api(
                    "GET",
                    f"/workspaces/{ws.workspace_id}/permissionassignments",
                )
                for pa in resp.get("permission_assignments", []):
                    pid = str(pa.get("principal", {}).get("principal_id", ""))
                    if pid in group_ids:
                        found.append((pid, ws.workspace_name))
            except Exception as exc:
                log.warning("permissionassignments failed for %s: %s", ws.workspace_name, exc)
            return found

        workers = max(1, min(max_workers, len(workspaces))) if workspaces else 1
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_check, ws): ws for ws in workspaces}
            for fut in as_completed(futures):
                for gid, ws_name in fut.result():
                    result.setdefault(gid, []).append(ws_name)

        return result

    def _groups_with_uc_grants(
        self,
        group_ids: Set[str],
        workspaces: List[WorkspaceInfo],
        max_workers: int,
    ) -> Set[str]:
        """Return subset of group_ids that have at least one UC catalog grant."""
        found: Set[str] = set()
        if not group_ids or not workspaces:
            return found

        # Need group names for matching against UC grant principals
        # Fetch them from account SCIM
        id_to_name: Dict[str, str] = {}
        for gid in group_ids:
            try:
                resp = self.api.account_api("GET", f"/scim/v2/Groups/{gid}")
                id_to_name[gid] = resp.get("displayName", gid)
            except Exception:
                id_to_name[gid] = gid

        target_names = set(id_to_name.values())
        target_names_lower = {n.lower() for n in target_names}

        def _scan_ws(ws: WorkspaceInfo) -> Set[str]:
            hits: Set[str] = set()
            try:
                catalogs = self.api.workspace_api(
                    ws.workspace_url, "GET", "/api/2.1/unity-catalog/catalogs"
                ).get("catalogs", [])
            except Exception:
                return hits

            for cat in catalogs:
                cname = cat.get("name", "")
                if not cname:
                    continue
                try:
                    grants = self.api.workspace_api(
                        ws.workspace_url, "GET",
                        f"/api/2.1/unity-catalog/permissions/catalog/{cname}",
                    ).get("privilege_assignments") or []
                except Exception:
                    continue

                for g in grants:
                    p = (g.get("principal") or "").replace("`", "").strip()
                    if p in target_names or p.lower() in target_names_lower:
                        # reverse-map name → id
                        for gid, gname in id_to_name.items():
                            if gname == p or gname.lower() == p.lower():
                                hits.add(gid)
                if hits == group_ids:
                    # Found all — no need to scan more catalogs
                    break

            return hits

        workers = max(1, min(max_workers, len(workspaces)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_scan_ws, ws) for ws in workspaces]
            for fut in as_completed(futures):
                found |= fut.result()
                if found >= group_ids:
                    break

        return found
