"""Principal-centric auditor — reverse lookup from user/SP/group.

Answers: "Given this principal, what groups are they in, which workspaces
can they reach, and what Unity Catalog permissions flow through each group?"
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from databricks_group_audit.client import AuditClient
from databricks_group_audit.models import (
    EffectivePermission,
    GroupMembership,
    MemberType,
    PrincipalAuditResult,
    WorkspaceInfo,
    WorkspaceRole,
)
from databricks_group_audit.workspace import WorkspaceDiscovery

log = logging.getLogger(__name__)


class PrincipalAuditor:
    """Audit a single principal's effective access across the account.

    Starting from a user email, service-principal app-ID / display name,
    or group display name, this class:

    1. Resolves **every group** the principal belongs to (direct + transitive).
    2. Checks **workspace permission assignments** for each group.
    3. Scans **Unity Catalog grants** (catalog / schema / table) that flow
       through those groups.
    4. Flags **dead-end groups** — memberships that contribute no workspace
       access through any path in the group hierarchy.
    """

    def __init__(
        self,
        api_client: AuditClient,
        workspace_discovery: Optional[WorkspaceDiscovery] = None,
        cloud_provider: str = "azure",
    ):
        self.api = api_client
        self.ws_discovery = workspace_discovery or WorkspaceDiscovery(api_client, cloud_provider)
        self.cloud_provider = cloud_provider.upper()

    # ------------------------------------------------------------------
    # Step 1 — Identify the principal
    # ------------------------------------------------------------------

    def find_principal(self, identifier: str) -> Tuple[str, str, str]:
        """Look up a principal by email, application ID, or display name.

        Returns ``(principal_type, principal_id, display_name)``.
        Raises ``ValueError`` when no match is found.
        """
        identifier = identifier.strip()

        # --- Try User by email ---
        if "@" in identifier:
            try:
                resp = self.api.account_api(
                    "GET", "/scim/v2/Users",
                    params={"filter": f'emails.value eq "{identifier}"'},
                )
                for u in resp.get("Resources", []):
                    return "USER", u["id"], u.get("displayName", identifier)
            except Exception as exc:
                log.warning("User lookup failed for '%s': %s", identifier, exc)

        # --- Try Service Principal by applicationId or displayName ---
        for filt in (
            f'applicationId eq "{identifier}"',
            f'displayName eq "{identifier}"',
        ):
            try:
                resp = self.api.account_api(
                    "GET", "/scim/v2/ServicePrincipals",
                    params={"filter": filt},
                )
                for sp in resp.get("Resources", []):
                    return "SERVICE_PRINCIPAL", sp["id"], sp.get("displayName", identifier)
            except Exception as exc:
                log.warning("SP lookup (%s) failed: %s", filt, exc)

        # --- Try Group by displayName ---
        try:
            resp = self.api.account_api(
                "GET", "/scim/v2/Groups",
                params={"filter": f'displayName eq "{identifier}"'},
            )
            for g in resp.get("Resources", []):
                return "GROUP", g["id"], g.get("displayName", identifier)
        except Exception as exc:
            log.warning("Group lookup failed for '%s': %s", identifier, exc)

        raise ValueError(f"Principal '{identifier}' not found as user, SP, or group.")

    # ------------------------------------------------------------------
    # Step 2 — Reverse group membership (BFS upward)
    # ------------------------------------------------------------------

    def resolve_group_memberships(
        self, principal_id: str, principal_type: str, principal_name: str,
    ) -> Tuple[List[GroupMembership], Dict[str, str]]:
        """Find every group the principal belongs to.

        Returns ``(memberships, id_to_name_map)``.
        """
        all_groups = self.api.scim_list_all("Groups")

        id_to_name: Dict[str, str] = {}
        child_to_parents: Dict[str, Set[str]] = {}

        for g in all_groups:
            gid = g.get("id", "")
            gname = g.get("displayName", "")
            id_to_name[gid] = gname
            for m in g.get("members", []):
                cid = m.get("value", "")
                if cid:
                    child_to_parents.setdefault(cid, set()).add(gid)

        direct_parent_ids = child_to_parents.get(principal_id, set())

        memberships: List[GroupMembership] = []
        visited: Set[str] = set()
        queue: deque[Tuple[str, List[str], bool]] = deque()

        for pid in direct_parent_ids:
            path = [principal_name, id_to_name.get(pid, pid)]
            queue.append((pid, path, True))

        while queue:
            gid, path, is_direct = queue.popleft()
            if gid in visited:
                continue
            visited.add(gid)
            gname = id_to_name.get(gid, gid)
            memberships.append(GroupMembership(
                group_id=gid, group_name=gname, path=list(path), is_direct=is_direct,
            ))
            for parent_id in child_to_parents.get(gid, set()):
                if parent_id not in visited:
                    queue.append((parent_id, path + [id_to_name.get(parent_id, parent_id)], False))

        return memberships, id_to_name

    # ------------------------------------------------------------------
    # Step 3 — Workspace permission assignments
    # ------------------------------------------------------------------

    def get_workspace_assignments(
        self,
        workspaces: List[WorkspaceInfo],
        principal_id: str,
        group_ids: Set[str],
        id_to_name: Dict[str, str],
    ) -> List[WorkspaceRole]:
        """Check each workspace for permission assignments matching the
        principal or any of their groups."""
        roles: List[WorkspaceRole] = []
        relevant_ids = group_ids | {principal_id}

        for ws in workspaces:
            try:
                resp = self.api.account_api(
                    "GET",
                    f"/workspaces/{ws.workspace_id}/permissionassignments",
                )
                for pa in resp.get("permission_assignments", []):
                    pid = str(pa.get("principal", {}).get("principal_id", ""))
                    if pid not in relevant_ids:
                        continue
                    for perm in pa.get("permissions", []):
                        via = id_to_name.get(pid, pid)
                        roles.append(WorkspaceRole(
                            workspace_id=ws.workspace_id,
                            workspace_name=ws.workspace_name,
                            workspace_url=ws.workspace_url,
                            permission_level=perm,
                            via_group=via if pid != principal_id else "(direct)",
                            via_group_id=pid,
                        ))
            except Exception as exc:
                log.warning("Failed to get assignments for workspace %s: %s", ws.workspace_name, exc)

        return roles

    # ------------------------------------------------------------------
    # Step 4 — Catalog / schema / table permissions per group
    # ------------------------------------------------------------------

    def scan_permissions(
        self,
        workspace_roles: List[WorkspaceRole],
        principal_name: str,
        group_names: Set[str],
        scan_schemas: bool = False,
        scan_tables: bool = False,
    ) -> List[EffectivePermission]:
        """For each workspace the principal can access, scan UC grants
        and return only those held by the principal or their groups.

        Deduplication is keyed on ``(workspace_url, catalog_name)`` so that
        identically-named catalogs in different workspaces / metastores are
        each scanned independently.  Principal matching is case-insensitive
        and strips backtick quoting uniformly at all securable levels.
        """
        perms: List[EffectivePermission] = []
        relevant = group_names | {principal_name}
        # Pre-compute lowercased set once — reused at catalog / schema / table levels
        relevant_lower = {n.lower() for n in relevant}

        def _matches(p: str) -> bool:
            """Backtick-strip + case-insensitive membership check."""
            clean = p.replace("`", "").strip()
            return p in relevant or clean in relevant or clean.lower() in relevant_lower

        seen_ws: Set[str] = set()
        # (workspace_url, catalog_name) — same semantics as CatalogPermissionScanner
        scanned_catalogs: Set[Tuple[str, str]] = set()

        for role in workspace_roles:
            if role.workspace_url in seen_ws:
                continue
            seen_ws.add(role.workspace_url)

            try:
                catalogs = self.api.workspace_api(
                    role.workspace_url, "GET", "/api/2.1/unity-catalog/catalogs",
                ).get("catalogs", [])
            except Exception:
                continue

            for cat in catalogs:
                cname = cat.get("name", "")
                if not cname:
                    continue
                cat_key = (role.workspace_url, cname)
                if cat_key in scanned_catalogs:
                    continue
                scanned_catalogs.add(cat_key)

                try:
                    cat_grants = self.api.workspace_api(
                        role.workspace_url, "GET",
                        f"/api/2.1/unity-catalog/permissions/catalog/{cname}",
                    ).get("privilege_assignments") or []
                except Exception:
                    cat_grants = []

                for g in cat_grants:
                    principal = g.get("principal", "")
                    privs = g.get("privileges") or []
                    if privs and _matches(principal):
                        perms.append(EffectivePermission(
                            securable_type="CATALOG", securable_name=cname,
                            privileges=privs, via_group=principal,
                            workspace_name=role.workspace_name,
                            workspace_url=role.workspace_url,
                        ))

                if not (scan_schemas or scan_tables):
                    continue

                # Schema-level grants
                try:
                    schemas = self.api.workspace_api(
                        role.workspace_url, "GET",
                        "/api/2.1/unity-catalog/schemas",
                        params={"catalog_name": cname},
                    ).get("schemas", [])
                except Exception:
                    schemas = []

                for sch in schemas:
                    sname = sch.get("name", "")
                    if not sname:
                        continue
                    full_schema = f"{cname}.{sname}"
                    try:
                        sgrants = self.api.workspace_api(
                            role.workspace_url, "GET",
                            f"/api/2.1/unity-catalog/permissions/schema/{full_schema}",
                        ).get("privilege_assignments") or []
                    except Exception:
                        sgrants = []

                    for sg in sgrants:
                        principal = sg.get("principal", "")
                        privs = sg.get("privileges") or []
                        if privs and _matches(principal):
                            perms.append(EffectivePermission(
                                securable_type="SCHEMA", securable_name=full_schema,
                                privileges=privs, via_group=principal,
                                workspace_name=role.workspace_name,
                                workspace_url=role.workspace_url,
                            ))

                    if not scan_tables:
                        continue

                    # Table / view-level grants
                    try:
                        tables = self.api.workspace_api(
                            role.workspace_url, "GET",
                            "/api/2.1/unity-catalog/tables",
                            params={"catalog_name": cname, "schema_name": sname},
                        ).get("tables", [])
                    except Exception:
                        tables = []

                    for tbl in tables:
                        tname = tbl.get("name", "")
                        if not tname:
                            continue
                        full_table = f"{cname}.{sname}.{tname}"
                        try:
                            tgrants = self.api.workspace_api(
                                role.workspace_url, "GET",
                                f"/api/2.1/unity-catalog/permissions/table/{full_table}",
                            ).get("privilege_assignments") or []
                        except Exception:
                            tgrants = []

                        for tg in tgrants:
                            principal = tg.get("principal", "")
                            privs = tg.get("privileges") or []
                            if privs and _matches(principal):
                                perms.append(EffectivePermission(
                                    securable_type="TABLE", securable_name=full_table,
                                    privileges=privs, via_group=principal,
                                    workspace_name=role.workspace_name,
                                    workspace_url=role.workspace_url,
                                ))

        return perms

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    def audit(
        self,
        identifier: str,
        explicit_workspace_urls: str = "",
        scan_schemas: bool = False,
        scan_tables: bool = False,
    ) -> PrincipalAuditResult:
        """Run a full principal audit.

        Parameters
        ----------
        identifier:
            User email, SP application ID / display name, or group name.
        explicit_workspace_urls:
            Comma-separated workspace URLs (empty = discover all).
        scan_schemas:
            Also scan schema-level grants.
        scan_tables:
            Also scan table/view-level grants (implies schema scan).
        """
        # 1. Identify
        ptype, pid, pname = self.find_principal(identifier)
        log.info("Principal: %s (%s, id=%s)", pname, ptype, pid)

        # 2. Resolve group memberships
        memberships, id_to_name = self.resolve_group_memberships(pid, ptype, pname)
        group_ids = {m.group_id for m in memberships}
        group_names = {m.group_name for m in memberships}
        log.info("Found %d group membership(s)", len(memberships))

        # 3. Discover workspaces
        workspaces = self.ws_discovery.discover(explicit_workspace_urls)

        # 4. Workspace assignments
        ws_roles = self.get_workspace_assignments(workspaces, pid, group_ids, id_to_name)
        log.info("Found %d workspace role(s)", len(ws_roles))

        # 5. Dead-end groups — groups that provide no workspace access through any path.
        #
        # A group G is NOT a dead end when:
        #   a) G itself is directly assigned to a workspace, OR
        #   b) G is a transitive *ancestor* of a workspace-assigned group in
        #      the principal's membership hierarchy (i.e. a workspace-assigned
        #      group appears between the principal and G in the BFS upward path,
        #      meaning the principal reaches workspace access through a child of G).
        #
        # We use a name→ids multimap to handle the edge case where two groups
        # share the same display name but have different IDs.
        groups_with_access = {r.via_group_id for r in ws_roles if r.via_group != "(direct)"}

        name_to_ids: Dict[str, Set[str]] = {}
        for m in memberships:
            name_to_ids.setdefault(m.group_name, set()).add(m.group_id)

        dead_ends: List[str] = []
        for m in memberships:
            if m.group_id in groups_with_access:
                continue
            # m.path = [principal_name, ..., m.group_name]
            # path[1:-1] are intermediate groups — descendants of m in the hierarchy.
            # If any of them has workspace access, m transitively enables access.
            path_has_access = any(
                name_to_ids.get(name, set()) & groups_with_access
                for name in m.path[1:-1]
            )
            if not path_has_access:
                dead_ends.append(m.group_name)

        # 6. Scan UC permissions
        perms = self.scan_permissions(
            ws_roles, pname, group_names,
            scan_schemas=scan_schemas or scan_tables,
            scan_tables=scan_tables,
        )
        log.info("Found %d UC permission(s)", len(perms))

        return PrincipalAuditResult(
            principal_type=ptype,
            principal_id=pid,
            principal_name=pname,
            groups=memberships,
            workspace_roles=ws_roles,
            permissions=perms,
            dead_end_groups=dead_ends,
        )
