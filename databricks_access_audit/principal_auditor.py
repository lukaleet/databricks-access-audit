"""Principal-centric auditor — reverse lookup from user/SP/group.

Answers: "Given this principal, what groups are they in, which workspaces
can they reach, and what Unity Catalog permissions flow through each group?"
"""

from __future__ import annotations

import logging
import sys
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

from databricks_access_audit.client import AuditClient, _scim_filter_escape
from databricks_access_audit.group_resolver import GroupMembershipResolver
from databricks_access_audit.models import (
    EffectivePermission,
    GroupMembership,
    PrincipalAuditResult,
    WorkspaceInfo,
    WorkspaceRole,
)
from databricks_access_audit.workspace import WorkspaceDiscovery

log = logging.getLogger(__name__)


class PrincipalAuditor:
    """Audit a single principal's effective access across the account.

    Starting from a user email, service-principal app-ID / display name,
    or group display name, this class:

    1. Resolves **every group** the principal belongs to (direct + transitive).
    2. Checks **workspace permission assignments** for each group.
    3. Scans **Unity Catalog grants** (catalog / schema / table) that flow
       through those groups.
    4. Flags **workspace-unassigned groups** — memberships that contribute no workspace
       access through any path in the group hierarchy.
    """

    def __init__(
        self,
        api_client: AuditClient,
        workspace_discovery: Optional[WorkspaceDiscovery] = None,
        cloud_provider: str = "azure",
        group_resolver: Optional[GroupMembershipResolver] = None,
    ):
        self.api = api_client
        self.ws_discovery = workspace_discovery or WorkspaceDiscovery(api_client, cloud_provider)
        self.cloud_provider = cloud_provider.upper()
        self._group_resolver = group_resolver or GroupMembershipResolver(api_client)

    # ------------------------------------------------------------------
    # Step 1 — Identify the principal
    # ------------------------------------------------------------------

    def find_principal(self, identifier: str) -> Tuple[str, str, str, Optional[str], str]:
        """Look up a principal by email, application ID, or display name.

        Returns ``(principal_type, principal_id, display_name, external_id, uc_name)``.
        ``external_id`` is the SCIM ``externalId`` field — non-empty when the
        principal was provisioned by an external IdP.
        ``uc_name`` is the identifier used in Unity Catalog grant entries —
        for users this is the SCIM ``userName`` (which may differ from the email
        passed in, e.g. Azure AD guest UPNs like ``user_gmail.com#ext#@tenant``),
        for SPs and groups it equals the display name.
        Raises ``ValueError`` when no match is found.
        """
        identifier = identifier.strip()

        # --- Try User by email ---
        if "@" in identifier:
            try:
                resp = self.api.account_api(
                    "GET", "/scim/v2/Users",
                    params={"filter": f'emails.value eq "{_scim_filter_escape(identifier)}"'},
                )
                for u in resp.get("Resources", []):
                    uc_name = u.get("userName") or identifier
                    return ("USER", u["id"], u.get("displayName", identifier),
                            u.get("externalId") or None, uc_name)
            except Exception as exc:
                log.warning("User lookup failed for '%s': %s", identifier, exc)

        # --- Try Service Principal by applicationId or displayName ---
        safe = _scim_filter_escape(identifier)
        for filt in (
            f'applicationId eq "{safe}"',
            f'displayName eq "{safe}"',
        ):
            try:
                resp = self.api.account_api(
                    "GET", "/scim/v2/ServicePrincipals",
                    params={"filter": filt},
                )
                for sp in resp.get("Resources", []):
                    dname = sp.get("displayName", identifier)
                    return ("SERVICE_PRINCIPAL", sp["id"], dname,
                            sp.get("externalId") or None, dname)
            except Exception as exc:
                log.warning("SP lookup (%s) failed: %s", filt, exc)

        # --- Try Group by displayName ---
        try:
            resp = self.api.account_api(
                "GET", "/scim/v2/Groups",
                params={"filter": f'displayName eq "{_scim_filter_escape(identifier)}"'},
            )
            for g in resp.get("Resources", []):
                dname = g.get("displayName", identifier)
                return ("GROUP", g["id"], dname, g.get("externalId") or None, dname)
        except Exception as exc:
            log.warning("Group lookup failed for '%s': %s", identifier, exc)

        raise ValueError(f"Principal '{identifier}' not found as user, SP, or group.")

    # ------------------------------------------------------------------
    # Step 1b — Alternate identity resolution (B2B guest users)
    # ------------------------------------------------------------------

    def _resolve_alternate_identities(
        self,
        principal_type: str,
        principal_id: str,
        principal_name: str,
        external_id: Optional[str],
        workspaces: List[WorkspaceInfo],
        max_workers: int = 8,
    ) -> Tuple[Set[str], Set[str]]:
        """Discover alternate account SCIM records for the same physical person.

        Azure AD B2B guest users appear in workspace SCIM under a guest UPN
        (e.g. ``user_gmail.com#EXT#@tenant.onmicrosoft.com``) that is a
        *different* account SCIM record from their home-tenant email record.
        Group memberships and UC grants may be stored against either identity.

        Strategy:
        1. Search workspace SCIM on each workspace by ``externalId`` (supported
           there) to discover B2B UPN aliases.
        2. Look each alias up in account SCIM by ``userName`` (supported) to get
           the alternate account SCIM ID for BFS.

        Returns ``(alternate_account_ids, alternate_usernames)``.
        """
        if principal_type != "USER" or not workspaces:
            return set(), set()

        # Step 1 — collect B2B UPN aliases from all workspaces in parallel
        known: Set[str] = {principal_name}
        ws_aliases: Set[str] = set()

        def _aliases_for_ws(ws: WorkspaceInfo) -> Set[str]:
            return self._get_workspace_principal_aliases(
                ws.workspace_url, principal_type, principal_id,
                known_identities=known,
                external_id=external_id,
            )

        with ThreadPoolExecutor(max_workers=min(max_workers, len(workspaces))) as ex:
            for result in ex.map(_aliases_for_ws, workspaces):
                ws_aliases |= result

        if not ws_aliases:
            return set(), set()

        # Step 2 — look up each alias in account SCIM by userName
        alt_ids: Set[str] = set()
        for username in ws_aliases:
            try:
                resp = self.api.account_api(
                    "GET", "/scim/v2/Users",
                    params={"filter": f'userName eq "{_scim_filter_escape(username)}"'},
                )
                for u in resp.get("Resources", []):
                    uid = u.get("id", "")
                    if uid and uid != principal_id:
                        alt_ids.add(uid)
                        log.info(
                            "Alternate account SCIM record for %s: id=%s userName=%s",
                            principal_name, uid, username,
                        )
            except Exception as exc:
                log.debug(
                    "Account SCIM userName lookup for '%s' failed: %s", username, exc,
                )

        return alt_ids, ws_aliases

    # ------------------------------------------------------------------
    # Step 2 — Reverse group membership (BFS upward)
    # ------------------------------------------------------------------

    def resolve_group_memberships(
        self, principal_id: str, principal_type: str, principal_name: str,
    ) -> Tuple[List[GroupMembership], Dict[str, str]]:
        """Find every group the principal belongs to.

        Returns ``(memberships, id_to_name_map)``.

        Delegates the O(N) group-membership fetch to the shared
        :class:`~databricks_access_audit.group_resolver.GroupMembershipResolver`,
        which parallelises individual GETs and caches the result for the
        lifetime of the resolver.  Sharing a resolver instance with the catalog
        scanner means the expensive fetch happens once per session rather than
        once per auditor step.
        """
        id_to_name, id_to_external, child_to_parents = (
            self._group_resolver.get_group_membership_map()
        )

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
                external_id=id_to_external.get(gid),
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
        max_workers: int = 8,
        group_id_to_path: Optional[Dict[str, List[str]]] = None,
    ) -> List[WorkspaceRole]:
        """Check each workspace for permission assignments matching the
        principal or any of their groups.

        Each workspace is queried in parallel via ``ThreadPoolExecutor``.
        ``id_to_name``, ``relevant_ids``, and ``group_id_to_path`` are
        read-only during parallel execution so no locking is required.
        """
        if not workspaces:
            return []

        relevant_ids = group_ids | {principal_id}
        _paths = group_id_to_path or {}

        def _check_one(ws: WorkspaceInfo) -> List[WorkspaceRole]:
            result: List[WorkspaceRole] = []
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
                        is_direct = pid == principal_id
                        result.append(WorkspaceRole(
                            workspace_id=ws.workspace_id,
                            workspace_name=ws.workspace_name,
                            workspace_url=ws.workspace_url,
                            permission_level=perm,
                            via_group=via if not is_direct else "(direct)",
                            via_group_id=pid,
                            via_path=_paths.get(pid, []) if not is_direct else [],
                        ))
            except Exception as exc:
                log.warning(
                    "Failed to get assignments for workspace %s: %s", ws.workspace_name, exc
                )
                print(
                    f"WARNING  workspace '{ws.workspace_name}' assignments skipped: {exc}",
                    file=sys.stderr,
                )
            return result

        workers = max(1, min(max_workers, len(workspaces)))
        roles: List[WorkspaceRole] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_check_one, ws): ws for ws in workspaces}
            for fut in as_completed(futures):
                roles.extend(fut.result())
        return roles

    # ------------------------------------------------------------------
    # Step 4 — Catalog / schema / table permissions per group
    # ------------------------------------------------------------------

    def _scan_one_workspace(
        self,
        role: WorkspaceRole,
        relevant: Set[str],
        relevant_lower: Set[str],
        scan_schemas: bool,
        scan_tables: bool,
        group_name_to_path: Optional[Dict[str, List[str]]] = None,
    ) -> List[EffectivePermission]:
        """Scan UC grants for a single workspace role.

        All arguments are read-only; ``scanned_catalogs`` is local so this
        method is safe to run concurrently with other workspace scans.
        """
        _paths = group_name_to_path or {}

        def _matches(p: str) -> bool:
            clean = p.replace("`", "").strip()
            return p in relevant or clean in relevant or clean.lower() in relevant_lower

        def _path_for(p: str) -> List[str]:
            clean = p.replace("`", "").strip()
            return _paths.get(p) or _paths.get(clean) or _paths.get(clean.lower()) or []

        perms: List[EffectivePermission] = []
        # Catalog names within one workspace are unique, so a plain set suffices.
        scanned_catalogs: Set[str] = set()

        try:
            catalogs = self.api.workspace_api(
                role.workspace_url, "GET", "/api/2.1/unity-catalog/catalogs",
            ).get("catalogs", [])
        except Exception:
            return perms

        for cat in catalogs:
            cname = cat.get("name", "")
            if not cname or cname in scanned_catalogs:
                continue
            scanned_catalogs.add(cname)

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
                        via_path=_path_for(principal),
                    ))

            if not (scan_schemas or scan_tables):
                continue

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
                            via_path=_path_for(principal),
                        ))

                if not scan_tables:
                    continue

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
                                via_path=_path_for(principal),
                            ))

        return perms

    def scan_permissions(
        self,
        workspace_roles: List[WorkspaceRole],
        principal_name: str,
        group_names: Set[str],
        scan_schemas: bool = False,
        scan_tables: bool = False,
        max_workers: int = 8,
        principal_aliases: Optional[Set[str]] = None,
        group_name_to_path: Optional[Dict[str, List[str]]] = None,
    ) -> List[EffectivePermission]:
        """For each workspace the principal can access, scan UC grants
        and return only those held by the principal or their groups.

        Duplicate workspace URLs (same workspace via multiple group paths) are
        deduplicated upfront before dispatch.  Each unique workspace is then
        scanned in parallel via ``ThreadPoolExecutor``; catalog-level dedup
        is local to each workspace scan so no locking is needed.

        Principal matching is case-insensitive and strips backtick quoting
        uniformly at all securable levels.

        ``principal_aliases`` supplements ``principal_name`` with additional
        identifiers for the same principal (e.g. the SCIM ``userName`` for Azure
        AD guest users whose UC grants are stored under their UPN rather than
        their display name).
        """
        relevant = group_names | {principal_name} | (principal_aliases or set())
        relevant_lower = {n.lower() for n in relevant}

        # Deduplicate by workspace URL; first occurrence keeps the workspace metadata.
        seen_ws: Set[str] = set()
        unique_roles: List[WorkspaceRole] = []
        for role in workspace_roles:
            if role.workspace_url not in seen_ws:
                seen_ws.add(role.workspace_url)
                unique_roles.append(role)

        if not unique_roles:
            return []

        workers = max(1, min(max_workers, len(unique_roles)))
        perms: List[EffectivePermission] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    self._scan_one_workspace,
                    role, relevant, relevant_lower, scan_schemas, scan_tables,
                    group_name_to_path,
                ): role
                for role in unique_roles
            }
            for fut in as_completed(futures):
                perms.extend(fut.result())

        return perms

    # ------------------------------------------------------------------
    # Workspace-level identity resolution (Azure AD B2B guest alias)
    # ------------------------------------------------------------------

    def _get_workspace_principal_aliases(
        self,
        workspace_url: str,
        principal_type: str,
        principal_id: str,
        known_identities: Set[str],
        external_id: Optional[str] = None,
    ) -> Set[str]:
        """Return additional workspace-level userNames for this principal.

        Azure AD B2B guest users have **two** workspace SCIM records:

        1. The account-synced record (same ID as account SCIM; ``userName``
           equals the account email, e.g. ``alice@gmail.com``).
        2. The Azure AD guest record (different ID; ``userName`` equals the
           B2B guest UPN, e.g. ``alice_gmail.com#EXT#@tenant.onmicrosoft.com``).

        Workspace object ACLs are stored under the **guest UPN**, so the
        account email alone will never match those entries.

        When ``external_id`` is provided (the SCIM ``externalId`` field from
        the account record), we search workspace SCIM by
        ``externalId eq "{external_id}"``; this returns *both* records and lets
        us discover the guest UPN.  When ``external_id`` is absent we fall back
        to a direct ``/Users/{principal_id}`` lookup.

        Returns the set of workspace userNames **not already in**
        ``known_identities`` (case-insensitive).  Returns an empty set for
        non-users or on any API failure.
        """
        if principal_type != "USER":
            return set()

        known_lower = {k.lower() for k in known_identities}
        aliases: Set[str] = set()

        try:
            if external_id:
                resp = self.api.workspace_api(
                    workspace_url, "GET",
                    "/api/2.0/preview/scim/v2/Users",
                    params={"filter": f'externalId eq "{external_id}"'},
                )
                for user in resp.get("Resources", []):
                    ws_username = (user.get("userName") or "").strip()
                    if ws_username and ws_username.lower() not in known_lower:
                        aliases.add(ws_username)
            else:
                resp = self.api.workspace_api(
                    workspace_url, "GET",
                    f"/api/2.0/preview/scim/v2/Users/{principal_id}",
                )
                ws_username = (resp.get("userName") or "").strip()
                if ws_username and ws_username.lower() not in known_lower:
                    aliases.add(ws_username)
        except Exception as exc:
            log.debug(
                "Workspace SCIM lookup for %s on %s failed (aliases skipped): %s",
                principal_id, workspace_url, exc,
            )

        return aliases

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    def audit(
        self,
        identifier: str,
        explicit_workspace_urls: str = "",
        scan_schemas: bool = False,
        scan_tables: bool = False,
        scan_workspace_objects: bool = False,
        workspace_object_types: Optional[List[str]] = None,
        max_workers: int = 8,
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
        scan_workspace_objects:
            Also scan workspace-level object permissions (jobs, clusters,
            SQL warehouses, pipelines, cluster policies).
        workspace_object_types:
            Subset of object types to scan when *scan_workspace_objects* is set.
            ``None`` = all 13 types.  See ``ALL_OBJECT_TYPES`` in
            ``workspace_object_scanner`` for the full list.
        max_workers:
            Maximum number of parallel threads for workspace and UC scanning.
        """
        # 1. Identify
        ptype, pid, pname, p_ext_id, p_uc_name = self.find_principal(identifier)
        log.info("Principal: %s (%s, id=%s, source=%s)", pname, ptype, pid,
                 "external" if p_ext_id else "internal")

        # 2. Discover workspaces (moved before BFS so alias resolution can use
        # workspace SCIM to find B2B guest UPN records)
        workspaces = self.ws_discovery.discover(explicit_workspace_urls)

        # 1b. Alternate identity resolution — Azure AD B2B guests appear in
        # workspace SCIM under a guest UPN that is a separate account SCIM record.
        # Group memberships and UC grants may be stored against that identity.
        # Uses workspace SCIM (externalId filter supported) → account SCIM by userName.
        alt_ids: Set[str] = set()
        alt_uc_names: Set[str] = set()
        if ptype == "USER":
            alt_ids, alt_uc_names = self._resolve_alternate_identities(
                ptype, pid, pname, p_ext_id, workspaces, max_workers,
            )
            if alt_ids:
                log.info(
                    "Found %d alternate identity record(s) for %s",
                    len(alt_ids), pname,
                )

        # 3. Resolve group memberships — BFS from primary ID, then from any alternate
        # IDs (B2B guest records); merge, deduplicating by group_id.
        memberships, id_to_name = self.resolve_group_memberships(pid, ptype, pname)
        if alt_ids:
            seen_group_ids = {m.group_id for m in memberships}
            for alt_id in alt_ids:
                alt_memberships, alt_id_map = self.resolve_group_memberships(
                    alt_id, ptype, pname,
                )
                id_to_name.update(alt_id_map)
                for m in alt_memberships:
                    if m.group_id not in seen_group_ids:
                        memberships.append(m)
                        seen_group_ids.add(m.group_id)
        group_ids = {m.group_id for m in memberships}
        group_names = {m.group_name for m in memberships}
        log.info("Found %d group membership(s)", len(memberships))

        # Path maps built once from the BFS result — O(1) lookup at every
        # workspace and UC grant match site; zero additional API calls.
        group_id_to_path: Dict[str, List[str]] = {m.group_id: m.path for m in memberships}
        group_name_to_path: Dict[str, List[str]] = {m.group_name: m.path for m in memberships}

        # 4. Workspace assignments
        ws_roles = self.get_workspace_assignments(
            workspaces, pid, group_ids, id_to_name,
            max_workers=max_workers,
            group_id_to_path=group_id_to_path,
        )
        log.info("Found %d workspace role(s)", len(ws_roles))

        # 5. Groups with no workspace assignment — provide no workspace access through any path.
        # Note: these may still hold UC grants (catalog/schema/table level) without being
        # assigned to a workspace — a valid UC-only access pattern.
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
        # p_uc_name may differ from pname for Azure AD guest users whose UC
        # grants are stored under their tenant UPN (user_gmail.com#ext#@tenant).
        # alt_uc_names adds userNames from any alternate account SCIM records
        # (B2B guest UPNs) so direct grants stored under those identities are found.
        aliases: Set[str] = {p_uc_name} if p_uc_name != pname else set()
        aliases |= alt_uc_names
        perms = self.scan_permissions(
            ws_roles, pname, group_names,
            scan_schemas=scan_schemas or scan_tables,
            scan_tables=scan_tables,
            max_workers=max_workers,
            principal_aliases=aliases,
            group_name_to_path=group_name_to_path,
        )
        log.info("Found %d UC permission(s)", len(perms))

        # 7. Scan workspace object permissions (optional)
        ws_obj_grants = []
        if scan_workspace_objects:
            from databricks_access_audit.workspace_object_scanner import WorkspaceObjectScanner
            obj_scanner = WorkspaceObjectScanner(self.api, self._group_resolver)

            # Build URL → WorkspaceInfo from ws_roles first, then supplement with
            # all discovered workspaces.  Principals may reach workspaces through
            # implicit built-in groups (e.g. "account users") that don't appear in
            # permissionassignments, so relying solely on ws_roles would miss those
            # workspaces entirely and produce a spurious zero-grant result.
            ws_infos: Dict[str, WorkspaceInfo] = {}
            for role in ws_roles:
                if role.workspace_url not in ws_infos:
                    ws_infos[role.workspace_url] = WorkspaceInfo(
                        workspace_id=role.workspace_id,
                        deployment_name="",
                        workspace_name=role.workspace_name,
                        workspace_url=role.workspace_url,
                        cloud=self.cloud_provider,
                        region="",
                    )
            for ws in workspaces:
                if ws.workspace_url not in ws_infos:
                    ws_infos[ws.workspace_url] = ws

            for ws_url, ws_info in ws_infos.items():
                ws_aliases = self._get_workspace_principal_aliases(
                    ws_url, ptype, pid,
                    known_identities={pname} | aliases,
                    external_id=p_ext_id,
                )
                effective_aliases = aliases | ws_aliases
                ws_obj_grants.extend(
                    obj_scanner.scan_workspace_for_principal(
                        ws_info, pname, group_names,
                        principal_aliases=effective_aliases,
                        object_types=workspace_object_types,
                        max_workers=max_workers,
                    )
                )
            log.info("Found %d workspace object grant(s)", len(ws_obj_grants))

        # Split workspace-unassigned groups into two buckets now that UC perms are known.
        # A group that appears as via_group in any UC permission is intentionally UC-only.
        groups_providing_uc = {p.via_group for p in perms}
        truly_dead = [g for g in dead_ends if g not in groups_providing_uc]
        uc_only = [g for g in dead_ends if g in groups_providing_uc]

        return PrincipalAuditResult(
            principal_type=ptype,
            principal_id=pid,
            principal_name=pname,
            principal_external_id=p_ext_id,
            groups=memberships,
            workspace_roles=ws_roles,
            permissions=perms,
            dead_end_groups=truly_dead,
            uc_only_groups=uc_only,
            workspace_object_grants=ws_obj_grants,
        )
