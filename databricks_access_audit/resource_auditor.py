"""Resource-centric auditor — 'who has access to this resource?'"""

from __future__ import annotations

import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from databricks_access_audit.client import AuditClient, _scim_filter_escape
from databricks_access_audit.group_resolver import GroupMembershipResolver
from databricks_access_audit.models import (
    PrincipalSource,
    ResourceAuditResult,
    ResourceGrant,
)
from databricks_access_audit.workspace import WorkspaceDiscovery

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

log = logging.getLogger(__name__)


def detect_resource_type(name: str) -> str:
    """Auto-detect resource type from the name format.

    - starts with https:// or contains "databricks" → "workspace"
    - 0 dots → "catalog"
    - 1 dot  → "schema"
    - 2+ dots → "table"
    """
    n = name.strip()
    if n.startswith("https://") or "databricks" in n.lower():
        return "workspace"
    dot_count = n.count(".")
    if dot_count == 0:
        return "catalog"
    if dot_count == 1:
        return "schema"
    return "table"


class ResourceAuditor:
    """Audit a single resource to discover who has access to it."""

    def __init__(
        self,
        api: AuditClient,
        account_id: str,
        cloud: str = "azure",
    ):
        self.api = api
        self.account_id = account_id
        self.cloud = cloud
        self._principal_type_cache: Dict[str, Tuple[str, PrincipalSource]] = {}

    # ------------------------------------------------------------------
    # Principal classification
    # ------------------------------------------------------------------

    def _classify_principal(
        self, name: str
    ) -> Tuple[str, PrincipalSource]:
        """Return (principal_type, principal_source) for a principal name.

        Classification order:
        1. Cache hit → return immediately.
        2. Email heuristic (@) → try SCIM user lookup.
        3. Group lookup.
        4. Service Principal lookup.
        5. Default to GROUP / INTERNAL.
        """
        if name in self._principal_type_cache:
            return self._principal_type_cache[name]

        result: Tuple[str, PrincipalSource] = ("GROUP", PrincipalSource.INTERNAL)

        # UUID-shaped name → service principal applicationId (used in UC grants).
        # Groups and users never have UUID-format identifiers.
        if _UUID_RE.match(name):
            result = ("SERVICE_PRINCIPAL", PrincipalSource.INTERNAL)
            self._principal_type_cache[name] = result
            return result

        # Email heuristic: try user first
        if "@" in name:
            try:
                resp = self.api.account_api(
                    "GET", "/scim/v2/Users",
                    params={"filter": f'userName eq "{_scim_filter_escape(name)}"'},
                )
                for u in resp.get("Resources", []):
                    ext = u.get("externalId") or None
                    src = PrincipalSource.EXTERNAL if ext else PrincipalSource.INTERNAL
                    result = ("USER", src)
                    self._principal_type_cache[name] = result
                    return result
            except Exception as exc:
                log.debug("User SCIM lookup failed for '%s': %s", name, exc)

            # Fallback: also try email search via emails.value
            try:
                resp = self.api.account_api(
                    "GET", "/scim/v2/Users",
                    params={"filter": f'emails.value eq "{_scim_filter_escape(name)}"'},
                )
                for u in resp.get("Resources", []):
                    ext = u.get("externalId") or None
                    src = PrincipalSource.EXTERNAL if ext else PrincipalSource.INTERNAL
                    result = ("USER", src)
                    self._principal_type_cache[name] = result
                    return result
            except Exception as exc:
                log.debug("User email SCIM lookup failed for '%s': %s", name, exc)

        # Try group lookup
        try:
            resp = self.api.account_api(
                "GET", "/scim/v2/Groups",
                params={"filter": f'displayName eq "{_scim_filter_escape(name)}"'},
            )
            for g in resp.get("Resources", []):
                ext = g.get("externalId") or None
                src = PrincipalSource.EXTERNAL if ext else PrincipalSource.INTERNAL
                result = ("GROUP", src)
                self._principal_type_cache[name] = result
                return result
        except Exception as exc:
            log.debug("Group SCIM lookup failed for '%s': %s", name, exc)

        # Try service principal lookup
        try:
            resp = self.api.account_api(
                "GET", "/scim/v2/ServicePrincipals",
                params={"filter": f'displayName eq "{_scim_filter_escape(name)}"'},
            )
            for sp in resp.get("Resources", []):
                ext = sp.get("externalId") or None
                src = PrincipalSource.EXTERNAL if ext else PrincipalSource.INTERNAL
                result = ("SERVICE_PRINCIPAL", src)
                self._principal_type_cache[name] = result
                return result
        except Exception as exc:
            log.debug("SP SCIM lookup failed for '%s': %s", name, exc)

        self._principal_type_cache[name] = result
        return result

    # ------------------------------------------------------------------
    # Group expansion
    # ------------------------------------------------------------------

    def _expand_group(self, group_name: str) -> List[Dict]:
        """Expand a group to its individual members.

        Returns a list of dicts with keys: name, type, source.
        Returns [] silently on any error.
        """
        try:
            resolver = GroupMembershipResolver(self.api)
            node = resolver.resolve_group(group_name)
            if not node:
                return []
            members = resolver.get_all_members_flat(node)
            result = []
            for u in members.get("users", []):
                name = u.email or u.display_name
                result.append({
                    "name": name,
                    "type": "USER",
                    "source": u.source,
                })
            for sp in members.get("service_principals", []):
                result.append({
                    "name": sp.display_name,
                    "type": "SERVICE_PRINCIPAL",
                    "source": sp.source,
                })
            return result
        except Exception as exc:
            log.debug("Group expansion failed for '%s': %s", group_name, exc)
            return []

    # ------------------------------------------------------------------
    # UC resource scan
    # ------------------------------------------------------------------

    def _scan_uc_resource(
        self,
        workspace,
        resource_type: str,
        resource_name: str,
        expand_groups: bool,
    ) -> List[ResourceGrant]:
        """Scan Unity Catalog permissions for a specific resource on one workspace.

        Returns [] silently on any error (not every workspace has UC or the
        specific catalog/schema/table).
        """
        try:
            resp = self.api.workspace_api(
                workspace.workspace_url,
                "GET",
                f"/api/2.1/unity-catalog/permissions/{resource_type}/{resource_name}",
            )
        except Exception as exc:
            log.debug(
                "UC scan skipped for %s/%s on %s: %s",
                resource_type, resource_name, workspace.workspace_name, exc,
            )
            return []

        grants: List[ResourceGrant] = []
        rt = resource_type.upper()
        for assignment in resp.get("privilege_assignments", []):
            principal_name = assignment.get("principal", "")
            if not principal_name:
                continue
            privileges = assignment.get("privileges", [])
            if not privileges:
                continue

            principal_type, principal_source = self._classify_principal(principal_name)

            # Direct grant
            grants.append(ResourceGrant(
                resource_type=rt,
                resource_name=resource_name,
                principal_name=principal_name,
                principal_type=principal_type,
                principal_source=principal_source,
                privileges=list(privileges),
                via_group=None,
                workspace_name=workspace.workspace_name,
            ))

            # Expand groups to individual members
            if expand_groups and principal_type == "GROUP":
                for member in self._expand_group(principal_name):
                    grants.append(ResourceGrant(
                        resource_type=rt,
                        resource_name=resource_name,
                        principal_name=member["name"],
                        principal_type=member["type"],
                        principal_source=member["source"],
                        privileges=list(privileges),
                        via_group=principal_name,
                        workspace_name=workspace.workspace_name,
                    ))

        return grants

    # ------------------------------------------------------------------
    # Workspace permission scan
    # ------------------------------------------------------------------

    def _scan_workspace_resource(
        self,
        workspace,
        expand_groups: bool,
    ) -> List[ResourceGrant]:
        """Scan workspace-level permission assignments for one workspace.

        Prints a warning to stderr on failure.
        """
        try:
            resp = self.api.account_api(
                "GET",
                f"/workspaces/{workspace.workspace_id}/permissionassignments",
            )
        except Exception as exc:
            print(
                f"WARNING  Could not get permission assignments for "
                f"workspace '{workspace.workspace_name}': {exc}",
                file=sys.stderr,
            )
            return []

        grants: List[ResourceGrant] = []
        for assignment in resp.get("permission_assignments", []):
            principal = assignment.get("principal", {})
            # Prefer user_name (email) over display_name — it's unique per
            # identity and triggers the @ heuristic in _classify_principal.
            # display_name is shared across B2B guest duplicates.
            principal_name = (
                principal.get("user_name")
                or principal.get("service_principal_name")
                or principal.get("display_name")
                or ""
            )
            if not principal_name:
                continue

            permissions = assignment.get("permissions", [])
            if not permissions:
                continue

            # permissions is a list of strings e.g. ["ADMIN"] from the Account API
            privileges = [
                p if isinstance(p, str) else p.get("permission_level", "")
                for p in permissions
                if p
            ]
            if not privileges:
                continue

            principal_type, principal_source = self._classify_principal(principal_name)

            # Direct assignment
            grants.append(ResourceGrant(
                resource_type="WORKSPACE",
                resource_name=workspace.workspace_name,
                principal_name=principal_name,
                principal_type=principal_type,
                principal_source=principal_source,
                privileges=privileges,
                via_group=None,
                workspace_name=workspace.workspace_name,
            ))

            # Expand groups to individual members
            if expand_groups and principal_type == "GROUP":
                for member in self._expand_group(principal_name):
                    grants.append(ResourceGrant(
                        resource_type="WORKSPACE",
                        resource_name=workspace.workspace_name,
                        principal_name=member["name"],
                        principal_type=member["type"],
                        principal_source=member["source"],
                        privileges=privileges,
                        via_group=principal_name,
                        workspace_name=workspace.workspace_name,
                    ))

        return grants

    # ------------------------------------------------------------------
    # Main audit
    # ------------------------------------------------------------------

    def audit(
        self,
        resource_name: str,
        resource_type: Optional[str] = None,
        expand_groups: bool = True,
        explicit_workspace_urls: str = "",
        max_workers: int = 8,
    ) -> ResourceAuditResult:
        """Run a resource-centric audit.

        Auto-detects resource_type when not supplied.
        For UC resources: scans all workspaces in parallel, deduplicates.
        For workspace resources: finds workspace by name or URL match.

        Raises ValueError when a workspace resource is not found.
        """
        if resource_type is None:
            resource_type = detect_resource_type(resource_name)

        rt_lower = resource_type.lower()

        discovery = WorkspaceDiscovery(self.api, cloud_provider=self.cloud)
        workspaces = discovery.discover(explicit_workspace_urls)

        result = ResourceAuditResult(
            resource_type=resource_type.upper(),
            resource_name=resource_name,
        )

        if rt_lower == "workspace":
            # Find workspace by name or URL match
            target = None
            name_lower = resource_name.strip().lower()
            for ws in workspaces:
                if (
                    ws.workspace_name.lower() == name_lower
                    or ws.workspace_url.lower().rstrip("/") == name_lower.rstrip("/")
                    or ws.deployment_name.lower() == name_lower
                ):
                    target = ws
                    break

            if target is None:
                available = ", ".join(ws.workspace_name for ws in workspaces[:10])
                raise ValueError(
                    f"Workspace '{resource_name}' not found. "
                    f"Available workspaces: {available}"
                )

            raw = self._scan_workspace_resource(target, expand_groups)
            seen: set = set()
            deduped: List[ResourceGrant] = []
            for g in raw:
                key = (g.principal_name, g.via_group or "", frozenset(g.privileges))
                if key not in seen:
                    seen.add(key)
                    deduped.append(g)
            result.grants = deduped
            return result

        # UC resource: scan all workspaces in parallel
        # Map resource_type to UC securable_type path segment
        uc_type_map = {
            "catalog": "catalog",
            "schema": "schema",
            "table": "table",
        }
        uc_type = uc_type_map.get(rt_lower, rt_lower)

        all_grants: List[ResourceGrant] = []
        workers = max(1, min(max_workers, len(workspaces))) if workspaces else 1

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    self._scan_uc_resource,
                    ws, uc_type, resource_name, expand_groups,
                ): ws
                for ws in workspaces
            }
            for fut in as_completed(futures):
                try:
                    all_grants.extend(fut.result())
                except Exception as exc:
                    ws = futures[fut]
                    log.debug("UC scan failed for %s: %s", ws.workspace_name, exc)

        # Deduplicate: same (principal_name, via_group_or_empty, frozenset(privileges))
        seen: set = set()
        deduped: List[ResourceGrant] = []
        for g in all_grants:
            key = (g.principal_name, g.via_group or "", frozenset(g.privileges))
            if key not in seen:
                seen.add(key)
                deduped.append(g)

        result.grants = deduped
        return result
