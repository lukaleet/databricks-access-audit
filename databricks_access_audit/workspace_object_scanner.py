"""Workspace-level object permission scanner.

Scans the Databricks workspace permissions API (``/api/2.0/permissions/``) for
thirteen object types and classifies each ACL entry relative to a target group
or principal.  Works alongside the Unity Catalog scanners and reuses the shared
``classify_grant`` helper from ``_classification.py``.

Object types covered
--------------------
Compute / orchestration:
* ``JOB``            — ``/api/2.1/jobs/list`` + ``/api/2.0/permissions/jobs/{id}``
* ``CLUSTER``        — ``/api/2.0/clusters/list`` + ``/api/2.0/permissions/clusters/{id}``
* ``CLUSTER_POLICY`` — ``/api/2.0/policies/clusters/list``
  + ``/api/2.0/permissions/cluster-policies/{id}``
* ``PIPELINE``       — ``/api/2.0/pipelines`` + ``/api/2.0/permissions/pipelines/{id}``

SQL / Analytics:
* ``SQL_WAREHOUSE``     — ``/api/2.0/sql/warehouses`` + ``/api/2.0/permissions/warehouses/{id}``
* ``SQL_QUERY``         — ``/api/2.0/sql/queries`` + ``/api/2.0/permissions/queries/{id}``
* ``SQL_ALERT``         — ``/api/2.0/sql/alerts`` + ``/api/2.0/permissions/alerts/{id}``
* ``DASHBOARD``         — ``/api/2.0/lakeview/dashboards``
  + ``/api/2.0/permissions/dashboards/{id}``
* ``GENIE_SPACE``       — ``/api/2.0/genie/spaces`` + ``/api/2.0/permissions/genie/spaces/{id}``

AI / ML:
* ``EXPERIMENT``       — ``/api/2.0/mlflow/experiments/list``
  + ``/api/2.0/permissions/experiments/{id}``
* ``REGISTERED_MODEL`` — ``/api/2.0/mlflow/registered-models/list``
  + ``/api/2.0/permissions/registered-models/{name}``
* ``SERVING_ENDPOINT`` — ``/api/2.0/serving-endpoints``
  + ``/api/2.0/permissions/serving-endpoints/{name}``
* ``APP``               — ``/api/2.0/apps`` + ``/api/2.0/permissions/apps/{name}``

Not covered: notebooks and MLflow experiment artifacts require recursive filesystem
walking (unbounded API call count); Unity Catalog model registry grants are already
covered by the UC permission scanners.

Remediation note
-----------------
Workspace ACL changes require REST API calls, not SQL.  The tool does **not**
generate REVOKE SQL for workspace object grants.  Use the Databricks
``PUT /api/2.0/permissions/{object_type}/{id}`` endpoint for remediation.
"""

from __future__ import annotations

import logging
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple

from databricks_access_audit._classification import build_member_lookups, classify_grant
from databricks_access_audit.client import AuditClient
from databricks_access_audit.group_resolver import GroupMembershipResolver
from databricks_access_audit.models import (
    GrantSource,
    GroupMember,
    GroupNode,
    WorkspaceInfo,
    WorkspaceObjectGrant,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Object type configuration table
# ---------------------------------------------------------------------------

def _nested(outer: str, inner: str):
    """Name accessor for nested dict fields (e.g. job settings.name)."""
    def _get(obj: dict) -> str:
        return (obj.get(outer) or {}).get(inner, "")
    return _get


def _flat(field: str):
    """Name accessor for a top-level dict field."""
    def _get(obj: dict) -> str:
        return obj.get(field, "")
    return _get


# Each entry: list_endpoint, list_key, id_field, object_type, perm_prefix, name_fn
# paginated=True means the list endpoint returns next_page_token and needs looping.
_OBJECT_CONFIGS: Dict[str, Dict[str, Any]] = {
    "jobs": {
        "list_endpoint": "/api/2.1/jobs/list",
        "list_key": "jobs",
        "id_field": "job_id",
        "object_type": "JOB",
        "perm_prefix": "/api/2.0/permissions/jobs",
        "name_fn": _nested("settings", "name"),
        "paginated": True,
    },
    "clusters": {
        "list_endpoint": "/api/2.0/clusters/list",
        "list_key": "clusters",
        "id_field": "cluster_id",
        "object_type": "CLUSTER",
        "perm_prefix": "/api/2.0/permissions/clusters",
        "name_fn": _flat("cluster_name"),
        "paginated": False,
    },
    "sql_warehouses": {
        "list_endpoint": "/api/2.0/sql/warehouses",
        "list_key": "warehouses",
        "id_field": "id",
        "object_type": "SQL_WAREHOUSE",
        "perm_prefix": "/api/2.0/permissions/warehouses",
        "name_fn": _flat("name"),
        "paginated": False,
    },
    "pipelines": {
        "list_endpoint": "/api/2.0/pipelines",
        "list_key": "statuses",
        "id_field": "pipeline_id",
        "object_type": "PIPELINE",
        "perm_prefix": "/api/2.0/permissions/pipelines",
        "name_fn": _flat("name"),
        "paginated": True,
    },
    "cluster_policies": {
        "list_endpoint": "/api/2.0/policies/clusters/list",
        "list_key": "policies",
        "id_field": "policy_id",
        "object_type": "CLUSTER_POLICY",
        "perm_prefix": "/api/2.0/permissions/cluster-policies",
        "name_fn": _flat("name"),
        "paginated": False,
    },
    # SQL / Analytics
    "sql_queries": {
        "list_endpoint": "/api/2.0/sql/queries",
        "list_key": "results",
        "id_field": "id",
        "object_type": "SQL_QUERY",
        "perm_prefix": "/api/2.0/permissions/queries",
        "name_fn": _flat("name"),
        "paginated": True,
    },
    "sql_alerts": {
        "list_endpoint": "/api/2.0/sql/alerts",
        "list_key": "results",
        "id_field": "id",
        "object_type": "SQL_ALERT",
        "perm_prefix": "/api/2.0/permissions/alerts",
        "name_fn": _flat("name"),
        "paginated": True,
    },
    "lakeview_dashboards": {
        "list_endpoint": "/api/2.0/lakeview/dashboards",
        "list_key": "dashboards",
        "id_field": "dashboard_id",
        "object_type": "DASHBOARD",
        "perm_prefix": "/api/2.0/permissions/dashboards",
        "name_fn": _flat("display_name"),
        "paginated": True,
    },
    "genie_spaces": {
        "list_endpoint": "/api/2.0/genie/spaces",
        "list_key": "spaces",
        "id_field": "id",
        "object_type": "GENIE_SPACE",
        "perm_prefix": "/api/2.0/permissions/genie/spaces",
        "name_fn": _flat("title"),
        "paginated": True,
    },
    # AI / ML
    "mlflow_experiments": {
        "list_endpoint": "/api/2.0/mlflow/experiments/list",
        "list_key": "experiments",
        "id_field": "experiment_id",
        "object_type": "EXPERIMENT",
        "perm_prefix": "/api/2.0/permissions/experiments",
        "name_fn": _flat("name"),
        "paginated": True,
    },
    "registered_models": {
        "list_endpoint": "/api/2.0/mlflow/registered-models/list",
        "list_key": "registered_models",
        "id_field": "name",
        "object_type": "REGISTERED_MODEL",
        "perm_prefix": "/api/2.0/permissions/registered-models",
        "name_fn": _flat("name"),
        "paginated": True,
    },
    "serving_endpoints": {
        "list_endpoint": "/api/2.0/serving-endpoints",
        "list_key": "endpoints",
        "id_field": "name",
        "object_type": "SERVING_ENDPOINT",
        "perm_prefix": "/api/2.0/permissions/serving-endpoints",
        "name_fn": _flat("name"),
        "paginated": False,
    },
    "apps": {
        "list_endpoint": "/api/2.0/apps",
        "list_key": "apps",
        "id_field": "name",
        "object_type": "APP",
        "perm_prefix": "/api/2.0/permissions/apps",
        "name_fn": _flat("name"),
        "paginated": True,
    },
}

ALL_OBJECT_TYPES: List[str] = list(_OBJECT_CONFIGS.keys())


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class WorkspaceObjectScanner:
    """Scan workspace-level object permissions for a target group or principal.

    Implements the same public interface pattern as
    :class:`~databricks_access_audit.catalog_scanner.CatalogPermissionScanner`
    (``scan_workspace`` / ``scan_all_workspaces``) for group audit mode, plus
    ``scan_workspace_for_principal`` for principal audit mode.

    Shares the :class:`~databricks_access_audit.group_resolver.GroupMembershipResolver`
    instance with the catalog scanner so the O(N) SCIM group fetch is paid exactly once
    per session regardless of how many scanners run.
    """

    def __init__(
        self, api_client: AuditClient, group_resolver: GroupMembershipResolver
    ) -> None:
        self.api = api_client
        self.group_resolver = group_resolver

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    def _list_objects(self, workspace_url: str, config: dict) -> List[dict]:
        """List all objects of one type, handling pagination via next_page_token.

        Handles both wrapped responses ``{"key": [...], "next_page_token": "..."}``
        and bare JSON arrays ``[...]`` (some DBSQL endpoints return the latter).
        """
        try:
            items: List[dict] = []
            params: Dict[str, Any] = {}
            while True:
                resp = self.api.workspace_api(
                    workspace_url, "GET", config["list_endpoint"],
                    params=params if params else {},
                )
                # Some endpoints return a bare list; others wrap under a key.
                if isinstance(resp, list):
                    batch: List[dict] = resp
                else:
                    batch = resp.get(config["list_key"]) or []
                items.extend(batch)
                if not config.get("paginated"):
                    break
                next_token = resp.get("next_page_token") if isinstance(resp, dict) else None
                if not next_token:
                    break
                params = {"page_token": next_token}
            return items
        except Exception as exc:
            log.warning(
                "Failed to list %s on %s: %s", config["object_type"], workspace_url, exc
            )
            return []

    def _get_acl(self, workspace_url: str, perm_endpoint: str) -> List[dict]:
        """Fetch ACL for one object. Returns empty list on any error."""
        try:
            resp = self.api.workspace_api(workspace_url, "GET", perm_endpoint)
            return resp.get("access_control_list", []) or []
        except Exception as exc:
            log.debug("ACL fetch failed for %s: %s", perm_endpoint, exc)
            return []

    @staticmethod
    def _extract_acl_principal(entry: dict) -> Tuple[str, str]:
        """Return ``(principal_identifier, raw_field)`` from an ACL entry.

        Databricks workspace permissions ACL entries carry the principal in one of
        three mutually exclusive fields: ``user_name``, ``group_name``, or
        ``service_principal_name``.  Returns ``("", "")`` when none is present
        (e.g. the ``admins`` or ``users`` system entries that have no name field).
        """
        for field in ("user_name", "group_name", "service_principal_name"):
            val = entry.get(field, "")
            if val:
                return val, field
        return "", ""

    @staticmethod
    def _best_perm_level(all_perms: List[dict]) -> str:
        """Return the first (most privileged) permission level from the ACL entry."""
        if not all_perms:
            return ""
        return all_perms[0].get("permission_level", "")

    def _get_upstream_groups(self, target_group_name: str) -> Dict[str, str]:
        """BFS-walk the group membership map to find all ancestors of the target group.

        Delegates to the resolver's ``get_group_membership_map()``,
        which is cached per resolver instance.
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

    # ------------------------------------------------------------------
    # Group audit — scan one object type
    # ------------------------------------------------------------------

    def _scan_one_type(
        self,
        workspace: WorkspaceInfo,
        config: dict,
        target_group_name: str,
        upstream_groups: Dict[str, str],
        member_emails: Set[str],
        member_names: Set[str],
        sp_names: Set[str],
        sp_app_ids: Set[str],
    ) -> List[WorkspaceObjectGrant]:
        """Scan all objects of one type on one workspace for the target group."""
        grants: List[WorkspaceObjectGrant] = []
        objects = self._list_objects(workspace.workspace_url, config)
        name_fn = config["name_fn"]

        for obj in objects:
            obj_id = str(obj.get(config["id_field"], ""))
            if not obj_id:
                continue
            obj_name = name_fn(obj)
            perm_endpoint = f"{config['perm_prefix']}/{obj_id}"
            acl = self._get_acl(workspace.workspace_url, perm_endpoint)

            for entry in acl:
                raw_principal, _ = self._extract_acl_principal(entry)
                if not raw_principal:
                    continue
                result = classify_grant(
                    raw_principal, target_group_name, upstream_groups,
                    member_emails, member_names, sp_names, sp_app_ids,
                )
                if result is None:
                    continue
                source, ptype, inherited, member = result
                perm_level = self._best_perm_level(entry.get("all_permissions", []))
                if not perm_level:
                    continue
                grants.append(WorkspaceObjectGrant(
                    object_type=config["object_type"],
                    object_id=obj_id,
                    object_name=obj_name,
                    workspace_name=workspace.workspace_name,
                    workspace_url=workspace.workspace_url,
                    principal=raw_principal,
                    principal_type=ptype,
                    permission_level=perm_level,
                    grant_source=source,
                    inherited_from=inherited,
                    member_of_target=member,
                ))
        return grants

    # ------------------------------------------------------------------
    # Group audit — public interface
    # ------------------------------------------------------------------

    def scan_workspace(
        self,
        workspace: WorkspaceInfo,
        target_group_name: str,
        all_members: Dict[str, List[GroupMember]],
        upstream_groups: Optional[Dict[str, str]] = None,
        object_types: Optional[List[str]] = None,
        max_workers: int = 8,
    ) -> List[WorkspaceObjectGrant]:
        """Scan one workspace for object grants related to *target_group_name*.

        Parameters
        ----------
        upstream_groups:
            Pre-computed ancestor map from :meth:`_get_upstream_groups`.
            Computed on demand when *None*.  Pass explicitly when scanning
            multiple workspaces to avoid repeated SCIM calls.
        object_types:
            Subset of ``ALL_OBJECT_TYPES`` to scan.  *None* = all 13 types.
        """
        if upstream_groups is None:
            upstream_groups = self._get_upstream_groups(target_group_name)

        member_emails, member_names, sp_names, sp_app_ids = build_member_lookups(all_members)

        types_to_scan = [
            (key, _OBJECT_CONFIGS[key])
            for key in (object_types or ALL_OBJECT_TYPES)
            if key in _OBJECT_CONFIGS
        ]
        if not types_to_scan:
            return []

        grants: List[WorkspaceObjectGrant] = []
        workers = max(1, min(max_workers, len(types_to_scan)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    self._scan_one_type,
                    workspace, config, target_group_name, upstream_groups,
                    member_emails, member_names, sp_names, sp_app_ids,
                ): key
                for key, config in types_to_scan
            }
            for fut in as_completed(futures):
                key = futures[fut]
                try:
                    grants.extend(fut.result())
                except Exception as exc:
                    log.warning(
                        "Object type '%s' scan error on %s: %s",
                        key, workspace.workspace_name, exc,
                    )
        return grants

    def scan_all_workspaces(
        self,
        workspaces: List[WorkspaceInfo],
        target_group_name: str,
        group_node: GroupNode,
        all_members: Dict[str, List[GroupMember]],
        object_types: Optional[List[str]] = None,
        max_workers: int = 8,
    ) -> List[WorkspaceObjectGrant]:
        """Scan all workspaces in parallel for object grants related to *target_group_name*.

        ``group_node`` is accepted for interface parity with the catalog scanner
        but not used — upstream groups are derived via the resolver's cached map.
        Duplicate workspace URLs are silently deduplicated before dispatch.
        """
        upstream_groups = self._get_upstream_groups(target_group_name)

        seen_urls: Set[str] = set()
        unique: List[WorkspaceInfo] = []
        for ws in workspaces:
            if ws.workspace_url not in seen_urls:
                seen_urls.add(ws.workspace_url)
                unique.append(ws)
        if not unique:
            return []

        all_grants: List[WorkspaceObjectGrant] = []
        workers = min(max_workers, len(unique))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    self.scan_workspace,
                    ws, target_group_name, all_members, upstream_groups,
                    object_types, max_workers,
                ): ws
                for ws in unique
            }
            for fut in as_completed(futures):
                ws = futures[fut]
                try:
                    all_grants.extend(fut.result())
                except Exception as exc:
                    log.warning(
                        "Skipping workspace %s during object scan: %s",
                        ws.workspace_name, exc,
                    )
        return all_grants

    # ------------------------------------------------------------------
    # Principal audit — scan one object type
    # ------------------------------------------------------------------

    def _scan_one_type_for_principal(
        self,
        workspace: WorkspaceInfo,
        config: dict,
        direct_principals: Set[str],
        direct_lower: Set[str],
        group_names: Set[str],
        group_names_lower: Set[str],
    ) -> List[WorkspaceObjectGrant]:
        """Scan all objects of one type for access by principal or their groups."""
        grants: List[WorkspaceObjectGrant] = []
        objects = self._list_objects(workspace.workspace_url, config)
        name_fn = config["name_fn"]

        for obj in objects:
            obj_id = str(obj.get(config["id_field"], ""))
            if not obj_id:
                continue
            obj_name = name_fn(obj)
            perm_endpoint = f"{config['perm_prefix']}/{obj_id}"
            acl = self._get_acl(workspace.workspace_url, perm_endpoint)

            for entry in acl:
                raw_principal, field_name = self._extract_acl_principal(entry)
                if not raw_principal:
                    continue
                clean = raw_principal.replace("`", "").strip()
                perm_level = self._best_perm_level(entry.get("all_permissions", []))
                if not perm_level:
                    continue

                if raw_principal in direct_principals or clean.lower() in direct_lower:
                    ptype = "USER" if field_name == "user_name" else "SERVICE_PRINCIPAL"
                    grants.append(WorkspaceObjectGrant(
                        object_type=config["object_type"],
                        object_id=obj_id,
                        object_name=obj_name,
                        workspace_name=workspace.workspace_name,
                        workspace_url=workspace.workspace_url,
                        principal=raw_principal,
                        principal_type=ptype,
                        permission_level=perm_level,
                        grant_source=GrantSource.DIRECT,
                        inherited_from=None,
                        member_of_target=False,
                    ))
                elif raw_principal in group_names or clean.lower() in group_names_lower:
                    matched = raw_principal if raw_principal in group_names else clean
                    grants.append(WorkspaceObjectGrant(
                        object_type=config["object_type"],
                        object_id=obj_id,
                        object_name=obj_name,
                        workspace_name=workspace.workspace_name,
                        workspace_url=workspace.workspace_url,
                        principal=raw_principal,
                        principal_type="GROUP",
                        permission_level=perm_level,
                        grant_source=GrantSource.UPSTREAM,
                        inherited_from=matched,
                        member_of_target=False,
                    ))
        return grants

    # ------------------------------------------------------------------
    # Principal audit — public interface
    # ------------------------------------------------------------------

    def scan_workspace_for_principal(
        self,
        workspace: WorkspaceInfo,
        principal_name: str,
        group_names: Set[str],
        principal_aliases: Optional[Set[str]] = None,
        object_types: Optional[List[str]] = None,
        max_workers: int = 8,
    ) -> List[WorkspaceObjectGrant]:
        """Scan one workspace for object grants accessible by *principal_name*.

        A grant is included when the ACL entry matches either the principal
        directly (``DIRECT`` source) or one of their group memberships
        (``UPSTREAM`` source with ``inherited_from`` set to the group name).

        Parameters
        ----------
        principal_aliases:
            Additional identifiers for the same principal, e.g. the Azure AD
            guest UPN (``user_gmail.com#ext#@tenant``) alongside the display name.
        """
        direct_principals = {principal_name} | (principal_aliases or set())
        direct_lower = {n.lower() for n in direct_principals}
        group_names_lower = {n.lower() for n in group_names}

        types_to_scan = [
            (key, _OBJECT_CONFIGS[key])
            for key in (object_types or ALL_OBJECT_TYPES)
            if key in _OBJECT_CONFIGS
        ]
        if not types_to_scan:
            return []

        grants: List[WorkspaceObjectGrant] = []
        workers = max(1, min(max_workers, len(types_to_scan)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    self._scan_one_type_for_principal,
                    workspace, config,
                    direct_principals, direct_lower,
                    group_names, group_names_lower,
                ): key
                for key, config in types_to_scan
            }
            for fut in as_completed(futures):
                key = futures[fut]
                try:
                    grants.extend(fut.result())
                except Exception as exc:
                    log.warning(
                        "Principal object type '%s' scan error on %s: %s",
                        key, workspace.workspace_name, exc,
                    )
        return grants
