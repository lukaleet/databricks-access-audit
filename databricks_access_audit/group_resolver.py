"""Recursive group membership resolver via SCIM API."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

from databricks_access_audit.client import AuditClient, _scim_filter_escape
from databricks_access_audit.models import GroupMember, GroupNode, MemberType

log = logging.getLogger(__name__)

MAX_RECURSION_DEPTH = 50


class GroupMembershipResolver:
    """Walk the SCIM API to build a full group hierarchy tree."""

    def __init__(self, api_client: AuditClient):
        self.api_client = api_client
        self._group_cache: Dict[str, dict] = {}
        self._user_cache: Dict[str, dict] = {}
        self._sp_cache: Dict[str, dict] = {}
        self._resolved_groups: Set[str] = set()
        self._group_membership_map_cache: Optional[
            Tuple[Dict[str, str], Dict[str, Optional[str]], Dict[str, Set[str]]]
        ] = None

    def clear_caches(self) -> None:
        """Reset all caches (useful between separate audit runs)."""
        self._group_cache.clear()
        self._user_cache.clear()
        self._sp_cache.clear()
        self._resolved_groups.clear()
        self._group_membership_map_cache = None

    # -- Shared group membership map ----------------------------------------

    def get_group_membership_map(
        self, max_workers: int = 16,
    ) -> Tuple[Dict[str, str], Dict[str, Optional[str]], Dict[str, Set[str]]]:
        """Return ``(id_to_name, id_to_external_id, child_to_parents)`` — cached.

        Fetches all group IDs and names with a single paginated list call, then
        parallel-GETs each group individually to obtain the ``members`` field
        (the Databricks SCIM list endpoint never returns members regardless of
        client or query parameters — only individual GETs include them).

        The result is stored on the instance so multiple callers within the same
        session (catalog scanner, principal auditor, schema scanner) pay the O(N)
        fetch cost exactly once.  Call :meth:`clear_caches` to force a refresh.

        Thread safety: the parallel GETs run in a thread pool but all writes to
        shared state happen in the main thread after the pool has finished.
        """
        if self._group_membership_map_cache is not None:
            return self._group_membership_map_cache

        all_groups = self.api_client.scim_list_all("Groups")

        id_to_name: Dict[str, str] = {}
        id_to_external: Dict[str, Optional[str]] = {}
        for g in all_groups:
            gid = g.get("id")
            if not gid:
                continue
            id_to_name[gid] = g.get("displayName", "")
            id_to_external[gid] = g.get("externalId") or None

        child_to_parents: Dict[str, Set[str]] = {}

        def _fetch_one(gid: str) -> Tuple[str, dict]:
            return gid, self.api_client.account_api("GET", f"/scim/v2/Groups/{gid}")

        workers = min(max_workers, len(id_to_name)) if id_to_name else 1
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_fetch_one, gid): gid for gid in id_to_name}
            for fut in as_completed(futures):
                try:
                    gid, full = fut.result()
                except Exception:
                    continue
                # Warm the individual-get cache so _get_group_by_id hits it later.
                self._group_cache[gid] = full
                # Refresh externalId from the full record (list may omit it).
                id_to_external[gid] = full.get("externalId") or None
                for m in full.get("members", []):
                    child_id = m.get("value")
                    if child_id:
                        child_to_parents.setdefault(child_id, set()).add(gid)

        result = (id_to_name, id_to_external, child_to_parents)
        self._group_membership_map_cache = result
        return result

    # -- SCIM helpers -------------------------------------------------------

    def _get_group_by_name(self, name: str) -> Optional[dict]:
        try:
            resp = self.api_client.account_api(
                "GET", "/scim/v2/Groups",
                params={"filter": f'displayName eq "{_scim_filter_escape(name)}"'},
            )
            resources = resp.get("Resources", [])
            return resources[0] if resources else None
        except Exception as exc:
            log.warning("Failed to fetch group '%s': %s", name, exc)
            return None

    def _get_group_by_id(self, gid: str) -> Optional[dict]:
        if gid in self._group_cache:
            return self._group_cache[gid]
        try:
            resp = self.api_client.account_api("GET", f"/scim/v2/Groups/{gid}")
            self._group_cache[gid] = resp
            return resp
        except Exception as exc:
            log.warning("Failed to fetch group id '%s': %s", gid, exc)
            return None

    def _get_user_by_id(self, uid: str) -> Optional[dict]:
        if uid in self._user_cache:
            return self._user_cache[uid]
        try:
            resp = self.api_client.account_api("GET", f"/scim/v2/Users/{uid}")
            self._user_cache[uid] = resp
            return resp
        except Exception as exc:
            log.warning("Failed to fetch user id '%s': %s", uid, exc)
            return None

    def _get_sp_by_id(self, sid: str) -> Optional[dict]:
        if sid in self._sp_cache:
            return self._sp_cache[sid]
        try:
            resp = self.api_client.account_api("GET", f"/scim/v2/ServicePrincipals/{sid}")
            self._sp_cache[sid] = resp
            return resp
        except Exception as exc:
            log.warning("Failed to fetch SP id '%s': %s", sid, exc)
            return None

    # -- Bulk pre-fetch ----------------------------------------------------

    def _prefetch_users_and_sps(self) -> None:
        """Bulk-fetch all users and SPs into caches (two paginated calls).

        Trading a wider initial fetch for zero per-member API calls. For
        accounts with <10 000 users this is significantly faster than N+1.
        """
        if not self._user_cache:
            try:
                for u in self.api_client.scim_list_all("Users"):
                    self._user_cache[u.get("id", "")] = u
                log.info("Pre-fetched %d users", len(self._user_cache))
            except Exception as exc:
                log.info("Bulk user fetch unavailable, falling back to per-member: %s", exc)

        if not self._sp_cache:
            try:
                for sp in self.api_client.scim_list_all("ServicePrincipals"):
                    self._sp_cache[sp.get("id", "")] = sp
                log.info("Pre-fetched %d service principals", len(self._sp_cache))
            except Exception as exc:
                log.info("Bulk SP fetch unavailable, falling back to per-member: %s", exc)

    # -- Recursive resolver ------------------------------------------------

    def _resolve_recursive(
        self, group_id: str, parent_path: Optional[List[str]] = None, depth: int = 0
    ) -> Optional[GroupNode]:
        if parent_path is None:
            parent_path = []

        if depth > MAX_RECURSION_DEPTH:
            log.warning(
                "Max recursion depth (%d) reached at group '%s'", MAX_RECURSION_DEPTH, group_id
            )
            return None

        if group_id in self._resolved_groups:
            return None
        self._resolved_groups.add(group_id)

        group_data = self._get_group_by_id(group_id)
        if not group_data:
            return None

        group_name = group_data.get("displayName", group_id)
        node = GroupNode(
            id=group_id,
            display_name=group_name,
            parent_path=list(parent_path),
            external_id=group_data.get("externalId") or None,
        )

        current_path = parent_path + [group_name]
        for member in group_data.get("members", []):
            ref = member.get("$ref", "")
            mid = member.get("value")
            display = member.get("display", "Unknown")

            if "Users/" in ref:
                user_data = self._get_user_by_id(mid)
                email = None
                external_id = None
                if user_data:
                    emails = user_data.get("emails", [])
                    for _e in emails:
                        v = _e.get("value")
                        if v and (_e.get("primary") or email is None):
                            email = v
                    display = user_data.get("displayName", display)
                    external_id = user_data.get("externalId") or None
                node.direct_users.append(
                    GroupMember(id=mid, display_name=display, member_type=MemberType.USER,
                                email=email, parent_groups=list(current_path),
                                external_id=external_id)
                )

            elif "ServicePrincipals/" in ref:
                sp_data = self._get_sp_by_id(mid)
                app_id = None
                external_id = None
                if sp_data:
                    app_id = sp_data.get("applicationId")
                    display = sp_data.get("displayName", display)
                    external_id = sp_data.get("externalId") or None
                node.direct_service_principals.append(
                    GroupMember(id=mid, display_name=display,
                                member_type=MemberType.SERVICE_PRINCIPAL,
                                application_id=app_id, parent_groups=list(current_path),
                                external_id=external_id)
                )

            elif "Groups/" in ref:
                nested = self._resolve_recursive(mid, current_path, depth + 1)
                if nested:
                    node.nested_groups[mid] = nested

        return node

    # -- Public interface --------------------------------------------------

    def resolve_group(self, group_name: str) -> Optional[GroupNode]:
        """Resolve full membership hierarchy for a group by display name."""
        self._resolved_groups.clear()
        self._prefetch_users_and_sps()
        group_data = self._get_group_by_name(group_name)
        if not group_data:
            return None
        return self._resolve_recursive(group_data["id"])

    @staticmethod
    def get_all_members_flat(node: GroupNode) -> Dict[str, List[GroupMember]]:
        """Flatten the hierarchy into deduplicated user and SP lists."""
        users: Dict[str, GroupMember] = {}
        sps: Dict[str, GroupMember] = {}

        def _collect(n: GroupNode) -> None:
            for u in n.direct_users:
                if u.id not in users:
                    users[u.id] = u
            for sp in n.direct_service_principals:
                if sp.id not in sps:
                    sps[sp.id] = sp
            for nested in n.nested_groups.values():
                _collect(nested)

        _collect(node)
        return {"users": list(users.values()), "service_principals": list(sps.values())}
