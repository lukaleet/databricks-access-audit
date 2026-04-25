"""Recursive group membership resolver via SCIM API."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

from databricks_group_audit.client import AuditClient, _scim_filter_escape
from databricks_group_audit.models import GroupMember, GroupNode, MemberType

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

    def clear_caches(self) -> None:
        """Reset all caches (useful between separate audit runs)."""
        self._group_cache.clear()
        self._user_cache.clear()
        self._sp_cache.clear()
        self._resolved_groups.clear()

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
                log.warning("Bulk user fetch failed, falling back to per-member: %s", exc)

        if not self._sp_cache:
            try:
                for sp in self.api_client.scim_list_all("ServicePrincipals"):
                    self._sp_cache[sp.get("id", "")] = sp
                log.info("Pre-fetched %d service principals", len(self._sp_cache))
            except Exception as exc:
                log.warning("Bulk SP fetch failed, falling back to per-member: %s", exc)

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
