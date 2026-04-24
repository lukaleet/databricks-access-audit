"""Recursive group membership resolver via SCIM API."""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from databricks_group_audit.client import DatabricksAPIClient
from databricks_group_audit.models import GroupMember, GroupNode, MemberType


class GroupMembershipResolver:
    """Walk the SCIM API to build a full group hierarchy tree."""

    def __init__(self, api_client: DatabricksAPIClient):
        self.api_client = api_client
        self._group_cache: Dict[str, dict] = {}
        self._resolved_groups: Set[str] = set()

    # -- SCIM helpers -------------------------------------------------------

    def _get_group_by_name(self, name: str) -> Optional[dict]:
        try:
            resp = self.api_client.account_api(
                "GET", "/scim/v2/Groups",
                params={"filter": f'displayName eq "{name}"'},
            )
            resources = resp.get("Resources", [])
            return resources[0] if resources else None
        except Exception:
            return None

    def _get_group_by_id(self, gid: str) -> Optional[dict]:
        if gid in self._group_cache:
            return self._group_cache[gid]
        try:
            resp = self.api_client.account_api("GET", f"/scim/v2/Groups/{gid}")
            self._group_cache[gid] = resp
            return resp
        except Exception:
            return None

    def _get_user_by_id(self, uid: str) -> Optional[dict]:
        try:
            return self.api_client.account_api("GET", f"/scim/v2/Users/{uid}")
        except Exception:
            return None

    def _get_sp_by_id(self, sid: str) -> Optional[dict]:
        try:
            return self.api_client.account_api("GET", f"/scim/v2/ServicePrincipals/{sid}")
        except Exception:
            return None

    # -- Recursive resolver ------------------------------------------------

    def _resolve_recursive(
        self, group_id: str, parent_path: Optional[List[str]] = None, depth: int = 0
    ) -> Optional[GroupNode]:
        if parent_path is None:
            parent_path = []

        if group_id in self._resolved_groups:
            return None
        self._resolved_groups.add(group_id)

        group_data = self._get_group_by_id(group_id)
        if not group_data:
            return None

        group_name = group_data.get("displayName", group_id)
        node = GroupNode(id=group_id, display_name=group_name, parent_path=list(parent_path))

        current_path = parent_path + [group_name]
        for member in group_data.get("members", []):
            ref = member.get("$ref", "")
            mid = member.get("value")
            display = member.get("display", "Unknown")

            if "/Users/" in ref:
                user_data = self._get_user_by_id(mid)
                email = None
                if user_data:
                    emails = user_data.get("emails", [])
                    email = emails[0].get("value") if emails else None
                    display = user_data.get("displayName", display)
                node.direct_users.append(
                    GroupMember(id=mid, display_name=display, member_type=MemberType.USER,
                                email=email, parent_groups=list(current_path))
                )

            elif "/ServicePrincipals/" in ref:
                sp_data = self._get_sp_by_id(mid)
                app_id = None
                if sp_data:
                    app_id = sp_data.get("applicationId")
                    display = sp_data.get("displayName", display)
                node.direct_service_principals.append(
                    GroupMember(id=mid, display_name=display,
                                member_type=MemberType.SERVICE_PRINCIPAL,
                                application_id=app_id, parent_groups=list(current_path))
                )

            elif "/Groups/" in ref:
                nested = self._resolve_recursive(mid, current_path, depth + 1)
                if nested:
                    node.nested_groups[mid] = nested

        return node

    # -- Public interface --------------------------------------------------

    def resolve_group(self, group_name: str) -> Optional[GroupNode]:
        """Resolve full membership hierarchy for a group by display name."""
        self._resolved_groups.clear()
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
