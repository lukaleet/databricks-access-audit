"""Compare group memberships between two principals."""
from __future__ import annotations

import logging

from databricks_access_audit.client import AuditClient
from databricks_access_audit.models import CompareResult, GroupComparison
from databricks_access_audit.principal_auditor import PrincipalAuditor

log = logging.getLogger(__name__)


class PrincipalComparer:
    """Compare group memberships between two principals.

    Resolves both principals via SCIM, performs the BFS group-membership walk
    for each, then returns a :class:`CompareResult` showing which groups are
    unique to each principal and which are shared.

    This is a pure read operation — no API writes are performed.
    """

    def __init__(self, api_client: AuditClient, cloud_provider: str = "azure"):
        self.api = api_client
        self._auditor = PrincipalAuditor(api_client, cloud_provider=cloud_provider)

    def compare(self, identifier_a: str, identifier_b: str) -> CompareResult:
        """Compare group memberships of two principals.

        Parameters
        ----------
        identifier_a, identifier_b:
            User email, SP application ID / display name, or group display name.

        Returns
        -------
        CompareResult
            Groups only in A, only in B, and shared — each annotated with
            source (external/internal), is_direct, and membership path.

        Raises
        ------
        ValueError
            If either principal cannot be resolved.
        """
        ptype_a, pid_a, pname_a, _, _ = self._auditor.find_principal(identifier_a)
        log.info("Resolved A: %s (%s, id=%s)", pname_a, ptype_a, pid_a)

        ptype_b, pid_b, pname_b, _, _ = self._auditor.find_principal(identifier_b)
        log.info("Resolved B: %s (%s, id=%s)", pname_b, ptype_b, pid_b)

        memberships_a, _ = self._auditor.resolve_group_memberships(pid_a, ptype_a, pname_a)
        memberships_b, _ = self._auditor.resolve_group_memberships(pid_b, ptype_b, pname_b)

        by_id_a = {m.group_id: m for m in memberships_a}
        by_id_b = {m.group_id: m for m in memberships_b}

        all_ids = set(by_id_a) | set(by_id_b)

        only_a: list[GroupComparison] = []
        only_b: list[GroupComparison] = []
        both: list[GroupComparison] = []

        for gid in sorted(all_ids, key=lambda i: (
            by_id_a.get(i, by_id_b.get(i)).group_name.lower()  # type: ignore[union-attr]
        )):
            ma = by_id_a.get(gid)
            mb = by_id_b.get(gid)
            ext_id = (ma or mb).external_id  # type: ignore[union-attr]
            gname = (ma or mb).group_name  # type: ignore[union-attr]

            gc = GroupComparison(
                group_id=gid,
                group_name=gname,
                external_id=ext_id,
                in_a=ma is not None,
                in_b=mb is not None,
                is_direct_in_a=ma.is_direct if ma else False,
                is_direct_in_b=mb.is_direct if mb else False,
                path_in_a=ma.path if ma else [],
                path_in_b=mb.path if mb else [],
            )

            if ma and mb:
                both.append(gc)
            elif ma:
                only_a.append(gc)
            else:
                only_b.append(gc)

        return CompareResult(
            principal_a=identifier_a,
            principal_b=identifier_b,
            display_name_a=pname_a,
            display_name_b=pname_b,
            only_in_a=only_a,
            only_in_b=only_b,
            in_both=both,
        )
