"""Workspace-local group detection.

Databricks is deprecating workspace-local groups in favour of account-level
SCIM groups managed through the account console or an identity provider (IdP).
Workspace-local groups are not visible to the Account API, cannot be used in
Unity Catalog permission grants, and are not migrated automatically — they
must be recreated at the account level as part of the Unity Catalog migration.

This module detects groups that exist in a workspace's own SCIM directory
(``/api/2.0/preview/scim/v2/Groups``) but are **absent from the account-level
SCIM directory** (``/scim/v2/Groups``).  Those are workspace-local groups.

Common scenarios:
* Customers in the middle of a Unity Catalog migration who haven't yet run the
  UCX migration tool's group migration step.
* Accounts that were onboarded before account-level groups were available and
  still have legacy workspace-local groups.

See also: https://docs.databricks.com/administration-guide/users-groups/groups.html

Usage::

    from databricks_access_audit.local_groups import LocalGroupChecker
    from databricks_access_audit.workspace import WorkspaceDiscovery

    checker = LocalGroupChecker(client)
    workspaces = WorkspaceDiscovery(client, "azure").discover()
    findings = checker.check_all_workspaces(workspaces)
    for f in findings:
        print(f"  {f.group_name} in '{f.workspace_name}' — workspace-local (not in account SCIM)")
"""

from __future__ import annotations

import logging
from typing import List, Set

from databricks_access_audit.client import AuditClient
from databricks_access_audit.models import LocalGroupFinding, WorkspaceInfo

log = logging.getLogger(__name__)

_WS_SCIM_GROUPS_ENDPOINT = "/api/2.0/preview/scim/v2/Groups"
_WS_SCIM_PAGE_SIZE = 100


class LocalGroupChecker:
    """Detect workspace-local (non-account-level) SCIM groups.

    Compares the groups visible in each workspace's SCIM directory against
    the account-level group roster.  Any workspace group not present in the
    account SCIM (matched case-insensitively by display name) is a
    workspace-local legacy group.

    Parameters
    ----------
    api_client:
        The audit API client.  Must be authenticated with Account Admin
        credentials so that the account SCIM listing succeeds.
    """

    def __init__(self, api_client: AuditClient) -> None:
        self.api = api_client

    # ------------------------------------------------------------------
    # Account-level group roster
    # ------------------------------------------------------------------

    def get_account_group_names(self) -> Set[str]:
        """Return the lowercased display names of all account-level SCIM groups."""
        groups = self.api.scim_list_all("Groups")
        return {g.get("displayName", "").lower() for g in groups if g.get("displayName")}

    # ------------------------------------------------------------------
    # Workspace-level group listing
    # ------------------------------------------------------------------

    def _get_workspace_groups(self, workspace_url: str) -> List[dict]:
        """Return all groups from a single workspace's SCIM directory.

        Uses manual pagination (startIndex / count) because workspace SCIM
        does not guarantee returning all groups in a single page.
        """
        all_groups: List[dict] = []
        start_index = 1

        while True:
            try:
                resp = self.api.workspace_api(
                    workspace_url, "GET", _WS_SCIM_GROUPS_ENDPOINT,
                    params={"startIndex": start_index, "count": _WS_SCIM_PAGE_SIZE},
                )
            except Exception as exc:
                log.warning(
                    "Could not list workspace SCIM groups from %s: %s",
                    workspace_url, exc,
                )
                break

            resources = resp.get("Resources", [])
            all_groups.extend(resources)

            total = resp.get("totalResults", 0)
            if len(all_groups) >= total or not resources:
                break

            start_index += len(resources)

        return all_groups

    # ------------------------------------------------------------------
    # Per-workspace check
    # ------------------------------------------------------------------

    def check_workspace(
        self,
        workspace: WorkspaceInfo,
        account_group_names: Set[str] | None = None,
    ) -> List[LocalGroupFinding]:
        """Find workspace-local groups in a single workspace.

        Parameters
        ----------
        workspace:
            The workspace to check.
        account_group_names:
            Pre-fetched set of lowercased account group names.  When omitted
            the method fetches them from the account SCIM API (one extra
            round-trip per call — prefer passing it when checking many
            workspaces).

        Returns
        -------
        list of LocalGroupFinding
            One entry per workspace-local group found.
        """
        if account_group_names is None:
            account_group_names = self.get_account_group_names()

        ws_groups = self._get_workspace_groups(workspace.workspace_url)
        findings: List[LocalGroupFinding] = []

        for g in ws_groups:
            name = g.get("displayName", "")
            if not name:
                continue
            if name.lower() in account_group_names:
                continue  # present at account level — not workspace-local

            member_count = len(g.get("members") or [])
            findings.append(LocalGroupFinding(
                group_name=name,
                group_id=g.get("id", ""),
                workspace_name=workspace.workspace_name,
                workspace_url=workspace.workspace_url,
                member_count=member_count,
            ))

        return findings

    # ------------------------------------------------------------------
    # Full-account check
    # ------------------------------------------------------------------

    def check_all_workspaces(
        self, workspaces: List[WorkspaceInfo],
    ) -> List[LocalGroupFinding]:
        """Find workspace-local groups across all provided workspaces.

        Fetches the account group roster once, then checks each workspace in
        turn.  Workspace API errors are logged at WARNING level and that
        workspace is skipped so a single unreachable workspace does not abort
        the entire check.

        Parameters
        ----------
        workspaces:
            List of :class:`~databricks_access_audit.models.WorkspaceInfo`
            objects, typically from
            :meth:`~databricks_access_audit.workspace.WorkspaceDiscovery.discover`.

        Returns
        -------
        list of LocalGroupFinding
            Aggregated findings across all workspaces.
        """
        account_names = self.get_account_group_names()
        log.info("Checking %d workspace(s) for workspace-local groups.", len(workspaces))

        all_findings: List[LocalGroupFinding] = []
        for ws in workspaces:
            findings = self.check_workspace(ws, account_group_names=account_names)
            if findings:
                log.info(
                    "Found %d workspace-local group(s) in '%s'.",
                    len(findings), ws.workspace_name,
                )
            all_findings.extend(findings)

        return all_findings
