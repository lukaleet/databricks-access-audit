"""Stale grant detection via Databricks system.access.audit.

Queries ``system.access.audit`` — the per-workspace Unity Catalog system
table that records every API call, command, and data-access event — to
determine which principals have **not** accessed anything within a
configurable inactivity window.  Those principals' member-direct catalog
grants are then flagged as potentially stale.

Prerequisites
-------------
* Unity Catalog must be enabled and the **system catalog** must be activated
  for the account (``SYSTEM`` catalog visible via the metastore).
* The audit SP (or the running user) must have ``SELECT`` on
  ``system.access.audit``, which requires being a **Metastore Admin** or
  having been explicitly granted access to the system catalog.
* A **SQL warehouse** in the target workspace is required to execute the
  SQL statement.  Pass its ID via ``--sql-warehouse-id``.

Availability
------------
``system.access.audit`` was introduced in Databricks Runtime 11.3 / DBR 12.x
for AWS and Azure; GCP availability followed shortly after.  For accounts
where audit log delivery is disabled the table will exist but may be empty.

Stale definition
----------------
A principal is considered stale when they do not appear in
``system.access.audit`` for any event within the last ``stale_days`` days.
This is a *conservative* definition: the absence of audit records does not
prove the principal has never accessed data (audit delivery may be delayed,
or the access may have occurred before the retention window), but it is a
strong signal for compliance review.

Usage::

    from databricks_group_audit.stale_checker import StaleGrantChecker

    checker = StaleGrantChecker(
        api_client=client,
        workspace_url="https://adb-123.azuredatabricks.net",
        warehouse_id="abc123def456",
        stale_days=90,
    )
    findings = checker.check_catalog_grants(
        catalog_grants, workspace_name="prod", workspace_url=ws_url,
    )
    for f in findings:
        print(f"{f.principal}: {', '.join(f.privileges)} on {f.catalog_name} — stale")
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set

from databricks_group_audit.client import AuditClient
from databricks_group_audit.models import CatalogGrant, GrantSource, StaleFinding

log = logging.getLogger(__name__)

# SQL statement execution terminal states.
_TERMINAL_STATES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED", "CLOSED"})

# Query returns one row per principal that had *any* auditable event in the
# configured window.  We identify users by email and service principals by
# their application ID (subject field) or display name (service_principal_name).
# Using COALESCE with three alternatives covers the variations across cloud
# providers and Databricks Runtime versions.
_ACTIVITY_QUERY = """\
SELECT
  COALESCE(
    user_identity.email,
    user_identity.service_principal_name,
    CAST(user_identity.service_principal_application_id AS STRING)
  ) AS principal,
  DATE(MAX(event_time)) AS last_seen_date
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -{days}, CURRENT_TIMESTAMP())
  AND COALESCE(
    user_identity.email,
    user_identity.service_principal_name,
    CAST(user_identity.service_principal_application_id AS STRING)
  ) IS NOT NULL
GROUP BY 1
"""


class StaleGrantChecker:
    """Detect stale catalog grants by cross-referencing system.access.audit.

    Parameters
    ----------
    api_client:
        The audit API client (satisfies :class:`~databricks_group_audit.client.AuditClient`).
    workspace_url:
        URL of the workspace whose ``system.access.audit`` table will be
        queried.  This should be a workspace that has the relevant metastore
        attached and audit log delivery enabled.
    warehouse_id:
        ID of the SQL warehouse in ``workspace_url`` to use for statement
        execution.  The warehouse must have access to the system catalog.
    stale_days:
        Number of days of inactivity after which a grant is considered stale.
        Default: 90 days.
    poll_interval:
        Seconds between status-check polls when the statement has not
        completed within the initial ``wait_timeout``.  Default: 2 s.
    max_wait:
        Maximum total seconds to wait for a statement to complete before
        giving up.  Default: 300 s (5 minutes).
    """

    def __init__(
        self,
        api_client: AuditClient,
        workspace_url: str,
        warehouse_id: str,
        stale_days: int = 90,
        poll_interval: float = 2.0,
        max_wait: float = 300.0,
    ) -> None:
        self.api = api_client
        self.workspace_url = workspace_url.rstrip("/")
        self.warehouse_id = warehouse_id
        self.stale_days = stale_days
        self.poll_interval = poll_interval
        self.max_wait = max_wait

    # ------------------------------------------------------------------
    # Statement execution
    # ------------------------------------------------------------------

    def _execute_statement(self, sql: str) -> List[Dict[str, Any]]:
        """Submit a SQL statement and return the result rows as a list of dicts.

        Uses the Databricks Statement Execution API (v2.0) with inline
        disposition and JSON_ARRAY format so results are returned directly in
        the response body without a separate download step.

        Returns an empty list on error; the error is logged at ERROR level so
        it is visible without raising an exception (stale-check failure should
        not abort the audit).
        """
        resp = self.api.workspace_api(
            self.workspace_url, "POST", "/api/2.0/sql/statements",
            json={
                "warehouse_id": self.warehouse_id,
                "statement": sql,
                "wait_timeout": "30s",
                "on_wait_timeout": "CONTINUE",
                "disposition": "INLINE",
                "format": "JSON_ARRAY",
            },
        )

        stmt_id = resp.get("statement_id", "")
        if not stmt_id:
            raise RuntimeError(
                f"Statement execution API returned no statement_id: {resp}"
            )

        # Poll until terminal state or timeout.
        elapsed = 0.0
        while resp.get("status", {}).get("state", "") not in _TERMINAL_STATES:
            if elapsed >= self.max_wait:
                raise RuntimeError(
                    f"Statement {stmt_id} did not complete within {self.max_wait:.0f} s."
                )
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval
            resp = self.api.workspace_api(
                self.workspace_url, "GET",
                f"/api/2.0/sql/statements/{stmt_id}",
            )

        state = resp.get("status", {}).get("state", "")
        if state != "SUCCEEDED":
            err = resp.get("status", {}).get("error", {}).get("message", state)
            raise RuntimeError(f"SQL statement {stmt_id} failed: {err}")

        # Parse schema + data.
        manifest = resp.get("manifest", {})
        columns = [c.get("name", "") for c in manifest.get("schema", {}).get("columns", [])]
        data_array = resp.get("result", {}).get("data_array") or []

        if not columns:
            log.warning("Statement %s returned no column schema.", stmt_id)
            return []

        return [dict(zip(columns, row)) for row in data_array]

    # ------------------------------------------------------------------
    # Active principal lookup
    # ------------------------------------------------------------------

    def get_active_principals(self) -> Set[str]:
        """Return the set of principals with any auditable activity in the
        last ``stale_days`` days, as recorded in ``system.access.audit``.

        Principals are identified by email (for users) or by
        ``service_principal_name`` / ``service_principal_application_id``
        (for service principals) — whichever field is populated.

        Raises :class:`RuntimeError` when the statement execution API fails so
        that :meth:`check_catalog_grants` can catch it and avoid producing
        false stale findings.
        """
        sql = _ACTIVITY_QUERY.format(days=self.stale_days)
        rows = self._execute_statement(sql)
        active: Set[str] = set()
        for row in rows:
            principal = row.get("principal")
            if principal:
                active.add(principal)
                active.add(principal.lower())  # case-insensitive fallback
        return active

    # ------------------------------------------------------------------
    # Cross-reference with grants
    # ------------------------------------------------------------------

    def check_catalog_grants(
        self,
        catalog_grants: List[CatalogGrant],
        workspace_name: str,
        workspace_url: str,
    ) -> List[StaleFinding]:
        """Flag member-direct catalog grants whose holders have no recent activity.

        Only :attr:`~databricks_group_audit.models.GrantSource.MEMBER_DIRECT`
        grants (individual user / SP personal grants) are checked.  Group-level
        grants are not included because groups do not appear in the audit log
        as individual principals.

        A grant is stale when the principal does not appear in
        ``system.access.audit`` for *any* event in the last ``stale_days``
        days — not just catalog-specific events.  This is intentionally
        conservative: a principal without any recorded activity is a stronger
        signal than one who accessed a different catalog.

        Parameters
        ----------
        catalog_grants:
            Grants returned by
            :meth:`~databricks_group_audit.catalog_scanner.CatalogPermissionScanner.scan_all_workspaces`.
        workspace_name:
            Human-readable workspace name (used in finding output only).
        workspace_url:
            Workspace URL corresponding to the grants (used in finding output).

        Returns
        -------
        list of StaleFinding
            One entry per stale member-direct grant.  Empty list when
            ``system.access.audit`` cannot be queried or all principals are
            recently active.
        """
        member_grants = [
            g for g in catalog_grants
            if g.grant_source == GrantSource.MEMBER_DIRECT
        ]
        if not member_grants:
            return []

        try:
            active = self.get_active_principals()
        except Exception as exc:
            log.error("Stale-check failed: could not query audit log: %s", exc)
            return []

        findings: List[StaleFinding] = []
        for grant in member_grants:
            principal_lower = grant.principal.lower()
            if grant.principal in active or principal_lower in active:
                continue  # recently active — not stale

            findings.append(StaleFinding(
                principal=grant.principal,
                principal_type=grant.principal_type,
                catalog_name=grant.catalog_name,
                privileges=list(grant.privileges),
                workspace_name=workspace_name,
                workspace_url=workspace_url,
                last_access=None,  # not seen in audit window
                stale_days=self.stale_days,
            ))

        return findings
