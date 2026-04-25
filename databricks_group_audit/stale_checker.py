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
from datetime import date, timedelta
from typing import Any, Dict, List, Set

from databricks_group_audit.client import AuditClient
from databricks_group_audit.models import CatalogGrant, GrantSource, StaleFinding

log = logging.getLogger(__name__)

# SQL statement execution terminal states.
_TERMINAL_STATES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED", "CLOSED"})

# One row per principal that had *any* auditable event in the lookback window.
# ``{lookback}`` is substituted with ``max_lookback_days`` at call time — a
# longer window than ``stale_days`` so that principals with some historical
# activity (but outside the stale threshold) still get a ``last_access`` date
# rather than reporting ``None``.  The stale threshold is applied in Python
# after the query returns.
_ACTIVITY_QUERY = """\
SELECT
  COALESCE(
    user_identity.email,
    user_identity.service_principal_name,
    CAST(user_identity.service_principal_application_id AS STRING)
  ) AS principal,
  DATE(MAX(event_time)) AS last_seen_date
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -{lookback}, CURRENT_TIMESTAMP())
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
        max_lookback_days: int = 0,
    ) -> None:
        self.api = api_client
        self.workspace_url = workspace_url.rstrip("/")
        self.warehouse_id = warehouse_id
        self.stale_days = stale_days
        self.poll_interval = poll_interval
        self.max_wait = max_wait
        # Query window for audit history.  Must be >= stale_days so that
        # principals with activity older than stale_days (but within this
        # window) get a real last_access date instead of None.
        self.max_lookback_days = (
            max_lookback_days if max_lookback_days > 0
            else max(stale_days * 3, 365)
        )

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
    # Activity lookup
    # ------------------------------------------------------------------

    def _get_activity_by_principal(self) -> Dict[str, str]:
        """Return ``{principal: last_seen_date_iso}`` for all principals seen
        within ``max_lookback_days``.

        Both the original-case and lowercased forms of each principal are
        stored so that callers can do case-insensitive lookups with a plain
        ``dict.get``.

        Raises :class:`RuntimeError` when the statement execution API fails so
        that :meth:`check_catalog_grants` can catch it and avoid producing
        false stale findings.
        """
        sql = _ACTIVITY_QUERY.format(lookback=self.max_lookback_days)
        rows = self._execute_statement(sql)
        activity: Dict[str, str] = {}
        for row in rows:
            principal = row.get("principal")
            last_seen = row.get("last_seen_date")
            if principal and last_seen:
                date_str = str(last_seen)
                activity[principal] = date_str
                activity[principal.lower()] = date_str
        return activity

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
        stale_threshold = (date.today() - timedelta(days=self.stale_days)).isoformat()
        activity = self._get_activity_by_principal()
        return {p for p, d in activity.items() if d >= stale_threshold}

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

        A grant is stale when the principal's last recorded activity in
        ``system.access.audit`` predates the ``stale_days`` threshold.
        ``StaleFinding.last_access`` is populated with the ISO date of the
        principal's most recent activity within ``max_lookback_days`` when
        that date exists, or ``None`` when the principal does not appear in
        the audit log at all within the lookback window.

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
            activity = self._get_activity_by_principal()
        except Exception as exc:
            log.error("Stale-check failed: could not query audit log: %s", exc)
            return []

        stale_threshold = (date.today() - timedelta(days=self.stale_days)).isoformat()

        findings: List[StaleFinding] = []
        for grant in member_grants:
            last_seen = (
                activity.get(grant.principal)
                or activity.get(grant.principal.lower())
            )
            if last_seen and last_seen >= stale_threshold:
                continue  # active within the stale window

            findings.append(StaleFinding(
                principal=grant.principal,
                principal_type=grant.principal_type,
                catalog_name=grant.catalog_name,
                privileges=list(grant.privileges),
                workspace_name=workspace_name,
                workspace_url=workspace_url,
                # ISO date when last seen (but outside threshold), or None if
                # not seen at all within max_lookback_days.
                last_access=last_seen,
                stale_days=self.stale_days,
            ))

        return findings
