"""Just-in-time Workspace Admin elevation for the audit service principal.

Overview
--------
The audit tool requires the running service principal to be a **Workspace
Admin** on every workspace it scans so that it can read workspace permission
assignments and authenticate to workspace-level APIs.

When the SP is already an **Account Admin** but is *not yet* a Workspace
Admin on one or more workspaces, this module temporarily elevates it, runs
the audit, then restores the original state — even if the audit fails with
an exception.

Out of scope
------------
**Metastore Admin** is intentionally *not* managed here.  That role is
required so the SP can call ``GET /permissions/catalog/{name}`` (and the
equivalent schema/table endpoints), but it must be granted manually before
running the tool.  See the Prerequisites section in README.md.

The account-level **Account Admin** role also cannot be auto-granted — it is
a hard prerequisite that must already be in place for any of the Account API
calls to succeed.

Guarantee
---------
Cleanup (restoration of prior state) is unconditional.  It runs via the
context manager's ``__exit__`` regardless of whether the audit succeeded or
raised.  If cleanup itself fails, the module:

1. Emits an ERROR log with explicit manual revocation instructions.
2. Raises ``RuntimeError`` so the failure is never silently swallowed.

If both the audit *and* the cleanup fail, the original audit exception is
logged before the cleanup error is raised so neither is lost.

Usage
-----
Typical CLI usage via the ``--auto-elevate`` flag::

    databricks-group-audit --group "data-engineers" --auto-elevate

Programmatic usage::

    from databricks_group_audit.elevate import PermissionElevator

    with PermissionElevator(client, sp_application_id="<client-id>") as elev:
        for ws in workspaces:
            elev.ensure_workspace_admin(ws.workspace_id, ws.workspace_name)
        # ... run audit ...
    # prior workspace assignments are restored here, success or failure

Dry-run mode (preview without writing)::

    with PermissionElevator(client, sp_application_id, dry_run=True) as elev:
        for ws in workspaces:
            elev.ensure_workspace_admin(ws.workspace_id, ws.workspace_name)
        # Nothing is written; actions are only logged at INFO level.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

from databricks_group_audit.client import AuditClient, _scim_filter_escape

log = logging.getLogger(__name__)

# Databricks permission level strings returned by the permission assignments API.
_WORKSPACE_ADMIN = "WORKSPACE_ADMIN"
_USER = "USER"


@dataclass
class _ElevatedWorkspace:
    """Internal record of one workspace elevation, used to restore prior state."""

    workspace_id: str
    workspace_name: str
    # None  → SP had no assignment on this workspace before elevation.
    #         Cleanup will DELETE the assignment entirely.
    # "USER" → SP had a user-level assignment before elevation.
    #          Cleanup will PUT it back to USER.
    prior_level: Optional[str]


class PermissionElevator:
    """Temporarily elevate the audit SP to Workspace Admin where needed.

    Must be used as a context manager.  Elevation state is tracked internally
    and all changes are rolled back on ``__exit__``.

    Parameters
    ----------
    api_client:
        The audit API client (``DatabricksAPIClient`` or ``DatabricksSDKClient``).
        Must be authenticated with Account Admin credentials.
    sp_application_id:
        The service principal's OAuth **application (client) ID** — the same
        value passed as ``--client-id`` on the CLI.  Used to locate the SP in
        the account SCIM directory so its numeric SCIM ID can be resolved for
        permission assignment API calls.
    dry_run:
        When ``True``, log all intended actions at INFO level but do not call
        any write APIs (no PUT, no DELETE).  Useful for previewing which
        workspaces would be elevated before committing to an actual run.
    """

    def __init__(
        self,
        api_client: AuditClient,
        sp_application_id: str,
        dry_run: bool = False,
    ) -> None:
        self.api = api_client
        self.sp_application_id = sp_application_id
        self.dry_run = dry_run
        self._sp_scim_id: Optional[str] = None
        self._elevated: List[_ElevatedWorkspace] = []

    # ------------------------------------------------------------------
    # Context manager protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> "PermissionElevator":
        self._sp_scim_id = self._resolve_sp_id()
        log.info(
            "PermissionElevator initialised (SP SCIM ID: %s%s).",
            self._sp_scim_id,
            " — DRY RUN, no writes will occur" if self.dry_run else "",
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:  # type: ignore[override]
        cleanup_exc: Optional[Exception] = None
        try:
            self.revoke_elevated()
        except Exception as exc:
            cleanup_exc = exc

        if cleanup_exc is not None:
            if exc_val is not None:
                # Both the audit and the cleanup failed.  Log the original
                # audit error so it is not obscured by the cleanup error.
                log.error(
                    "Audit failed with: %s. "
                    "Cleanup also failed — see manual instructions below.",
                    exc_val,
                )
            raise cleanup_exc

        return False  # never suppress the original exception

    # ------------------------------------------------------------------
    # SP identity
    # ------------------------------------------------------------------

    def _resolve_sp_id(self) -> str:
        """Look up the SP's numeric SCIM ID from its application (client) ID.

        Raises
        ------
        ValueError
            If the SP is not found in the account SCIM directory.
        """
        resp = self.api.account_api(
            "GET",
            "/scim/v2/ServicePrincipals",
            params={"filter": f'applicationId eq "{_scim_filter_escape(self.sp_application_id)}"'},
        )
        resources = resp.get("Resources", [])
        if not resources:
            raise ValueError(
                f"Service principal with application ID '{self.sp_application_id}' "
                "was not found in the account SCIM directory.  Ensure the SP is "
                "provisioned at the account level before running with --auto-elevate."
            )
        return str(resources[0]["id"])

    # ------------------------------------------------------------------
    # Workspace Admin check and elevation
    # ------------------------------------------------------------------

    def _current_workspace_level(self, workspace_id: str) -> Optional[str]:
        """Return the SP's current assignment level on a workspace.

        Returns ``"WORKSPACE_ADMIN"``, ``"USER"``, or ``None`` (no assignment).
        Returns ``None`` on API errors so the caller can attempt elevation
        regardless — a failed read should not block the audit.
        """
        try:
            resp = self.api.account_api(
                "GET", f"/workspaces/{workspace_id}/permissionassignments"
            )
        except Exception as exc:
            log.warning(
                "Could not read permission assignments for workspace %s: %s",
                workspace_id, exc,
            )
            return None

        for pa in resp.get("permission_assignments", []):
            principal = pa.get("principal", {})
            # Match on numeric SCIM ID or on service_principal_name (application ID).
            if (
                str(principal.get("id", "")) == self._sp_scim_id
                or str(principal.get("service_principal_name", ""))
                == self.sp_application_id
            ):
                perms = pa.get("permissions", [])
                if _WORKSPACE_ADMIN in perms:
                    return _WORKSPACE_ADMIN
                return _USER

        return None  # SP has no assignment on this workspace

    def ensure_workspace_admin(
        self, workspace_id: str, workspace_name: str
    ) -> bool:
        """Elevate the SP to ``WORKSPACE_ADMIN`` on this workspace if needed.

        If the SP is already a Workspace Admin the method is a no-op and
        returns ``False``.  Otherwise it grants ``WORKSPACE_ADMIN``, records
        the prior state, and returns ``True``.

        The prior state (no assignment, or ``USER``-level) is stored
        internally so that :meth:`revoke_elevated` can restore it exactly.

        Parameters
        ----------
        workspace_id:
            Numeric workspace ID from the Account API (``WorkspaceInfo.workspace_id``).
            If the value is ``"manual"`` (set when workspaces are supplied via
            ``--workspace-urls``), the workspace ID is not known and elevation
            is skipped with a warning.
        workspace_name:
            Human-readable name used in log messages only.

        Returns
        -------
        bool
            ``True`` if elevation was performed; ``False`` if already admin or
            skipped.

        Raises
        ------
        RuntimeError
            If called outside of a ``with`` block.
        """
        if self._sp_scim_id is None:
            raise RuntimeError(
                "PermissionElevator must be used as a context manager "
                "(`with PermissionElevator(...) as elev:`)."
            )

        if workspace_id == "manual":
            log.warning(
                "Workspace '%s' has no known workspace ID (supplied via --workspace-urls). "
                "Cannot auto-elevate — ensure the SP is already a Workspace Admin there.",
                workspace_name,
            )
            return False

        prior = self._current_workspace_level(workspace_id)

        if prior == _WORKSPACE_ADMIN:
            log.debug(
                "SP already WORKSPACE_ADMIN on '%s' — skipping elevation.",
                workspace_name,
            )
            return False

        log.info(
            "%sElevating SP to WORKSPACE_ADMIN on workspace '%s' "
            "(prior assignment: %s).",
            "[dry-run] " if self.dry_run else "",
            workspace_name,
            prior if prior is not None else "none",
        )

        if not self.dry_run:
            self.api.account_api(
                "PUT",
                f"/workspaces/{workspace_id}/permissionassignments"
                f"/principals/{self._sp_scim_id}",
                json={"permission_level": _WORKSPACE_ADMIN},
            )

        # Record the elevation even in dry-run mode so revoke_elevated() has
        # a consistent view of what would have been elevated.
        self._elevated.append(
            _ElevatedWorkspace(
                workspace_id=workspace_id,
                workspace_name=workspace_name,
                prior_level=prior,
            )
        )
        return True

    # ------------------------------------------------------------------
    # Cleanup / restoration
    # ------------------------------------------------------------------

    def revoke_elevated(self) -> None:
        """Restore all elevated workspaces to their pre-elevation state.

        Called automatically by ``__exit__``.  Can also be called manually
        if you need to release permissions before the ``with`` block ends.

        After this method returns, :attr:`_elevated` is always cleared —
        even if individual restorations failed — so the method is safe to
        call multiple times.

        Raises
        ------
        RuntimeError
            If one or more workspace restorations failed.  The error message
            includes explicit manual revocation instructions so nothing is
            left dangling silently.
        """
        if not self._elevated:
            return

        failed: List[str] = []

        for record in list(self._elevated):
            try:
                self._restore_workspace(record)
            except Exception as exc:
                log.error(
                    "FAILED to restore permissions on workspace '%s': %s",
                    record.workspace_name, exc,
                )
                failed.append(record.workspace_name)

        self._elevated.clear()

        if failed:
            sp_id = self._sp_scim_id or "<sp-scim-id>"
            manual_steps = "\n".join(
                f"  Workspace '{ws}': remove WORKSPACE_ADMIN for SP SCIM ID {sp_id} "
                f"via the Databricks account console or:\n"
                f"    DELETE /api/2.0/accounts/<account-id>/workspaces/<workspace-id>"
                f"/permissionassignments/principals/{sp_id}"
                for ws in failed
            )
            msg = (
                f"Permission cleanup failed for {len(failed)} workspace(s). "
                "Manual action required to remove the temporary WORKSPACE_ADMIN grant:\n"
                + manual_steps
            )
            log.error(msg)
            raise RuntimeError(msg)

    def _restore_workspace(self, record: _ElevatedWorkspace) -> None:
        """Restore a single workspace to its pre-elevation state."""
        base = (
            f"/workspaces/{record.workspace_id}/permissionassignments"
            f"/principals/{self._sp_scim_id}"
        )

        if self.dry_run:
            action = (
                "DELETE assignment"
                if record.prior_level is None
                else f"PUT to {record.prior_level}"
            )
            log.info(
                "[dry-run] Would restore workspace '%s': %s.",
                record.workspace_name, action,
            )
            return

        if record.prior_level is None:
            # SP had no assignment before elevation — delete it entirely.
            log.info(
                "Removing temporary WORKSPACE_ADMIN grant on '%s' "
                "(SP had no prior workspace assignment).",
                record.workspace_name,
            )
            self.api.account_api("DELETE", base)
        else:
            # SP had a lower-level assignment — restore it.
            log.info(
                "Restoring workspace '%s' assignment to %s.",
                record.workspace_name, record.prior_level,
            )
            self.api.account_api("PUT", base, json={"permission_level": record.prior_level})
