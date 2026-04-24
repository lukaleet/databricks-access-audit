"""Tests for PermissionElevator — just-in-time Workspace Admin elevation."""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from databricks_group_audit.elevate import PermissionElevator

ACCOUNT_HOST = "https://accounts.azuredatabricks.net"
ACCOUNT_ID = "test-account-id"

SP_APP_ID = "sp-app-001"
SP_SCIM_ID = "scim-sp-99"

# Minimal SCIM response used to resolve the SP's SCIM ID.
_SP_SCIM_RESP = {
    "Resources": [{"id": SP_SCIM_ID, "applicationId": SP_APP_ID}],
    "totalResults": 1,
}

# account_api side_effect helpers ----------------------------------------


def _make_client(permission_assignments: list | None = None):
    """Return a mock AuditClient with a configurable account_api."""
    client = MagicMock()

    def _account_api(method: str, endpoint: str, **kwargs):
        if endpoint == "/scim/v2/ServicePrincipals":
            return _SP_SCIM_RESP
        if "permissionassignments" in endpoint and method == "GET":
            assignments = permission_assignments if permission_assignments is not None else []
            return {"permission_assignments": assignments}
        # PUT / DELETE — succeed silently.
        return {}

    client.account_api.side_effect = _account_api
    return client


def _ws_admin_assignment(sp_scim_id: str = SP_SCIM_ID):
    return {"principal": {"id": sp_scim_id}, "permissions": ["WORKSPACE_ADMIN"]}


def _user_assignment(sp_scim_id: str = SP_SCIM_ID):
    return {"principal": {"id": sp_scim_id}, "permissions": ["USER"]}


# ---------------------------------------------------------------------------
# SP ID resolution
# ---------------------------------------------------------------------------


def test_resolve_sp_id_found():
    client = _make_client()
    with PermissionElevator(client, SP_APP_ID) as elev:
        assert elev._sp_scim_id == SP_SCIM_ID


def test_resolve_sp_id_not_found():
    client = MagicMock()
    client.account_api.return_value = {"Resources": [], "totalResults": 0}

    with pytest.raises(ValueError, match="not found in the account SCIM directory"):
        with PermissionElevator(client, SP_APP_ID):
            pass


# ---------------------------------------------------------------------------
# ensure_workspace_admin — already admin
# ---------------------------------------------------------------------------


def test_already_admin_is_noop():
    client = _make_client([_ws_admin_assignment()])
    with PermissionElevator(client, SP_APP_ID) as elev:
        elevated = elev.ensure_workspace_admin("ws-1", "my-workspace")

    assert elevated is False
    # No PUT or DELETE calls expected.
    put_calls = [c for c in client.account_api.call_args_list if c.args[0] == "PUT"]
    assert not put_calls


# ---------------------------------------------------------------------------
# ensure_workspace_admin — elevation needed (no prior assignment)
# ---------------------------------------------------------------------------


def test_elevate_no_prior_assignment():
    client = _make_client([])  # SP not in assignments list
    with PermissionElevator(client, SP_APP_ID) as elev:
        elevated = elev.ensure_workspace_admin("ws-1", "my-workspace")
        assert elevated is True
        assert elev._elevated[0].prior_level is None

    # Cleanup: should have called DELETE (no prior assignment).
    delete_calls = [c for c in client.account_api.call_args_list if c.args[0] == "DELETE"]
    assert len(delete_calls) == 1
    assert f"/principals/{SP_SCIM_ID}" in delete_calls[0].args[1]


def test_elevate_sends_correct_put_payload():
    client = _make_client([])
    with PermissionElevator(client, SP_APP_ID) as elev:
        elev.ensure_workspace_admin("ws-42", "workspace-42")

    put_calls = [c for c in client.account_api.call_args_list if c.args[0] == "PUT"]
    # First PUT is the elevation grant.
    elevation_put = next(c for c in put_calls if "permissionassignments" in c.args[1])
    assert elevation_put.kwargs["json"]["permission_level"] == "WORKSPACE_ADMIN"


# ---------------------------------------------------------------------------
# ensure_workspace_admin — prior USER assignment → restored after
# ---------------------------------------------------------------------------


def test_elevate_with_prior_user_assignment():
    client = _make_client([_user_assignment()])
    with PermissionElevator(client, SP_APP_ID) as elev:
        elevated = elev.ensure_workspace_admin("ws-1", "my-workspace")
        assert elevated is True
        assert elev._elevated[0].prior_level == "USER"

    # Cleanup: should have called PUT back to USER.
    put_calls = [c for c in client.account_api.call_args_list if c.args[0] == "PUT"]
    restore_put = put_calls[-1]
    assert restore_put.kwargs["json"]["permission_level"] == "USER"


# ---------------------------------------------------------------------------
# ensure_workspace_admin — manual workspace_id (from --workspace-urls)
# ---------------------------------------------------------------------------


def test_manual_workspace_id_skips_elevation():
    client = _make_client()
    with PermissionElevator(client, SP_APP_ID) as elev:
        elevated = elev.ensure_workspace_admin("manual", "manual-ws")

    assert elevated is False
    assert not elev._elevated


# ---------------------------------------------------------------------------
# ensure_workspace_admin — called outside context manager
# ---------------------------------------------------------------------------


def test_ensure_outside_context_raises():
    client = _make_client()
    elev = PermissionElevator(client, SP_APP_ID)
    with pytest.raises(RuntimeError, match="context manager"):
        elev.ensure_workspace_admin("ws-1", "ws")


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


def test_dry_run_no_writes():
    client = _make_client([])
    with PermissionElevator(client, SP_APP_ID, dry_run=True) as elev:
        elev.ensure_workspace_admin("ws-1", "ws")
        assert elev._elevated[0].prior_level is None  # state tracked

    # In dry-run, only GET and SCIM calls should be made — no PUT/DELETE.
    write_calls = [
        c for c in client.account_api.call_args_list
        if c.args[0] in ("PUT", "DELETE")
    ]
    assert not write_calls


def test_dry_run_elevation_still_recorded():
    """Even in dry-run, _elevated tracks what *would* be elevated."""
    client = _make_client([])
    with PermissionElevator(client, SP_APP_ID, dry_run=True) as elev:
        elev.ensure_workspace_admin("ws-1", "ws-one")
        elev.ensure_workspace_admin("ws-2", "ws-two")
        assert len(elev._elevated) == 2


# ---------------------------------------------------------------------------
# Cleanup on audit exception
# ---------------------------------------------------------------------------


def test_cleanup_runs_on_audit_exception():
    client = _make_client([])
    with pytest.raises(ValueError, match="audit failed"):
        with PermissionElevator(client, SP_APP_ID) as elev:
            elev.ensure_workspace_admin("ws-1", "ws")
            raise ValueError("audit failed")

    # Cleanup (DELETE) must still have been called.
    delete_calls = [c for c in client.account_api.call_args_list if c.args[0] == "DELETE"]
    assert len(delete_calls) == 1


def test_cleanup_failure_raises_runtime_error():
    """If cleanup fails, RuntimeError with manual instructions is raised."""
    client = _make_client([])

    call_count = {"n": 0}

    def _flaky_api(method: str, endpoint: str, **kwargs):
        if endpoint == "/scim/v2/ServicePrincipals":
            return _SP_SCIM_RESP
        if method == "GET" and "permissionassignments" in endpoint:
            return {"permission_assignments": []}
        if method == "PUT" and call_count["n"] == 0:
            # First PUT (elevation) succeeds.
            call_count["n"] += 1
            return {}
        if method == "DELETE":
            raise RuntimeError("network error during cleanup")
        return {}

    client.account_api.side_effect = _flaky_api

    with pytest.raises(RuntimeError, match="Manual action required"):
        with PermissionElevator(client, SP_APP_ID) as elev:
            elev.ensure_workspace_admin("ws-1", "ws")


def test_cleanup_failure_when_audit_also_fails():
    """When both audit and cleanup fail, RuntimeError from cleanup is raised."""
    client = _make_client([])

    call_count = {"n": 0}

    def _flaky_api(method: str, endpoint: str, **kwargs):
        if endpoint == "/scim/v2/ServicePrincipals":
            return _SP_SCIM_RESP
        if method == "GET" and "permissionassignments" in endpoint:
            return {"permission_assignments": []}
        if method == "PUT" and call_count["n"] == 0:
            call_count["n"] += 1
            return {}
        if method == "DELETE":
            raise RuntimeError("cleanup network error")
        return {}

    client.account_api.side_effect = _flaky_api

    with pytest.raises(RuntimeError, match="Manual action required"):
        with PermissionElevator(client, SP_APP_ID) as elev:
            elev.ensure_workspace_admin("ws-1", "ws")
            raise ValueError("audit also failed")


# ---------------------------------------------------------------------------
# Multiple workspaces — partial failure in cleanup
# ---------------------------------------------------------------------------


def test_multiple_workspaces_all_restored():
    client = _make_client([])
    with PermissionElevator(client, SP_APP_ID) as elev:
        elev.ensure_workspace_admin("ws-1", "workspace-one")
        elev.ensure_workspace_admin("ws-2", "workspace-two")

    delete_calls = [c for c in client.account_api.call_args_list if c.args[0] == "DELETE"]
    assert len(delete_calls) == 2


def test_revoke_elevated_clears_list():
    client = _make_client([])
    with PermissionElevator(client, SP_APP_ID) as elev:
        elev.ensure_workspace_admin("ws-1", "ws")
        assert len(elev._elevated) == 1
    # After __exit__ the list must be cleared.
    assert elev._elevated == []


# ---------------------------------------------------------------------------
# revoke_elevated called manually (idempotent on second call)
# ---------------------------------------------------------------------------


def test_revoke_elevated_idempotent():
    client = _make_client([])
    with PermissionElevator(client, SP_APP_ID) as elev:
        elev.ensure_workspace_admin("ws-1", "ws")
        elev.revoke_elevated()  # manual early revoke
        assert elev._elevated == []
    # __exit__ calls revoke_elevated again — should be a no-op (empty list).
    delete_calls = [c for c in client.account_api.call_args_list if c.args[0] == "DELETE"]
    assert len(delete_calls) == 1  # exactly one delete, not two


# ---------------------------------------------------------------------------
# current_workspace_level — match by service_principal_name fallback
# ---------------------------------------------------------------------------


def test_match_by_service_principal_name():
    """SP can also be matched by service_principal_name (app-ID) in the API response."""
    assignment_by_name = {
        "principal": {"service_principal_name": SP_APP_ID},
        "permissions": ["WORKSPACE_ADMIN"],
    }
    client = _make_client([assignment_by_name])
    with PermissionElevator(client, SP_APP_ID) as elev:
        elevated = elev.ensure_workspace_admin("ws-1", "ws")

    # Already admin via service_principal_name match → no elevation.
    assert elevated is False


# ---------------------------------------------------------------------------
# current_workspace_level — API error → treat as no assignment
# ---------------------------------------------------------------------------


def test_permission_read_error_proceeds_with_elevation():
    """If reading current permissions fails, elevation proceeds anyway."""
    client = MagicMock()

    call_count = {"n": 0}

    def _api(method: str, endpoint: str, **kwargs):
        if endpoint == "/scim/v2/ServicePrincipals":
            return _SP_SCIM_RESP
        if method == "GET" and "permissionassignments" in endpoint:
            raise RuntimeError("API error")
        return {}

    client.account_api.side_effect = _api

    with PermissionElevator(client, SP_APP_ID) as elev:
        elevated = elev.ensure_workspace_admin("ws-1", "ws")

    # Elevation attempted (prior=None from error path).
    assert elevated is True
