"""Tests for snapshot build/save/load/diff (snapshot.py)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from databricks_group_audit.models import (
    AuditDiff,
    CatalogGrant,
    EffectivePermission,
    GrantSource,
    GroupMember,
    GroupMembership,
    MemberType,
    PrincipalAuditResult,
    WorkspaceRole,
)
from databricks_group_audit.snapshot import (
    SNAPSHOT_VERSION,
    build_group_snapshot,
    build_principal_snapshot,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _cat_grant(catalog="main", principal="alice@example.com", privs=None, ws="ws1"):
    return CatalogGrant(
        catalog_name=catalog,
        workspace_name=ws,
        workspace_url=f"https://{ws}.azuredatabricks.net",
        principal=principal,
        principal_type="USER",
        privileges=privs or ["USE_CATALOG", "SELECT"],
        grant_source=GrantSource.MEMBER_DIRECT,
        inherited_from=None,
    )


def _user(uid="u-1", name="Alice", ext_id=None):
    return GroupMember(id=uid, display_name=name, member_type=MemberType.USER,
                       external_id=ext_id)


def _sp(sid="sp-1", name="ETL-Bot"):
    return GroupMember(id=sid, display_name=name,
                       member_type=MemberType.SERVICE_PRINCIPAL)


def _members(*users, sps=None):
    return {"users": list(users), "service_principals": list(sps or [])}


def _principal_result(name="alice@example.com"):
    r = PrincipalAuditResult(
        principal_type="USER",
        principal_id="u-1",
        principal_name=name,
        permissions=[
            EffectivePermission(
                securable_type="CATALOG",
                securable_name="main",
                privileges=["USE_CATALOG"],
                via_group="data-engineers",
                workspace_name="ws1",
                workspace_url="https://ws1.azuredatabricks.net",
            )
        ],
        groups=[
            GroupMembership(group_id="g-1", group_name="data-engineers", is_direct=True)
        ],
        workspace_roles=[
            WorkspaceRole(
                workspace_id="ws-1", workspace_name="ws1",
                workspace_url="https://ws1.azuredatabricks.net",
                permission_level="USER", via_group="data-engineers",
            )
        ],
    )
    return r


# ---------------------------------------------------------------------------
# build_group_snapshot
# ---------------------------------------------------------------------------

def test_group_snapshot_version():
    snap = build_group_snapshot("grp", _members(_user()), [], [], [])
    assert snap["version"] == SNAPSHOT_VERSION


def test_group_snapshot_mode_and_target():
    snap = build_group_snapshot("data-engineers", _members(_user()), [], [], [])
    assert snap["mode"] == "group"
    assert snap["target"] == "data-engineers"


def test_group_snapshot_timestamp_is_set():
    snap = build_group_snapshot("grp", _members(_user()), [], [], [])
    assert snap["timestamp"]  # non-empty


def test_group_snapshot_grants_serialised():
    snap = build_group_snapshot("grp", _members(), [_cat_grant()], [], [])
    assert len(snap["grants"]) == 1
    g = snap["grants"][0]
    assert g["securable_type"] == "CATALOG"
    assert g["securable_name"] == "main"
    assert g["principal"] == "alice@example.com"
    assert "USE_CATALOG" in g["privileges"]


def test_group_snapshot_members_serialised():
    snap = build_group_snapshot("grp", _members(_user("u-1", "Alice")), [], [], [])
    assert len(snap["members"]["users"]) == 1
    assert snap["members"]["users"][0]["id"] == "u-1"
    assert snap["members"]["users"][0]["display_name"] == "Alice"


def test_group_snapshot_sp_members():
    snap = build_group_snapshot("grp", _members(sps=[_sp()]), [], [], [])
    assert len(snap["members"]["service_principals"]) == 1
    assert snap["members"]["service_principals"][0]["type"] == "ServicePrincipal"


def test_group_snapshot_privileges_sorted():
    snap = build_group_snapshot(
        "grp", _members(), [_cat_grant(privs=["SELECT", "USE_CATALOG"])], [], []
    )
    assert snap["grants"][0]["privileges"] == sorted(["SELECT", "USE_CATALOG"])


# ---------------------------------------------------------------------------
# build_principal_snapshot
# ---------------------------------------------------------------------------

def test_principal_snapshot_mode():
    snap = build_principal_snapshot(_principal_result())
    assert snap["mode"] == "principal"


def test_principal_snapshot_target():
    snap = build_principal_snapshot(_principal_result("bob@example.com"))
    assert snap["target"] == "bob@example.com"


def test_principal_snapshot_grants():
    snap = build_principal_snapshot(_principal_result())
    assert len(snap["grants"]) == 1
    assert snap["grants"][0]["securable_type"] == "CATALOG"


def test_principal_snapshot_groups():
    snap = build_principal_snapshot(_principal_result())
    assert len(snap["groups"]) == 1
    assert snap["groups"][0]["group_name"] == "data-engineers"


def test_principal_snapshot_workspace_roles():
    snap = build_principal_snapshot(_principal_result())
    assert len(snap["workspace_roles"]) == 1
    assert snap["workspace_roles"][0]["permission_level"] == "USER"


# ---------------------------------------------------------------------------
# save_snapshot / load_snapshot round-trip
# ---------------------------------------------------------------------------

def test_save_load_roundtrip():
    snap = build_group_snapshot("grp", _members(_user()), [_cat_grant()], [], [])
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    save_snapshot(snap, path)
    loaded = load_snapshot(path)
    assert loaded["target"] == snap["target"]
    assert loaded["grants"][0]["securable_name"] == "main"


def test_save_creates_parent_dirs(tmp_path):
    nested = str(tmp_path / "a" / "b" / "snap.json")
    snap = build_group_snapshot("grp", _members(), [], [], [])
    save_snapshot(snap, nested)
    assert Path(nested).exists()


def test_load_parses_json(tmp_path):
    path = str(tmp_path / "test.json")
    data = {"version": "1", "mode": "group", "target": "grp", "grants": []}
    Path(path).write_text(json.dumps(data), encoding="utf-8")
    loaded = load_snapshot(path)
    assert loaded["target"] == "grp"


# ---------------------------------------------------------------------------
# diff_snapshots — group mode
# ---------------------------------------------------------------------------

def _snap(grants=None, users=None, sps=None, target="grp", ts="2025-01-01T00:00:00Z"):
    return {
        "version": SNAPSHOT_VERSION,
        "mode": "group",
        "target": target,
        "timestamp": ts,
        "grants": grants or [],
        "members": {
            "users": users or [],
            "service_principals": sps or [],
        },
    }


def _grant_dict(catalog="main", principal="alice@example.com", privs=None):
    return {
        "securable_type": "CATALOG",
        "workspace_name": "ws1",
        "securable_name": catalog,
        "principal": principal,
        "principal_type": "USER",
        "privileges": sorted(privs or ["USE_CATALOG", "SELECT"]),
        "grant_source": "Member Direct",
        "inherited_from": None,
    }


def _member_dict(uid="u-1", name="Alice", mtype="User"):
    return {"id": uid, "display_name": name, "type": mtype, "external_id": None}


def test_diff_no_changes():
    g = _grant_dict()
    s1 = _snap(grants=[g], users=[_member_dict()])
    s2 = _snap(grants=[g], users=[_member_dict()], ts="2025-04-01T00:00:00Z")
    diff = diff_snapshots(s1, s2)
    assert not diff.has_changes
    assert diff.grants_added == []
    assert diff.grants_removed == []
    assert diff.members_added == []
    assert diff.members_removed == []


def test_diff_grant_added():
    s1 = _snap()
    s2 = _snap(grants=[_grant_dict()])
    diff = diff_snapshots(s1, s2)
    assert len(diff.grants_added) == 1
    assert diff.grants_removed == []
    assert diff.grants_added[0]["securable_name"] == "main"


def test_diff_grant_removed():
    s1 = _snap(grants=[_grant_dict()])
    s2 = _snap()
    diff = diff_snapshots(s1, s2)
    assert len(diff.grants_removed) == 1
    assert diff.grants_added == []


def test_diff_member_added():
    s1 = _snap()
    s2 = _snap(users=[_member_dict("u-99", "NewUser")])
    diff = diff_snapshots(s1, s2)
    assert len(diff.members_added) == 1
    assert diff.members_added[0]["display_name"] == "NewUser"
    assert diff.members_removed == []


def test_diff_member_removed():
    s1 = _snap(users=[_member_dict("u-1", "Alice")])
    s2 = _snap()
    diff = diff_snapshots(s1, s2)
    assert len(diff.members_removed) == 1
    assert diff.members_added == []


def test_diff_privilege_change_appears_as_add_and_remove():
    g_before = _grant_dict(privs=["SELECT"])
    g_after = _grant_dict(privs=["SELECT", "MODIFY"])
    s1 = _snap(grants=[g_before])
    s2 = _snap(grants=[g_after])
    diff = diff_snapshots(s1, s2)
    # Grant fingerprint changed → shows as removed + added
    assert len(diff.grants_removed) == 1
    assert len(diff.grants_added) == 1
    assert diff.has_changes


def test_diff_member_display_name_change_not_flagged():
    s1 = _snap(users=[_member_dict("u-1", "Alice")])
    s2 = _snap(users=[_member_dict("u-1", "Alice Smith")])  # same id, different name
    diff = diff_snapshots(s1, s2)
    # Member identity is (id, type) — display-name change is not a membership change
    assert not diff.has_changes


def test_diff_timestamps_preserved():
    s1 = _snap(ts="2025-01-01T00:00:00Z")
    s2 = _snap(ts="2025-04-01T00:00:00Z")
    diff = diff_snapshots(s1, s2)
    assert diff.baseline_timestamp == "2025-01-01T00:00:00Z"
    assert diff.current_timestamp == "2025-04-01T00:00:00Z"


def test_diff_target_from_current():
    s1 = _snap(target="grp-old")
    s2 = _snap(target="grp-new")
    diff = diff_snapshots(s1, s2)
    assert diff.target == "grp-new"


# ---------------------------------------------------------------------------
# diff_snapshots — principal mode
# ---------------------------------------------------------------------------

def _principal_snap(grants=None, groups=None, ts="2025-01-01T00:00:00Z"):
    return {
        "version": SNAPSHOT_VERSION,
        "mode": "principal",
        "target": "alice@example.com",
        "timestamp": ts,
        "grants": grants or [],
        "groups": groups or [],
        "workspace_roles": [],
    }


def _perm_dict(securable="main", via="data-engineers"):
    return {
        "securable_type": "CATALOG",
        "securable_name": securable,
        "privileges": ["USE_CATALOG"],
        "via_group": via,
        "workspace_name": "ws1",
    }


def _grp_dict(gid="g-1", name="data-engineers"):
    return {"group_id": gid, "group_name": name, "is_direct": True, "path": [name]}


def test_principal_diff_no_changes():
    g = _perm_dict()
    grp = _grp_dict()
    s1 = _principal_snap(grants=[g], groups=[grp])
    s2 = _principal_snap(grants=[g], groups=[grp], ts="2025-04-01T00:00:00Z")
    diff = diff_snapshots(s1, s2)
    assert not diff.has_changes


def test_principal_diff_grant_added():
    s1 = _principal_snap()
    s2 = _principal_snap(grants=[_perm_dict()])
    diff = diff_snapshots(s1, s2)
    assert len(diff.grants_added) == 1
    assert diff.mode == "principal"


def test_principal_diff_group_added():
    s1 = _principal_snap()
    s2 = _principal_snap(groups=[_grp_dict("g-99", "new-group")])
    diff = diff_snapshots(s1, s2)
    assert len(diff.members_added) == 1
    assert diff.members_added[0]["group_name"] == "new-group"


def test_principal_diff_group_removed():
    s1 = _principal_snap(groups=[_grp_dict()])
    s2 = _principal_snap()
    diff = diff_snapshots(s1, s2)
    assert len(diff.members_removed) == 1


# ---------------------------------------------------------------------------
# AuditDiff.has_changes property
# ---------------------------------------------------------------------------

def test_has_changes_false_when_empty():
    d = AuditDiff(
        baseline_timestamp="", current_timestamp="",
        mode="group", target="grp",
    )
    assert not d.has_changes


def test_has_changes_true_on_grants_added():
    d = AuditDiff(
        baseline_timestamp="", current_timestamp="",
        mode="group", target="grp",
        grants_added=[{"x": 1}],
    )
    assert d.has_changes


def test_has_changes_true_on_members_removed():
    d = AuditDiff(
        baseline_timestamp="", current_timestamp="",
        mode="group", target="grp",
        members_removed=[{"id": "u-1"}],
    )
    assert d.has_changes
