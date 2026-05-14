"""Snapshot serialisation and delta comparison for audit runs.

Each audit run can optionally save a timestamped JSON snapshot (``--save-snapshot
PATH``).  A later run can load a previous snapshot as a baseline (``--baseline
PATH``) and the tool will output what changed: new grants, removed grants, new
members, and removed members.

The snapshot format is intentionally simple plain-dict JSON so it remains
readable without this library installed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from databricks_access_audit.models import AuditDiff

SNAPSHOT_VERSION = "1"


# ---------------------------------------------------------------------------
# Serialise model objects → plain dicts
# ---------------------------------------------------------------------------

def _member_dict(m: Any) -> Dict:
    return {
        "id": m.id,
        "display_name": m.display_name,
        "type": m.member_type.value,
        "external_id": m.external_id,
    }


def _catalog_grant_dict(g: Any) -> Dict:
    return {
        "securable_type": "CATALOG",
        "workspace_name": g.workspace_name,
        "securable_name": g.catalog_name,
        "principal": g.principal,
        "principal_type": g.principal_type,
        "privileges": sorted(g.privileges),
        "grant_source": g.grant_source.value,
        "inherited_from": g.inherited_from,
    }


def _schema_grant_dict(g: Any) -> Dict:
    return {
        "securable_type": "SCHEMA",
        "workspace_name": g.workspace_name,
        "securable_name": f"{g.catalog_name}.{g.schema_name}",
        "principal": g.principal,
        "principal_type": g.principal_type,
        "privileges": sorted(g.privileges),
        "grant_source": g.grant_source.value,
        "inherited_from": g.inherited_from,
    }


def _table_grant_dict(g: Any) -> Dict:
    return {
        "securable_type": "TABLE",
        "workspace_name": g.workspace_name,
        "securable_name": g.full_name,
        "principal": g.principal,
        "principal_type": g.principal_type,
        "privileges": sorted(g.privileges),
        "grant_source": g.grant_source.value,
        "inherited_from": g.inherited_from,
    }


def _volume_grant_dict(g: Any) -> Dict:
    return {
        "securable_type": "VOLUME",
        "workspace_name": g.workspace_name,
        "securable_name": g.full_name,
        "principal": g.principal,
        "principal_type": g.principal_type,
        "privileges": sorted(g.privileges),
        "grant_source": g.grant_source.value,
        "inherited_from": g.inherited_from,
    }


# ---------------------------------------------------------------------------
# Build snapshots from audit run results
# ---------------------------------------------------------------------------

def _ws_object_grant_dict(g: Any) -> Dict:
    return {
        "securable_type": g.object_type,
        "workspace_name": g.workspace_name,
        "securable_name": g.object_name,
        "object_id": g.object_id,
        "principal": g.principal,
        "principal_type": g.principal_type,
        "permission_level": g.permission_level,
        "grant_source": g.grant_source.value,
        "inherited_from": g.inherited_from,
    }


def build_group_snapshot(
    group_name: str,
    members: Dict,
    catalog_grants: List,
    schema_grants: List,
    table_grants: List,
    workspace_object_grants: Optional[List] = None,
    volume_grants: Optional[List] = None,
) -> Dict:
    """Serialise a group audit run into a snapshot dict."""
    grants = (
        [_catalog_grant_dict(g) for g in catalog_grants]
        + [_schema_grant_dict(g) for g in schema_grants]
        + [_table_grant_dict(g) for g in table_grants]
        + [_volume_grant_dict(g) for g in (volume_grants or [])]
        + [_ws_object_grant_dict(g) for g in (workspace_object_grants or [])]
    )
    return {
        "version": SNAPSHOT_VERSION,
        "mode": "group",
        "target": group_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "grants": grants,
        "members": {
            "users": [_member_dict(u) for u in members.get("users", [])],
            "service_principals": [
                _member_dict(sp) for sp in members.get("service_principals", [])
            ],
        },
    }


def build_principal_snapshot(result: Any) -> Dict:
    """Serialise a principal audit run into a snapshot dict."""
    uc_grants = [
        {
            "securable_type": p.securable_type,
            "securable_name": p.securable_name,
            "privileges": sorted(p.privileges),
            "via_group": p.via_group,
            "via_path": p.via_path,
            "workspace_name": p.workspace_name,
        }
        for p in result.permissions
    ]
    obj_grants = [
        _ws_object_grant_dict(g)
        for g in getattr(result, "workspace_object_grants", [])
    ]
    return {
        "version": SNAPSHOT_VERSION,
        "mode": "principal",
        "target": result.principal_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "grants": uc_grants + obj_grants,
        "groups": [
            {
                "group_id": g.group_id,
                "group_name": g.group_name,
                "is_direct": g.is_direct,
                "path": g.path,
            }
            for g in result.groups
        ],
        "workspace_roles": [
            {
                "workspace_id": r.workspace_id,
                "workspace_name": r.workspace_name,
                "permission_level": r.permission_level,
                "via_group": r.via_group,
                "via_path": r.via_path,
            }
            for r in result.workspace_roles
        ],
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_snapshot(data: Dict, path: str) -> None:
    """Write *data* as indented JSON to *path* (creates parent dirs if needed)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def load_snapshot(path: str) -> Dict:
    """Load a snapshot dict from *path*.

    Raises
    ------
    ValueError
        If the file's ``version`` field does not match :data:`SNAPSHOT_VERSION`,
        indicating the file was written by an incompatible tool version.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    version = data.get("version")
    if version != SNAPSHOT_VERSION:
        raise ValueError(
            f"Snapshot version mismatch: expected '{SNAPSHOT_VERSION}', "
            f"got '{version}'. Re-run the audit to create a compatible snapshot."
        )
    return data


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def _fingerprint(item: Dict) -> str:
    """Stable string for set-based comparison — any field change == different."""
    return json.dumps(item, sort_keys=True, default=str)


def _member_key(m: Dict) -> str:
    """Identity key for a member (group mode): id + type only."""
    return json.dumps({"id": m.get("id", ""), "type": m.get("type", "")}, sort_keys=True)


def _group_key(g: Dict) -> str:
    """Identity key for a group membership (principal mode): group_id + name."""
    return json.dumps(
        {"group_id": g.get("group_id", ""), "group_name": g.get("group_name", "")},
        sort_keys=True,
    )


def diff_snapshots(baseline: Dict, current: Dict) -> AuditDiff:
    """Return an :class:`AuditDiff` describing what changed between two snapshots.

    Grants are compared by full fingerprint: any field change (including
    privilege additions/removals) is reported as a removal + addition pair.
    Members are compared by identity key (id + type) so display-name changes
    are not flagged as churn.
    """
    baseline_mode = baseline.get("mode", "group")
    mode = current.get("mode", "group")

    if baseline_mode != mode:
        raise ValueError(
            f"Cannot diff snapshots of different modes: "
            f"baseline is '{baseline_mode}', current is '{mode}'. "
            f"Re-run the same command that created the baseline snapshot."
        )

    # Grants
    b_grants = {_fingerprint(g): g for g in baseline.get("grants", [])}
    c_grants = {_fingerprint(g): g for g in current.get("grants", [])}
    grants_added = [g for fp, g in c_grants.items() if fp not in b_grants]
    grants_removed = [g for fp, g in b_grants.items() if fp not in c_grants]

    # Members or group memberships
    if mode == "group":
        b_all = [
            m
            for lst in baseline.get("members", {}).values()
            for m in lst
        ]
        c_all = [
            m
            for lst in current.get("members", {}).values()
            for m in lst
        ]
        b_keys = {_member_key(m): m for m in b_all}
        c_keys = {_member_key(m): m for m in c_all}
        members_added = [m for k, m in c_keys.items() if k not in b_keys]
        members_removed = [m for k, m in b_keys.items() if k not in c_keys]
    else:
        b_grps = {_group_key(g): g for g in baseline.get("groups", [])}
        c_grps = {_group_key(g): g for g in current.get("groups", [])}
        members_added = [g for k, g in c_grps.items() if k not in b_grps]
        members_removed = [g for k, g in b_grps.items() if k not in c_grps]

    return AuditDiff(
        baseline_timestamp=baseline.get("timestamp", ""),
        current_timestamp=current.get("timestamp", ""),
        mode=mode,
        target=current.get("target", ""),
        grants_added=grants_added,
        grants_removed=grants_removed,
        members_added=members_added,
        members_removed=members_removed,
    )
