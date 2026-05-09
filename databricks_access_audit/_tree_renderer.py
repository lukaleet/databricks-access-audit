"""ASCII tree renderer for principal audit — grouped by granting entity."""
from __future__ import annotations

from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from databricks_access_audit.models import PrincipalAuditResult, WorkspaceObjectGrant


def render_principal_tree(
    result: "PrincipalAuditResult",
    obj_grants: List["WorkspaceObjectGrant"],
    show_escalations: bool = False,
    show_workspace_objects: bool = False,
) -> None:
    SEP = "=" * 62
    from databricks_access_audit.models import PrincipalSource
    p_src = "external" if result.principal_source == PrincipalSource.EXTERNAL else "internal"

    print(f"\n{SEP}")
    print(f"  {result.principal_name}  ({result.principal_type} · {p_src})")
    print(f"{SEP}")

    # ── per-group buckets ────────────────────────────────────────────────────
    mem_by_name = {m.group_name: m for m in result.groups}

    ws_by_group: dict[str, list] = {}
    for r in result.workspace_roles:
        _k = "__direct__" if not r.via_group or r.via_group == "(direct)" else r.via_group
        ws_by_group.setdefault(_k, []).append(r)

    perm_by_group: dict[str, list] = {}
    for p in result.permissions:
        _k = "__direct__" if not p.via_group or p.via_group == "(direct)" else p.via_group
        perm_by_group.setdefault(_k, []).append(p)

    grant_groups = (set(ws_by_group) | set(perm_by_group)) - {"__direct__"}

    def _sort_key(g: str) -> tuple:
        m = mem_by_name.get(g)
        return (0 if (m and m.is_direct) else 1, g.lower())

    sorted_groups = sorted(grant_groups, key=_sort_key)

    has_direct  = bool(ws_by_group.get("__direct__") or perm_by_group.get("__direct__"))
    has_objects = show_workspace_objects and bool(obj_grants)
    n_extra     = (1 if has_direct else 0) + (1 if has_objects else 0)
    total       = len(sorted_groups) + n_extra

    def _branch(idx: int) -> tuple[str, str]:
        last = idx == total - 1
        return ("└─", "  ") if last else ("├─", "│ ")

    # ── group sections ───────────────────────────────────────────────────────
    for i, gname in enumerate(sorted_groups):
        conn, cont = _branch(i)
        m = mem_by_name.get(gname)
        if m:
            if m.is_direct:
                membership_tag = "direct"
            else:
                membership_tag = "transitive: " + " → ".join(m.path)
            src_tag = "Entra/IdP-managed" if m.source.value == "external" else "Databricks-managed"
            tag = f"[{membership_tag} · {src_tag}]"
        else:
            tag = ""

        print(f"\n  {conn} via  {gname}  {tag}")

        ws_list   = ws_by_group.get(gname, [])
        perm_list = perm_by_group.get(gname, [])

        if ws_list:
            print(f"  {cont}    Workspaces:")
            for r in ws_list:
                print(f"  {cont}      {r.workspace_name:<44} {r.permission_level}")

        if perm_list:
            print(f"  {cont}    Unity Catalog:")
            for p in perm_list:
                privs = ", ".join(p.privileges)
                ws    = f"  [{p.workspace_name}]" if p.workspace_name else ""
                print(f"  {cont}      {p.securable_type:<10} {p.securable_name:<44} {privs}{ws}")

    # ── direct / personal grants ─────────────────────────────────────────────
    if has_direct:
        idx       = len(sorted_groups)
        conn, cont = _branch(idx)
        direct_ws    = ws_by_group.get("__direct__", [])
        direct_perms = perm_by_group.get("__direct__", [])
        print(f"\n  {conn} Direct  [personal grants — no group]")
        if direct_ws:
            print(f"  {cont}    Workspaces:")
            for r in direct_ws:
                print(f"  {cont}      {r.workspace_name:<44} {r.permission_level}")
        if direct_perms:
            print(f"  {cont}    Unity Catalog:")
            for p in direct_perms:
                privs = ", ".join(p.privileges)
                ws    = f"  [{p.workspace_name}]" if p.workspace_name else ""
                print(f"  {cont}      {p.securable_type:<10} {p.securable_name:<44} {privs}{ws}")

    # ── workspace objects ────────────────────────────────────────────────────
    if has_objects:
        idx  = len(sorted_groups) + (1 if has_direct else 0)
        conn, _ = _branch(idx)
        print(f"\n  {conn} Workspace objects")
        for g in obj_grants:
            name = g.object_name or g.object_id
            print(
                f"         {g.object_type:<22} {name:<40}"
                f" {g.permission_level:<20} [{g.workspace_name}]"
            )

    # ── uc-only / unused groups ───────────────────────────────────────────────
    if result.uc_only_groups:
        ws_via = {
            r.via_group for r in result.workspace_roles
            if r.via_group and r.via_group != "(direct)"
        }

        def _ws_ancestor(g_name: str) -> str:
            for m in result.groups:
                try:
                    idx = m.path.index(g_name)
                except ValueError:
                    continue
                for later in m.path[idx + 1:]:
                    if later in ws_via:
                        return later
            return ""

        print("\n  UC-only groups  (UC grants only — no direct workspace assignment):")
        for g in result.uc_only_groups:
            ancestor = _ws_ancestor(g)
            if ancestor:
                print(f"    · {g}  [members get workspace access via {ancestor}]")
            else:
                print(f"    · {g}")

    if result.dead_end_groups:
        print("\n  Unused groups  (no workspace access, no UC grants):")
        for g in result.dead_end_groups:
            print(f"    · {g}")

    # ── escalation risks ─────────────────────────────────────────────────────
    if show_escalations and result.escalation_findings:
        print(f"\n  ⚠  Escalation risks ({len(result.escalation_findings)}):")
        for f in result.escalation_findings:
            kind = "transitive" if f.is_transitive else "direct"
            print(f"    ! [{f.securable_type}] {f.securable_name}: {f.privilege}"
                  f" via {f.via_group} ({kind})")

    # ── summary footer ───────────────────────────────────────────────────────
    n_direct   = sum(1 for m in result.groups if m.is_direct)
    n_transit  = len(result.groups) - n_direct
    n_ws       = len({r.workspace_name for r in result.workspace_roles})
    n_uc       = len(result.permissions)
    parts = [
        f"{n_direct} direct group{'s' if n_direct != 1 else ''}",
        f"{n_transit} transitive",
        f"{n_ws} workspace{'s' if n_ws != 1 else ''}",
        f"{n_uc} UC grant{'s' if n_uc != 1 else ''}",
    ]
    if has_objects:
        parts.append(f"{len(obj_grants)} workspace object{'s' if len(obj_grants) != 1 else ''}")

    print(f"\n{'─' * 62}")
    print(f"  {' · '.join(parts)}")
    print(f"{'=' * 62}")
