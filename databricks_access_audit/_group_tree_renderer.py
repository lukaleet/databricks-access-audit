"""ASCII tree renderer for group audit — grouped by grant source."""
from __future__ import annotations

from typing import List, Tuple


def render_group_tree(
    group_name: str,
    group_node,
    members: dict,
    catalog_grants: list,
    schema_grants: list,
    table_grants: list,
    workspace_object_grants: list,
    redundancy: list,
    show_workspace_objects: bool = False,
) -> None:
    from databricks_access_audit.models import GrantSource

    SEP = "=" * 64
    src_tag = "Entra/IdP-managed" if group_node.source.value == "external" else "Databricks-managed"
    n_members = len(members["users"]) + len(members["service_principals"])

    print(f"\n{SEP}")
    print(f"  {group_name}  ({src_tag} · {n_members} member{'s' if n_members != 1 else ''})")
    print(f"{SEP}")

    # Normalise all UC grants to (stype, sname, privs, grant_source, ws, principal)
    all_grants: List[Tuple] = []
    for g in catalog_grants:
        all_grants.append(("CATALOG", g.catalog_name, g.privileges,
                           g.grant_source, g.workspace_name, g.principal))
    for g in schema_grants:
        all_grants.append(("SCHEMA", f"{g.catalog_name}.{g.schema_name}", g.privileges,
                           g.grant_source, g.workspace_name, g.principal))
    for g in table_grants:
        all_grants.append(("TABLE", g.full_name, g.privileges,
                           g.grant_source, g.workspace_name, g.principal))

    # ── bucket by source ─────────────────────────────────────────────────────
    direct_grants  = [g for g in all_grants if g[3] == GrantSource.DIRECT]
    member_grants  = [g for g in all_grants if g[3] == GrantSource.MEMBER_DIRECT]

    upstream_by_parent: dict[str, list] = {}
    for g in all_grants:
        if g[3] == GrantSource.UPSTREAM:
            upstream_by_parent.setdefault(g[5], []).append(g)

    has_direct  = bool(direct_grants)
    has_member  = bool(member_grants)
    has_objects = show_workspace_objects and bool(workspace_object_grants)

    sorted_parents = sorted(upstream_by_parent)
    n_extra = (1 if has_direct else 0) + (1 if has_member else 0) + (1 if has_objects else 0)
    total   = len(sorted_parents) + n_extra

    def _branch(idx: int) -> tuple:
        last = idx == total - 1
        return ("└─", "  ") if last else ("├─", "│ ")

    def _print_uc(grants, cont: str) -> None:
        for stype, sname, privs, _gs, ws, _principal in sorted(grants, key=lambda x: (x[0], x[1])):
            privs_str = ", ".join(privs)
            ws_str    = f"  [{ws}]" if ws else ""
            print(f"  {cont}      {stype:<10} {sname:<44} {privs_str}{ws_str}")

    # ── upstream / parent-group sections ─────────────────────────────────────
    for i, parent_name in enumerate(sorted_parents):
        conn, cont = _branch(i)
        print(f"\n  {conn} via  {parent_name}  [parent group]")
        print(f"  {cont}    Unity Catalog:")
        _print_uc(upstream_by_parent[parent_name], cont)

    # ── direct section ────────────────────────────────────────────────────────
    if has_direct:
        idx = len(sorted_parents)
        conn, cont = _branch(idx)
        print(f"\n  {conn} Direct  [group holds these grants]")
        print(f"  {cont}    Unity Catalog:")
        _print_uc(direct_grants, cont)

    # ── member-direct section ────────────────────────────────────────────────
    if has_member:
        idx = len(sorted_parents) + (1 if has_direct else 0)
        conn, cont = _branch(idx)
        print(f"\n  {conn} Member direct  [personal grants — not via group]")

        redun_by_principal = {r.principal: r.redundancy_level.value for r in redundancy}
        counts: dict[str, int] = {}
        for g in member_grants:
            counts[g[5]] = counts.get(g[5], 0) + 1

        for name in sorted(counts):
            n     = counts[name]
            level = redun_by_principal.get(name, "")
            warn  = f"  [⚠ {level} redundancy]" if level and level != "None" else ""
            print(f"  {cont}    {name:<52} {n} grant{'s' if n != 1 else ''}{warn}")

    # ── workspace objects ─────────────────────────────────────────────────────
    if has_objects:
        idx = len(sorted_parents) + (1 if has_direct else 0) + (1 if has_member else 0)
        conn, _ = _branch(idx)
        print(f"\n  {conn} Workspace objects")
        for g in workspace_object_grants:
            name = g.object_name or g.object_id
            print(
                f"         {g.object_type:<22} {name:<40}"
                f" {g.permission_level:<20} [{g.workspace_name}]"
            )

    # ── redundancy callout ────────────────────────────────────────────────────
    n_full    = sum(1 for r in redundancy if r.redundancy_level.value == "Full")
    n_partial = sum(1 for r in redundancy if r.redundancy_level.value == "Partial")
    if n_full or n_partial:
        print(f"\n  ⚠  Redundant personal grants: {n_full} full, {n_partial} partial"
              "  (run --revoke-script for REVOKE SQL)")

    # ── summary footer ────────────────────────────────────────────────────────
    n_ws = len({g[4] for g in all_grants if g[4]})
    parts = [
        f"{n_members} member{'s' if n_members != 1 else ''}",
        f"{n_ws} workspace{'s' if n_ws != 1 else ''}",
        f"{len(direct_grants)} direct grant{'s' if len(direct_grants) != 1 else ''}",
        f"{sum(len(v) for v in upstream_by_parent.values())} upstream",
    ]
    if has_member:
        parts.append(f"{len(member_grants)} member-direct")
    if has_objects:
        n_obj = len(workspace_object_grants)
        parts.append(f"{n_obj} workspace object{'s' if n_obj != 1 else ''}")

    print(f"\n{'─' * 64}")
    print(f"  {' · '.join(parts)}")
    print(f"{'=' * 64}")
