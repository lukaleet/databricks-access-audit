"""Self-contained HTML + Mermaid renderer for principal audit output."""
from __future__ import annotations

import html as _html
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from databricks_access_audit.models import PrincipalAuditResult, WorkspaceObjectGrant


# ── helpers ──────────────────────────────────────────────────────────────────

def _e(text: object) -> str:
    """HTML-escape."""
    return _html.escape(str(text))


def _ml(text: str) -> str:
    """Escape text for a Mermaid double-quoted label."""
    return (
        text.replace("\\", "\\\\")
            .replace('"', "#quot;")
            .replace("<", "#lt;")
            .replace(">", "#gt;")
    )


# ── Mermaid diagram ───────────────────────────────────────────────────────────

def build_mermaid(
    result: "PrincipalAuditResult",
    obj_grants: List["WorkspaceObjectGrant"],
) -> str:
    """Return Mermaid LR flowchart source for the principal access map."""
    from databricks_access_audit.models import PrincipalSource

    node_lines: list[str] = []
    edge_lines: list[str] = []
    seen_nodes: set[str] = set()
    class_map: dict[str, list[str]] = {
        "principal": [], "grp_direct": [], "grp_transitive": [],
        "workspace": [], "catalog": [], "schema_n": [], "table_n": [],
        "direct_n": [],
    }

    def node(nid: str, label: str, cls: str) -> None:
        if nid not in seen_nodes:
            node_lines.append(f'    {nid}["{_ml(label)}"]')
            class_map[cls].append(nid)
            seen_nodes.add(nid)

    def edge(src: str, dst: str, label: str = "", dashed: bool = False) -> None:
        lbl = _ml(label)
        if dashed:
            arrow = f"-. {lbl} .->" if lbl else "-..->"
        else:
            arrow = f"-- {lbl} -->" if lbl else "-->"
        edge_lines.append(f"    {src} {arrow} {dst}")

    # Principal
    p_src = "external" if result.principal_source == PrincipalSource.EXTERNAL else "internal"
    node("P", f"👤 {result.principal_name}\n{result.principal_type} · {p_src}", "principal")

    # Per-group buckets
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

    # Workspace nodes (deduplicated)
    all_ws = sorted({r.workspace_name for r in result.workspace_roles})
    ws_nid  = {ws: f"WS{i}" for i, ws in enumerate(all_ws)}

    # UC securable nodes (deduplicated by type+name)
    all_sec = sorted({(p.securable_type, p.securable_name) for p in result.permissions})
    sec_nid  = {k: f"UC{i}" for i, k in enumerate(all_sec)}

    def _sort_key(g: str) -> tuple:
        m = mem_by_name.get(g)
        return (0 if (m and m.is_direct) else 1, g.lower())

    for i, gname in enumerate(sorted(grant_groups, key=_sort_key)):
        gid = f"G{i}"
        m   = mem_by_name.get(gname)
        is_direct = m.is_direct if m else False
        src_tag   = "Entra/IdP" if (m and m.source.value == "external") else "Databricks"
        d_tag     = "direct" if is_direct else "transitive"
        cls       = "grp_direct" if is_direct else "grp_transitive"
        node(gid, f"👥 {gname}\n{d_tag} · {src_tag}", cls)
        edge("P", gid, dashed=not is_direct)

        # → workspaces
        for r in ws_by_group.get(gname, []):
            wid = ws_nid[r.workspace_name]
            node(wid, f"🏢 {r.workspace_name}\n{r.permission_level}", "workspace")
            edge(gid, wid, label=r.permission_level)

        # → UC securables (merge privileges per unique securable)
        merged: dict[tuple, list[str]] = {}
        for p in perm_by_group.get(gname, []):
            key = (p.securable_type, p.securable_name)
            for priv in p.privileges:
                if priv not in merged.setdefault(key, []):
                    merged[key].append(priv)
        for (stype, sname), privs in sorted(merged.items()):
            ucid  = sec_nid[(stype, sname)]
            icon  = {"CATALOG": "📦", "SCHEMA": "📂", "TABLE": "📋"}.get(stype, "📄")
            _uc_cls = {"CATALOG": "catalog", "SCHEMA": "schema_n", "TABLE": "table_n"}
            ucls  = _uc_cls.get(stype, "catalog")
            node(ucid, f"{icon} {stype}\n{sname}", ucls)
            lbl   = ", ".join(privs[:2]) + ("…" if len(privs) > 2 else "")
            edge(gid, ucid, label=lbl)

    # Direct (personal) grants
    direct_ws    = ws_by_group.get("__direct__", [])
    direct_perms = perm_by_group.get("__direct__", [])
    if direct_ws or direct_perms:
        node("DIRECT", "🔑 Personal grants\n(no group)", "direct_n")
        edge("P", "DIRECT")
        for r in direct_ws:
            wid = ws_nid.get(r.workspace_name, "WSD0")
            node(wid, f"🏢 {r.workspace_name}\n{r.permission_level}", "workspace")
            edge("DIRECT", wid, label=r.permission_level)
        merged_d: dict[tuple, list[str]] = {}
        for p in direct_perms:
            key = (p.securable_type, p.securable_name)
            for priv in p.privileges:
                if priv not in merged_d.setdefault(key, []):
                    merged_d[key].append(priv)
        for (stype, sname), privs in sorted(merged_d.items()):
            ucid = sec_nid.get((stype, sname), "UCD0")
            icon = {"CATALOG": "📦", "SCHEMA": "📂", "TABLE": "📋"}.get(stype, "📄")
            _uc_node_cls = {"CATALOG": "catalog", "SCHEMA": "schema_n", "TABLE": "table_n"}
            ucls = _uc_node_cls.get(stype, "catalog")
            node(ucid, f"{icon} {stype}\n{sname}", ucls)
            edge("DIRECT", ucid)

    lines = ["graph LR"]
    lines.extend(node_lines)
    lines.extend(edge_lines)

    # Style
    lines += [
        "    classDef principal    fill:#3949ab,color:#fff,stroke:#1a237e,stroke-width:2px",
        "    classDef grp_direct   fill:#2e7d32,color:#fff,stroke:#1b5e20,stroke-width:2px",
        "    classDef grp_transitive fill:#81c784,color:#1b5e20,stroke:#388e3c,"
        "stroke-width:1px,stroke-dasharray:5",
        "    classDef workspace    fill:#b71c1c,color:#fff,stroke:#7f0000,stroke-width:2px",
        "    classDef catalog      fill:#e65100,color:#fff,stroke:#bf360c,stroke-width:2px",
        "    classDef schema_n     fill:#f57c00,color:#fff,stroke:#e65100,stroke-width:1px",
        "    classDef table_n      fill:#ffd54f,color:#5d4037,stroke:#f57c00,stroke-width:1px",
        "    classDef direct_n     fill:#546e7a,color:#fff,stroke:#263238,stroke-width:2px",
    ]
    for cls, nids in class_map.items():
        if nids:
            lines.append(f"    class {','.join(nids)} {cls}")

    return "\n".join(lines)


# ── HTML assembly ─────────────────────────────────────────────────────────────

_STYLE = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f0f2f5; color: #1a1a2e; }
    .wrapper { max-width: 1400px; margin: 0 auto; padding: 32px 20px; }

    header { background: linear-gradient(135deg, #3949ab, #1565c0);
             color: #fff; border-radius: 12px; padding: 26px 30px; margin-bottom: 22px; }
    header h1 { font-size: 20px; font-weight: 700; margin-bottom: 6px; }
    .meta { font-size: 13px; opacity: .85; }
    .badge { display:inline-block; background:rgba(255,255,255,.2); border-radius:4px;
             padding:1px 8px; margin-left:6px; font-size:12px; }

    section { background: #fff; border-radius: 12px; padding: 22px 24px;
              margin-bottom: 18px; box-shadow: 0 1px 4px rgba(0,0,0,.07); }
    section h2 { font-size: 15px; font-weight: 600; color: #3949ab;
                 border-bottom: 2px solid #e8eaf6; padding-bottom: 10px; margin-bottom: 16px; }

    .mermaid { overflow-x: auto; text-align: center; padding: 8px 0; }

    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
             gap: 12px; }
    .stat { background: #e8eaf6; border-radius: 10px; padding: 16px 12px; text-align: center; }
    .stat .n { font-size: 30px; font-weight: 800; color: #3949ab; line-height: 1; }
    .stat .l { font-size: 11px; color: #666; margin-top: 5px; text-transform: uppercase;
               letter-spacing: .04em; }

    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #e8eaf6; color: #3949ab; font-weight: 600;
         padding: 9px 13px; text-align: left; white-space: nowrap; }
    td { padding: 8px 13px; border-bottom: 1px solid #f5f5f5; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #fafbff; }

    .tag { display:inline-block; border-radius:4px; padding:1px 7px; font-size:11px;
           font-weight:600; margin:1px 2px; white-space:nowrap; }
    .t-direct    { background:#e8f5e9; color:#2e7d32; }
    .t-transit   { background:#f1f8e9; color:#558b2f; }
    .t-ext       { background:#e3f2fd; color:#1565c0; }
    .t-int       { background:#ede7f6; color:#4527a0; }
    .t-priv      { background:#fff8e1; color:#e65100; font-family:monospace; }
    .t-risk      { background:#ffebee; color:#b71c1c; }
    .t-ws        { background:#fce4ec; color:#880e4f; }

    .chain { font-family: monospace; font-size: 11px; color: #888; }
    .empty { color: #aaa; font-style: italic; }

    footer { text-align:center; font-size:12px; color:#aaa; margin-top:24px; padding-bottom:16px; }
    a { color: #3949ab; }
"""

_SCRIPT = """
  mermaid.initialize({
    startOnLoad: true,
    theme: 'base',
    themeVariables: { fontSize: '13px' },
    flowchart: { curve: 'basis', useMaxWidth: true }
  });
"""


def render_html(
    result: "PrincipalAuditResult",
    obj_grants: List["WorkspaceObjectGrant"],
    show_escalations: bool = False,
    show_workspace_objects: bool = False,
) -> str:
    """Return a complete self-contained HTML string for the principal audit."""
    from databricks_access_audit.models import PrincipalSource

    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    p_src = (
        "external (IdP-synced)"
        if result.principal_source == PrincipalSource.EXTERNAL
        else "internal (Databricks-managed)"
    )

    diagram = build_mermaid(result, obj_grants)

    # ── summary stats ─────────────────────────────────────────────────────────
    n_direct  = sum(1 for m in result.groups if m.is_direct)
    n_transit = len(result.groups) - n_direct
    n_ws      = len({r.workspace_name for r in result.workspace_roles})
    n_uc      = len(result.permissions)

    def stat(n: int, label: str) -> str:
        return f'<div class="stat"><div class="n">{n}</div><div class="l">{_e(label)}</div></div>'

    stats_html = (
        stat(n_direct,  "direct groups") +
        stat(n_transit, "transitive groups") +
        stat(n_ws,      "workspaces") +
        stat(n_uc,      "UC grants") +
        (stat(len(obj_grants), "workspace objects")
         if show_workspace_objects and obj_grants else "")
    )

    # ── group memberships table ───────────────────────────────────────────────
    def _group_rows() -> str:
        if not result.groups:
            return '<tr><td colspan="4" class="empty">No group memberships found.</td></tr>'
        rows = []
        for g in result.groups:
            d_tag = (
                '<span class="tag t-direct">direct</span>'
                if g.is_direct else
                '<span class="tag t-transit">transitive</span>'
            )
            s_tag = (
                '<span class="tag t-ext">Entra/IdP</span>'
                if g.source.value == "external" else
                '<span class="tag t-int">Databricks</span>'
            )
            path  = " → ".join(_e(s) for s in g.path)
            rows.append(
                f"<tr><td><strong>{_e(g.group_name)}</strong></td>"
                f"<td>{d_tag}</td><td>{s_tag}</td>"
                f'<td class="chain">{path}</td></tr>'
            )
        return "\n".join(rows)

    # ── workspace roles table ─────────────────────────────────────────────────
    def _ws_rows() -> str:
        if not result.workspace_roles:
            return '<tr><td colspan="4" class="empty">No workspace access found.</td></tr>'
        rows = []
        for r in result.workspace_roles:
            via   = _e(r.via_group) if r.via_group else '<span class="empty">direct</span>'
            path  = " → ".join(_e(s) for s in r.via_path)
            rows.append(
                f'<tr><td><span class="tag t-ws">{_e(r.workspace_name)}</span></td>'
                f"<td><strong>{_e(r.permission_level)}</strong></td>"
                f"<td>{via}</td>"
                f'<td class="chain">{path}</td></tr>'
            )
        return "\n".join(rows)

    # ── UC permissions table ──────────────────────────────────────────────────
    def _uc_rows() -> str:
        if not result.permissions:
            return '<tr><td colspan="5" class="empty">No Unity Catalog permissions found.</td></tr>'
        rows = []
        for p in result.permissions:
            privs = " ".join(f'<span class="tag t-priv">{_e(pr)}</span>' for pr in p.privileges)
            via   = _e(p.via_group) if p.via_group else '<span class="empty">direct</span>'
            rows.append(
                f"<tr><td>{_e(p.securable_type)}</td>"
                f"<td><strong>{_e(p.securable_name)}</strong></td>"
                f"<td>{privs}</td><td>{via}</td>"
                f"<td>{_e(p.workspace_name)}</td></tr>"
            )
        return "\n".join(rows)

    # ── workspace objects section ─────────────────────────────────────────────
    obj_section = ""
    if show_workspace_objects and obj_grants:
        rows = []
        for g in obj_grants:
            name = _e(g.object_name or g.object_id)
            via  = _e(g.inherited_from) if g.inherited_from else '<span class="empty">direct</span>'
            rows.append(
                f"<tr><td>{_e(g.object_type)}</td><td><strong>{name}</strong></td>"
                f"<td>{_e(g.permission_level)}</td><td>{via}</td>"
                f"<td>{_e(g.workspace_name)}</td></tr>"
            )
        obj_section = f"""
  <section>
    <h2>🗂 Workspace object permissions</h2>
    <table>
      <tr><th>Type</th><th>Object</th><th>Permission</th><th>Via</th><th>Workspace</th></tr>
      {"".join(rows)}
    </table>
  </section>"""

    # ── escalation findings section ───────────────────────────────────────────
    esc_section = ""
    if show_escalations and result.escalation_findings:
        rows = []
        for f in result.escalation_findings:
            kind = "transitive" if f.is_transitive else "direct"
            rows.append(
                f'<tr><td><span class="tag t-risk">{_e(f.privilege)}</span></td>'
                f"<td>{_e(f.securable_type)}</td><td>{_e(f.securable_name)}</td>"
                f"<td>{_e(f.via_group)}</td><td>{kind}</td>"
                f"<td>{_e(f.workspace_name)}</td></tr>"
            )
        esc_section = f"""
  <section>
    <h2>⚠️ Escalation risks</h2>
    <table>
      <tr><th>Privilege</th><th>Type</th><th>Securable</th><th>Via group</th>
          <th>Membership</th><th>Workspace</th></tr>
      {"".join(rows)}
    </table>
  </section>"""

    # ── UC-only / unused groups ───────────────────────────────────────────────
    extra_groups_html = ""
    if result.uc_only_groups or result.dead_end_groups:
        parts = []
        if result.uc_only_groups:
            items = ", ".join(f"<strong>{_e(g)}</strong>" for g in result.uc_only_groups)
            parts.append(
                "<p><strong>UC-only groups</strong> "
                f"(no workspace assignment — access via UC grants only):<br>{items}</p>"
            )
        if result.dead_end_groups:
            items = ", ".join(f"<strong>{_e(g)}</strong>" for g in result.dead_end_groups)
            parts.append(
                "<p style='margin-top:10px'><strong>Unused groups</strong>"
                f" (no workspace or UC grants):<br>{items}</p>"
            )
        extra_groups_html = f"""
  <section>
    <h2>Group notes</h2>
    {"".join(parts)}
  </section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access map — {_e(result.principal_name)}</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <style>{_STYLE}</style>
</head>
<body>
<div class="wrapper">

  <header>
    <h1>🔍 Access map — {_e(result.principal_name)}</h1>
    <div class="meta">
      {_e(result.principal_type)}
      <span class="badge">{_e(p_src)}</span>
      &nbsp;·&nbsp; Generated {_e(ts)}
    </div>
  </header>

  <section>
    <h2>Access graph</h2>
    <div class="mermaid">
{diagram}
    </div>
  </section>

  <section>
    <h2>Summary</h2>
    <div class="stats">{stats_html}</div>
  </section>

  <section>
    <h2>Group memberships</h2>
    <table>
      <tr><th>Group</th><th>Membership</th><th>Source</th><th>Path</th></tr>
      {_group_rows()}
    </table>
  </section>

  <section>
    <h2>Workspace access</h2>
    <table>
      <tr><th>Workspace</th><th>Permission</th><th>Via group</th><th>Path</th></tr>
      {_ws_rows()}
    </table>
  </section>

  <section>
    <h2>Unity Catalog permissions</h2>
    <table>
      <tr><th>Type</th><th>Securable</th><th>Privileges</th>
          <th>Via group</th><th>Workspace</th></tr>
      {_uc_rows()}
    </table>
  </section>

{obj_section}
{esc_section}
{extra_groups_html}

  <footer>
    Generated by <a href="https://github.com/lukaleet/databricks-access-audit">databricks-access-audit</a>
  </footer>

</div>
<script>{_SCRIPT}</script>
</body>
</html>"""
