"""Self-contained HTML + Mermaid renderer for group audit output."""
from __future__ import annotations

import html as _html
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from databricks_access_audit.models import (
        CatalogGrant,
        GroupNode,
        RedundancyResult,
        SchemaGrant,
        TableGrant,
        WorkspaceObjectGrant,
    )


def _e(text: object) -> str:
    return _html.escape(str(text))


def _ml(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
            .replace('"', "#quot;")
            .replace("<", "#lt;")
            .replace(">", "#gt;")
    )


# ── Mermaid diagram ───────────────────────────────────────────────────────────

def build_group_mermaid(
    group_name: str,
    group_node: "GroupNode",
    members: dict,
    catalog_grants: List["CatalogGrant"],
    schema_grants: List["SchemaGrant"] = None,
) -> str:
    """Return Mermaid LR flowchart for the group access footprint."""
    from databricks_access_audit.models import GrantSource

    node_lines: list[str] = []
    edge_lines: list[str] = []
    seen_nodes: set[str] = set()
    seen_edges: set[tuple] = set()
    class_map: dict[str, list[str]] = {
        "group": [], "parent": [], "workspace": [], "catalog": [], "schema_n": [],
    }

    def node(nid: str, label: str, cls: str) -> None:
        if nid not in seen_nodes:
            node_lines.append(f'    {nid}["{_ml(label)}"]')
            class_map[cls].append(nid)
            seen_nodes.add(nid)

    def edge(src: str, dst: str, label: str = "", dashed: bool = False) -> None:
        key = (src, dst, label)
        if key not in seen_edges:
            if dashed:
                arrow = f"-. {_ml(label)} .->" if label else "-..->"
            else:
                arrow = f'-- "{_ml(label)}" -->' if label else "-->"
            edge_lines.append(f"    {src} {arrow} {dst}")
            seen_edges.add(key)

    src_tag = "IdP-synced" if group_node.source.value == "external" else "Databricks"
    n_members = len(members["users"]) + len(members["service_principals"])
    node("G", f"👥 {group_name}\n{src_tag} · {n_members} members", "group")

    # Parent groups (visible from UPSTREAM grants) — cap at 5 to stay readable
    parent_names = sorted({
        g.principal for g in catalog_grants
        if g.grant_source == GrantSource.UPSTREAM
    })[:5]
    for i, pname in enumerate(parent_names):
        pid = f"PG{i}"
        node(pid, f"👥 {pname}\nparent group", "parent")
        edge(pid, "G", dashed=True)

    # Workspaces (inferred from DIRECT catalog grants)
    ws_names = sorted({
        g.workspace_name for g in catalog_grants
        if g.grant_source == GrantSource.DIRECT and g.workspace_name
    })
    ws_nid = {ws: f"WS{i}" for i, ws in enumerate(ws_names)}
    for ws_name, wid in ws_nid.items():
        node(wid, f"🏢 {ws_name}", "workspace")
        edge("G", wid)

    # UC catalogs — DIRECT grants only, cap at 8
    direct_cats: Dict[str, list] = {}
    for g in catalog_grants:
        if g.grant_source == GrantSource.DIRECT:
            for priv in g.privileges:
                if priv not in direct_cats.setdefault(g.catalog_name, []):
                    direct_cats[g.catalog_name].append(priv)
    shown_cats = sorted(direct_cats.keys())[:8]
    cat_nid: Dict[str, str] = {}
    for i, cat_name in enumerate(shown_cats):
        cid = f"UC{i}"
        cat_nid[cat_name] = cid
        node(cid, f"📦 CATALOG\n{cat_name}", "catalog")
        privs = direct_cats[cat_name]
        lbl = ", ".join(privs[:2]) + ("…" if len(privs) > 2 else "")
        edge("G", cid, label=lbl)
    if len(direct_cats) > 8:
        node("UCmore", f"📦 +{len(direct_cats) - 8} more catalogs", "catalog")
        edge("G", "UCmore")

    # Catalogs where the group holds ALL_PRIVILEGES directly (used for schema collapse)
    all_priv_cats = {cat for cat, privs in direct_cats.items() if "ALL_PRIVILEGES" in privs}

    # Schema nodes — DIRECT grants only, for shown catalogs, cap at 20
    if schema_grants:
        merged_schemas: Dict[tuple, list] = {}
        for sg in schema_grants:
            if sg.grant_source != GrantSource.DIRECT or sg.catalog_name not in cat_nid:
                continue
            key = (sg.catalog_name, sg.schema_name)
            for p in sg.privileges:
                if p not in merged_schemas.setdefault(key, []):
                    merged_schemas[key].append(p)
        shown_schemas = sorted(merged_schemas.keys())[:20]
        for j, (cat_name, sch_name) in enumerate(shown_schemas):
            privs = merged_schemas[(cat_name, sch_name)]
            scid = f"SC{j}"
            node(scid, f"📂 SCHEMA\n{cat_name}.{sch_name}", "schema_n")
            if cat_name not in all_priv_cats:
                lbl = ", ".join(privs[:2]) + ("…" if len(privs) > 2 else "")
                edge("G", scid, label=lbl)
            edge(cat_nid[cat_name], scid, dashed=True)
        # overflow schemas are noted in the stats section — no dangling node needed

    lines = ["graph LR"]
    lines.extend(node_lines)
    lines.extend(edge_lines)
    lines += [
        "    classDef group     fill:#2e7d32,color:#fff,stroke:#1b5e20,stroke-width:2px",
        "    classDef parent    fill:#81c784,color:#1b5e20,stroke:#388e3c,"
        "stroke-width:1px,stroke-dasharray:5",
        "    classDef workspace fill:#b71c1c,color:#fff,stroke:#7f0000,stroke-width:2px",
        "    classDef catalog   fill:#e65100,color:#fff,stroke:#bf360c,stroke-width:2px",
        "    classDef schema_n  fill:#f57c00,color:#fff,stroke:#e65100,stroke-width:1px",
    ]
    for cls, nids in class_map.items():
        if nids:
            lines.append(f"    class {','.join(nids)} {cls}")
    return "\n".join(lines)


# ── shared CSS / script ───────────────────────────────────────────────────────

_STYLE = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f0f2f5; color: #1a1a2e; }
    .wrapper { max-width: 1400px; margin: 0 auto; padding: 32px 20px; }

    header { background: linear-gradient(135deg, #1b5e20, #2e7d32);
             color: #fff; border-radius: 12px; padding: 26px 30px; margin-bottom: 22px; }
    header h1 { font-size: 20px; font-weight: 700; margin-bottom: 6px; }
    .meta { font-size: 13px; opacity: .85; }
    .badge { display:inline-block; background:rgba(255,255,255,.2); border-radius:4px;
             padding:1px 8px; margin-left:6px; font-size:12px; }

    section { background: #fff; border-radius: 12px; padding: 22px 24px;
              margin-bottom: 18px; box-shadow: 0 1px 4px rgba(0,0,0,.07); }
    section h2 { font-size: 15px; font-weight: 600; color: #2e7d32;
                 border-bottom: 2px solid #e8f5e9; padding-bottom: 10px; margin-bottom: 16px;
                 display: flex; justify-content: space-between; align-items: center; }

    .mermaid { overflow-x: auto; text-align: center; padding: 8px 0; }

    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
             gap: 12px; }
    .stat { background: #e8f5e9; border-radius: 10px; padding: 16px 12px; text-align: center; }
    .stat .n { font-size: 30px; font-weight: 800; color: #2e7d32; line-height: 1; }
    .stat .l { font-size: 11px; color: #666; margin-top: 5px; text-transform: uppercase;
               letter-spacing: .04em; }
    .stat.warn .n { color: #e65100; }
    .stat.warn { background: #fff3e0; }

    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #e8f5e9; color: #2e7d32; font-weight: 600;
         padding: 9px 13px; text-align: left; white-space: nowrap; }
    td { padding: 8px 13px; border-bottom: 1px solid #f5f5f5; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f9fff9; }

    .tag { display:inline-block; border-radius:4px; padding:1px 7px; font-size:11px;
           font-weight:600; margin:1px 2px; white-space:nowrap; }
    .t-direct   { background:#e8f5e9; color:#2e7d32; }
    .t-transit  { background:#f1f8e9; color:#558b2f; }
    .t-upstream { background:#e3f2fd; color:#1565c0; }
    .t-member   { background:#fce4ec; color:#880e4f; }
    .t-ext      { background:#e3f2fd; color:#1565c0; }
    .t-int      { background:#ede7f6; color:#4527a0; }
    .t-priv     { background:#fff8e1; color:#e65100; font-family:monospace; }
    .t-full     { background:#ffebee; color:#b71c1c; font-weight:700; }
    .t-partial  { background:#fff3e0; color:#e65100; }
    .t-cat      { background:#e8f5e9; color:#2e7d32; }
    .t-sch      { background:#e3f2fd; color:#1565c0; }
    .t-tbl      { background:#fff8e1; color:#e65100; }

    .redundancy-banner { background: #fff8e1; border: 1px solid #ffcc02;
                         border-radius: 8px; padding: 12px 16px; margin-bottom: 16px;
                         font-size: 13px; color: #5d4037; }
    .empty { color: #aaa; font-style: italic; }
    footer { text-align:center; font-size:12px; color:#aaa; margin-top:24px; padding-bottom:16px; }
    a { color: #2e7d32; }
    .depth-btn { background:#e8f5e9; border:1px solid #a5d6a7; border-radius:4px;
                 color:#2e7d32; cursor:pointer; font-size:12px; font-weight:600;
                 padding:3px 10px; flex-shrink:0; }
    .depth-btn:hover { background:#c8e6c9; }
    .trunc-note { font-size:12px; color:#aaa; font-style:italic;
                  margin-top:8px; text-align:center; }
"""

_SCRIPT = """
  mermaid.initialize({
    startOnLoad: true,
    theme: 'base',
    themeVariables: { fontSize: '13px' },
    flowchart: { curve: 'basis', useMaxWidth: true }
  });
  var _schRendered = false;
  function toggleDepth() {
    var wc = document.getElementById('wrap-cat');
    var ws = document.getElementById('wrap-sch');
    var btn = document.getElementById('depth-toggle');
    if (wc.style.display !== 'none') {
      wc.style.display = 'none';
      ws.style.display = 'block';
      btn.textContent = 'Catalog view';
      if (!_schRendered) {
        var src = document.getElementById('sch-src').textContent.trim();
        var div = document.createElement('div');
        div.className = 'mermaid';
        div.textContent = src;
        ws.appendChild(div);
        mermaid.run({ nodes: [div] });
        _schRendered = true;
      }
    } else {
      wc.style.display = 'block';
      ws.style.display = 'none';
      btn.textContent = 'Schema view';
    }
  }
"""


# ── HTML assembly ─────────────────────────────────────────────────────────────

def render_group_html(
    group_name: str,
    group_node: "GroupNode",
    members: dict,
    catalog_grants: List["CatalogGrant"],
    schema_grants: List["SchemaGrant"],
    table_grants: List["TableGrant"],
    workspace_object_grants: List["WorkspaceObjectGrant"],
    redundancy: List["RedundancyResult"],
    show_workspace_objects: bool = False,
    revoke_sql: str = "",
) -> str:

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    src_label = "IdP-synced (external)" if group_node.source.value == "external" \
                else "Databricks-managed (internal)"
    n_users = len(members["users"])
    n_sps   = len(members["service_principals"])
    n_cat   = len(catalog_grants)
    n_sch   = len(schema_grants)
    n_tbl   = len(table_grants)
    n_obj   = len(workspace_object_grants) if show_workspace_objects else 0
    n_full  = sum(1 for r in redundancy if r.redundancy_level.value == "Full")
    n_part  = sum(1 for r in redundancy if r.redundancy_level.value == "Partial")
    n_redun = n_full + n_part

    diagram_cat = build_group_mermaid(
        group_name, group_node, members, catalog_grants, schema_grants=None)
    _has_depth  = bool(schema_grants)
    diagram_sch = (
        build_group_mermaid(group_name, group_node, members, catalog_grants, schema_grants)
        if _has_depth else None
    )
    _n_schemas_total = len({sg.schema_name for sg in schema_grants}) if schema_grants else 0
    _schemas_truncated = max(0, _n_schemas_total - 20)

    # ── stats ─────────────────────────────────────────────────────────────────
    def stat(n: int, label: str, warn: bool = False) -> str:
        cls = ' class="stat warn"' if warn else ' class="stat"'
        return f'<div{cls}><div class="n">{n}</div><div class="l">{_e(label)}</div></div>'

    stats_html = (
        stat(n_users,  "users") +
        stat(n_sps,    "service principals") +
        stat(n_cat,    "catalog grants") +
        (stat(n_sch,   "schema grants") if n_sch else "") +
        (stat(n_tbl,   "table grants")  if n_tbl else "") +
        (stat(n_obj,   "workspace objects") if show_workspace_objects and n_obj else "") +
        (stat(n_redun, "redundant grants", warn=True) if n_redun else "")
    )

    # ── redundancy banner ─────────────────────────────────────────────────────
    redun_banner = ""
    if n_redun:
        redun_banner = (
            f'<div class="redundancy-banner">⚠️ <strong>{n_full} full</strong> and '
            f'<strong>{n_part} partial</strong> redundant personal grants detected — '
            f'members hold catalog grants already covered by this group. '
            f'Run <code>--revoke-script</code> to generate REVOKE SQL.</div>'
        )

    # ── members table ─────────────────────────────────────────────────────────
    def _member_rows() -> str:
        rows = []
        for m in sorted(members["users"], key=lambda x: x.display_name.lower()):
            is_direct = group_name in (m.parent_groups or [])
            d_tag = '<span class="tag t-direct">direct</span>' if is_direct else \
                    '<span class="tag t-transit">transitive</span>'
            s_tag = '<span class="tag t-ext">IdP-synced</span>' if m.external_id else \
                    '<span class="tag t-int">Databricks</span>'
            email = f'<br><span style="color:#888;font-size:11px">{_e(m.email)}</span>' \
                    if m.email and m.email != m.display_name else ""
            rows.append(
                f"<tr><td><strong>{_e(m.display_name)}</strong>{email}</td>"
                f"<td>User</td><td>{d_tag}</td><td>{s_tag}</td></tr>"
            )
        for m in sorted(members["service_principals"], key=lambda x: x.display_name.lower()):
            is_direct = group_name in (m.parent_groups or [])
            d_tag = '<span class="tag t-direct">direct</span>' if is_direct else \
                    '<span class="tag t-transit">transitive</span>'
            s_tag = '<span class="tag t-ext">IdP-synced</span>' if m.external_id else \
                    '<span class="tag t-int">Databricks</span>'
            rows.append(
                f"<tr><td><strong>{_e(m.display_name)}</strong></td>"
                f"<td>Service&nbsp;Principal</td><td>{d_tag}</td><td>{s_tag}</td></tr>"
            )
        if not rows:
            return '<tr><td colspan="4" class="empty">No members found.</td></tr>'
        return "\n".join(rows)

    # ── UC grants table (catalog + schema + table combined) ───────────────────
    def _grant_source_tag(gs: str) -> str:
        if gs == "Direct":
            return '<span class="tag t-direct">Direct</span>'
        if gs == "Upstream":
            return '<span class="tag t-upstream">Upstream</span>'
        return '<span class="tag t-member">Member Direct</span>'

    def _grant_rows() -> str:
        rows = []
        all_grants = (
            [(g.catalog_name, "", "", g.workspace_name, g.privileges, g.grant_source, "CATALOG")
             for g in catalog_grants
             if g.grant_source.value != "Member Direct"]
            + [
                (g.catalog_name, g.schema_name, "", g.workspace_name,
                 g.privileges, g.grant_source, "SCHEMA")
                for g in schema_grants
                if g.grant_source.value != "Member Direct"
            ]
            + [
                (g.catalog_name, g.schema_name, g.table_name, g.workspace_name,
                 g.privileges, g.grant_source, "TABLE")
                for g in table_grants
                if g.grant_source.value != "Member Direct"
            ]
        )
        if not all_grants:
            return '<tr><td colspan="5" class="empty">No Unity Catalog grants found.</td></tr>'
        def _sort_key(x):
            return (x[6], x[0], x[1], x[2])

        for cat, sch, tbl, ws, privs, gs, stype in sorted(all_grants, key=_sort_key):
            if stype == "CATALOG":
                name = cat
                t_cls = "t-cat"
            elif stype == "SCHEMA":
                name = f"{cat}.{sch}"
                t_cls = "t-sch"
            else:
                name = f"{cat}.{sch}.{tbl}"
                t_cls = "t-tbl"
            priv_tags = " ".join(f'<span class="tag t-priv">{_e(p)}</span>' for p in privs)
            rows.append(
                f'<tr><td><span class="tag {t_cls}">{stype}</span></td>'
                f"<td>{_e(name)}</td>"
                f"<td>{priv_tags}</td>"
                f"<td>{_grant_source_tag(gs.value if hasattr(gs, 'value') else gs)}</td>"
                f"<td>{_e(ws)}</td></tr>"
            )
        return "\n".join(rows)

    # ── redundancy table ──────────────────────────────────────────────────────
    def _redundancy_rows() -> str:
        interesting = [r for r in redundancy if r.redundancy_level.value in ("Full", "Partial")]
        if not interesting:
            return '<tr><td colspan="4" class="empty">No redundant grants found.</td></tr>'
        rows = []
        for r in sorted(interesting, key=lambda x: (x.redundancy_level.value, x.principal)):
            lvl_tag = '<span class="tag t-full">Full</span>' if r.redundancy_level.value == "Full" \
                      else '<span class="tag t-partial">Partial</span>'
            priv_tags = " ".join(f'<span class="tag t-priv">{_e(p)}</span>'
                                 for p in r.redundant_privileges)
            rows.append(
                f"<tr><td>{_e(r.principal)}</td><td>{_e(r.catalog_name)}</td>"
                f"<td>{lvl_tag}</td><td>{priv_tags}</td></tr>"
            )
        return "\n".join(rows)

    # ── workspace objects table ───────────────────────────────────────────────
    def _obj_rows() -> str:
        if not workspace_object_grants:
            return '<tr><td colspan="5" class="empty">No workspace object grants found.</td></tr>'
        rows = []
        def _obj_key(x):
            return (x.object_type, x.object_name or "")

        for g in sorted(workspace_object_grants, key=_obj_key):
            via = _e(g.inherited_from) if g.inherited_from else "—"
            rows.append(
                f"<tr><td>{_e(g.object_type)}</td>"
                f"<td>{_e(g.object_name or g.object_id)}</td>"
                f"<td>{_e(g.permission_level)}</td>"
                f"<td>{via}</td>"
                f"<td>{_e(g.workspace_name)}</td></tr>"
            )
        return "\n".join(rows)

    # ── compose ───────────────────────────────────────────────────────────────
    obj_section = ""
    if show_workspace_objects:
        obj_section = f"""
  <section>
    <h2>Workspace objects</h2>
    <table>
      <tr><th>Type</th><th>Name</th><th>Permission</th>
          <th>Inherited from</th><th>Workspace</th></tr>
      {_obj_rows()}
    </table>
  </section>"""

    redundancy_section = ""
    if n_redun:
        redundancy_section = f"""
  <section>
    <h2>⚠️ Redundant personal grants</h2>
    {redun_banner}
    <table>
      <tr><th>Member</th><th>Catalog</th><th>Overlap</th><th>Redundant privileges</th></tr>
      {_redundancy_rows()}
    </table>
  </section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Group audit — {_e(group_name)}</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <style>{_STYLE}</style>
</head>
<body>
<div class="wrapper">

  <header>
    <h1>👥 {_e(group_name)}</h1>
    <div class="meta">
      {_e(src_label)}
      <span class="badge">{n_users} user{'' if n_users == 1 else 's'}</span>
      <span class="badge">{n_sps} service principal{'' if n_sps == 1 else 's'}</span>
      <span class="badge">{ts}</span>
    </div>
  </header>

  <section>
    <h2>Overview</h2>
    <div class="stats">{stats_html}</div>
  </section>

  <section>
    <h2>Access graph{"" if not _has_depth else
      ' <button id="depth-toggle" class="depth-btn"'
      ' onclick="toggleDepth()">Schema view</button>'}</h2>
    <div id="wrap-cat">
      <div class="mermaid">{diagram_cat}</div>
    </div>
    {"" if not _has_depth else f'''<script type="text/plain" id="sch-src">
{diagram_sch}
    </script>
    <div id="wrap-sch" style="display:none">
      {"" if not _schemas_truncated else
        f'<p class="trunc-note">{_schemas_truncated} schema(s) not shown'
        f' — see Unity Catalog grants table.</p>'}
    </div>'''}
  </section>
{redundancy_section}
  <section>
    <h2>Members</h2>
    <table>
      <tr><th>Name</th><th>Type</th><th>Membership</th><th>Source</th></tr>
      {_member_rows()}
    </table>
  </section>

  <section>
    <h2>Unity Catalog grants</h2>
    <table>
      <tr><th>Level</th><th>Securable</th><th>Privileges</th>
          <th>Grant source</th><th>Workspace</th></tr>
      {_grant_rows()}
    </table>
  </section>
{obj_section}

  {f'''<section>
    <h2>REVOKE Script</h2>
    <pre style="background:#1e1e1e;color:#d4d4d4;padding:16px;border-radius:6px;
                overflow-x:auto;font-size:13px;line-height:1.6">{_e(revoke_sql.strip())}</pre>
  </section>''' if revoke_sql.strip() else ""}

  <footer>
    Generated by <a href="https://github.com/lukaleet/databricks-access-audit">databricks-access-audit</a>
  </footer>

</div>
<script>{_SCRIPT}</script>
</body>
</html>"""
