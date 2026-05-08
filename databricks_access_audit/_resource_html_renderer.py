"""Self-contained HTML + Mermaid renderer for resource audit output."""
from __future__ import annotations

import html as _html
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from databricks_access_audit.models import ResourceAuditResult


# ── helpers ──────────────────────────────────────────────────────────────────

def _e(text: object) -> str:
    """HTML-escape."""
    return _html.escape(str(text))


def _ml(s: str) -> str:
    """Escape text for a Mermaid double-quoted label."""
    return (
        s.replace("\\", "\\\\")
         .replace('"', "#quot;")
         .replace("[", "#lsqb;")
         .replace("]", "#rsqb;")
         .replace("<", "#lt;")
         .replace(">", "#gt;")
    )


def _trunc(s: str, n: int = 30) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


# ── Mermaid diagram ───────────────────────────────────────────────────────────

def _build_mermaid(result: "ResourceAuditResult") -> str:
    """Return Mermaid LR flowchart source for the resource access map."""
    lines: list[str] = ["flowchart LR"]
    seen_nodes: set[str] = set()
    seen_edges: set[tuple] = set()

    def _safe_id(s: str) -> str:
        return "n" + "".join(c if c.isalnum() else "_" for c in s)

    def node(nid: str, label: str, shape_open: str = "[", shape_close: str = "]") -> None:
        if nid not in seen_nodes:
            seen_nodes.add(nid)
            lines.append(f'    {nid}{shape_open}"{_ml(_trunc(label))}"{shape_close}')

    def edge(src: str, dst: str, style: str = "-->") -> None:
        key = (src, dst, style)
        if key not in seen_edges:
            seen_edges.add(key)
            lines.append(f"    {src} {style} {dst}")

    # Resource node (central)
    res_id = "resource"
    resource_label = f"{result.resource_type}: {result.resource_name}"
    lines.append(f'    {res_id}["{_ml(_trunc(resource_label, 40))}"]')
    seen_nodes.add(res_id)
    lines.append(f"    style {res_id} fill:#004D40,color:#fff,stroke:#00695C")

    # Collect direct grants (cap at 10 direct nodes)
    direct_grants = [g for g in result.grants if g.via_group is None]
    direct_grants = direct_grants[:10]

    # Collect via-group grants (cap at 20 member nodes total)
    via_group_grants = [g for g in result.grants if g.via_group is not None]
    member_cap = 20
    member_count = 0

    group_colors = {
        "GROUP": ("#e65100", "#fff3e0"),
        "USER": ("#00695c", "#e8f5e9"),
        "SERVICE_PRINCIPAL": ("#6a1b9a", "#f3e5f5"),
    }

    for g in direct_grants:
        ptype = g.principal_type
        fill, stroke_fill = group_colors.get(ptype, ("#37474f", "#eceff1"))
        pid = _safe_id(g.principal_name)
        label = _trunc(g.principal_name)
        node(pid, label)
        if pid not in [n.split("[")[0].strip() for n in lines if "[" in n]:
            pass  # already added
        lines.append(f"    style {pid} fill:{fill},color:#fff")
        edge(res_id, pid)

    # Group membership expansions
    groups_added: set[str] = set()
    for g in via_group_grants:
        if g.via_group is None:
            continue
        group_name = g.via_group
        gid = _safe_id("grp_" + group_name)
        if gid not in groups_added:
            groups_added.add(gid)
            node(gid, _trunc(group_name))
            lines.append(f"    style {gid} fill:#e65100,color:#fff")
            edge(res_id, gid)

        if member_count >= member_cap:
            continue
        member_count += 1
        pid = _safe_id("mem_" + g.principal_name)
        ptype = g.principal_type
        fill, _ = group_colors.get(ptype, ("#37474f", "#eceff1"))
        node(pid, _trunc(g.principal_name))
        lines.append(f"    style {pid} fill:{fill},color:#fff")
        edge(gid, pid, "-.->")

    return "\n".join(lines)


# ── Full HTML ────────────────────────────────────────────────────────────────

def render_resource_html(result: "ResourceAuditResult") -> str:
    """Render a complete self-contained HTML page for a resource audit result."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    direct_grants = [g for g in result.grants if g.via_group is None]
    via_grants = [g for g in result.grants if g.via_group is not None]
    total_principals = len({g.principal_name for g in result.grants})
    group_count = len({g.principal_name for g in result.grants if g.principal_type == "GROUP"})
    user_count = len({g.principal_name for g in result.grants
                      if g.principal_type == "USER" and g.via_group is None})

    mermaid_src = _build_mermaid(result)

    # Direct grants table rows
    direct_rows = ""
    for g in direct_grants:
        src_badge = (
            '<span class="badge badge-ext">external</span>'
            if g.principal_source.value == "external"
            else '<span class="badge badge-int">internal</span>'
        )
        type_badge = (
            f'<span class="badge badge-{g.principal_type.lower()}">'
            f'{_e(g.principal_type)}</span>'
        )
        direct_rows += (
            f"<tr>"
            f"<td>{_e(g.principal_name)}</td>"
            f"<td>{type_badge}</td>"
            f"<td>{src_badge}</td>"
            f"<td>{_e(', '.join(g.privileges))}</td>"
            f"<td>{_e(g.workspace_name)}</td>"
            f"</tr>\n"
        )

    # Via-group grants table rows
    via_rows = ""
    for g in via_grants:
        src_badge = (
            '<span class="badge badge-ext">external</span>'
            if g.principal_source.value == "external"
            else '<span class="badge badge-int">internal</span>'
        )
        type_badge = (
            f'<span class="badge badge-{g.principal_type.lower()}">'
            f'{_e(g.principal_type)}</span>'
        )
        via_rows += (
            f"<tr>"
            f"<td>{_e(g.principal_name)}</td>"
            f"<td>{type_badge}</td>"
            f"<td>{_e(g.via_group or '')}</td>"
            f"<td>{src_badge}</td>"
            f"<td>{_e(', '.join(g.privileges))}</td>"
            f"<td>{_e(g.workspace_name)}</td>"
            f"</tr>\n"
        )

    via_section = ""
    if via_grants:
        via_section = f"""
        <h2>Via group ({len(via_grants)} inherited grants)</h2>
        <table>
          <thead>
            <tr>
              <th>Principal</th><th>Type</th><th>Via Group</th>
              <th>Source</th><th>Privileges</th><th>Workspace</th>
            </tr>
          </thead>
          <tbody>
            {via_rows}
          </tbody>
        </table>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Resource Audit: {_e(result.resource_name)}</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <style>
    :root {{
      --teal-dark: #004D40;
      --teal-mid: #00695C;
      --teal-light: #E0F2F1;
      --text: #212121;
      --muted: #546e7a;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f5f5; color: var(--text); line-height: 1.5; }}
    header {{
      background: linear-gradient(135deg, var(--teal-dark) 0%, var(--teal-mid) 100%);
      color: #fff; padding: 2rem;
    }}
    header h1 {{ font-size: 1.6rem; font-weight: 700; }}
    header .meta {{ font-size: 0.85rem; opacity: 0.8; margin-top: 0.3rem; }}
    .badge-type {{
      display: inline-block; padding: 0.15rem 0.5rem;
      border-radius: 4px; font-size: 0.75rem; font-weight: 600;
      background: rgba(255,255,255,0.2); color: #fff; margin-left: 0.5rem;
    }}
    .stats {{
      display: flex; gap: 1rem; margin-top: 1.2rem; flex-wrap: wrap;
    }}
    .stat-card {{
      background: rgba(255,255,255,0.15); border-radius: 8px;
      padding: 0.6rem 1rem; min-width: 100px;
    }}
    .stat-card .num {{ font-size: 1.4rem; font-weight: 700; }}
    .stat-card .lbl {{ font-size: 0.75rem; opacity: 0.85; }}
    main {{ max-width: 1200px; margin: 2rem auto; padding: 0 1.5rem; }}
    .diagram-wrap {{
      background: #fff; border-radius: 8px; padding: 1.5rem;
      box-shadow: 0 1px 4px rgba(0,0,0,0.08); margin-bottom: 2rem; overflow-x: auto;
    }}
    h2 {{ font-size: 1.1rem; color: var(--teal-dark); margin: 1.5rem 0 0.8rem; }}
    table {{
      width: 100%; border-collapse: collapse; background: #fff;
      border-radius: 8px; overflow: hidden;
      box-shadow: 0 1px 4px rgba(0,0,0,0.08); margin-bottom: 2rem;
    }}
    th {{ background: var(--teal-dark); color: #fff; padding: 0.6rem 0.8rem;
          text-align: left; font-size: 0.85rem; }}
    td {{ padding: 0.55rem 0.8rem; font-size: 0.9rem; border-bottom: 1px solid #e0e0e0; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: var(--teal-light); }}
    .badge {{
      display: inline-block; padding: 0.1rem 0.45rem;
      border-radius: 4px; font-size: 0.75rem; font-weight: 600;
    }}
    .badge-ext {{ background: #e3f2fd; color: #1565c0; }}
    .badge-int {{ background: #f3e5f5; color: #6a1b9a; }}
    .badge-group {{ background: #fff3e0; color: #e65100; }}
    .badge-user {{ background: #e8f5e9; color: #2e7d32; }}
    .badge-service_principal {{ background: #ede7f6; color: #4527a0; }}
    footer {{ text-align: center; color: var(--muted); font-size: 0.8rem;
              padding: 2rem 1rem; }}
  </style>
</head>
<body>
<header>
  <h1>{_e(result.resource_name)}
    <span class="badge-type">{_e(result.resource_type)}</span>
  </h1>
  <div class="meta">Resource audit &middot; {_e(ts)}</div>
  <div class="stats">
    <div class="stat-card">
      <div class="num">{len(direct_grants)}</div>
      <div class="lbl">Direct grants</div>
    </div>
    <div class="stat-card">
      <div class="num">{len(via_grants)}</div>
      <div class="lbl">Via group</div>
    </div>
    <div class="stat-card">
      <div class="num">{total_principals}</div>
      <div class="lbl">Unique principals</div>
    </div>
    <div class="stat-card">
      <div class="num">{group_count}</div>
      <div class="lbl">Groups</div>
    </div>
    <div class="stat-card">
      <div class="num">{user_count}</div>
      <div class="lbl">Direct users</div>
    </div>
  </div>
</header>
<main>
  <div class="diagram-wrap">
    <div class="mermaid">
{mermaid_src}
    </div>
  </div>

  <h2>Direct grants ({len(direct_grants)})</h2>
  <table>
    <thead>
      <tr>
        <th>Principal</th><th>Type</th><th>Source</th><th>Privileges</th><th>Workspace</th>
      </tr>
    </thead>
    <tbody>
      {direct_rows if direct_rows else
       '<tr><td colspan="5" style="color:#888">No direct grants</td></tr>'}
    </tbody>
  </table>
{via_section}
</main>
<footer>Generated by databricks-access-audit &middot; {_e(ts)}</footer>
<script>
  mermaid.initialize({{ startOnLoad: true, theme: "default" }});
</script>
</body>
</html>"""
