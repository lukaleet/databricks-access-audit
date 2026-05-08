"""Self-contained HTML renderer for audit snapshot diffs."""
from __future__ import annotations

import html as _html
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from databricks_access_audit.models import AuditDiff


def _e(text: object) -> str:
    return _html.escape(str(text))


_STYLE = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f0f2f5; color: #1a1a2e; }
    .wrapper { max-width: 1100px; margin: 0 auto; padding: 32px 20px; }

    header { background: linear-gradient(135deg, #263238, #37474f);
             color: #fff; border-radius: 12px; padding: 26px 30px; margin-bottom: 22px; }
    header h1 { font-size: 20px; font-weight: 700; margin-bottom: 8px; }
    .meta { font-size: 13px; opacity: .8; line-height: 1.8; }
    .timeline { display:flex; align-items:center; gap:10px; margin-top:12px; font-size:13px; }
    .ts-box { background:rgba(255,255,255,.12); border-radius:6px; padding:6px 12px; }
    .ts-arrow { opacity:.5; font-size:18px; }

    .no-changes { background:#fff; border-radius:12px; padding:40px 24px; text-align:center;
                  box-shadow:0 1px 4px rgba(0,0,0,.07); color:#555; }
    .no-changes .icon { font-size:40px; margin-bottom:12px; }
    .no-changes h2 { font-size:17px; font-weight:600; color:#2e7d32; margin-bottom:6px; }
    .no-changes p { font-size:13px; color:#888; }

    .summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
               gap:12px; margin-bottom:22px; }
    .s-card { border-radius:10px; padding:16px 14px; text-align:center; }
    .s-add  { background:#e8f5e9; }
    .s-rem  { background:#ffebee; }
    .s-neu  { background:#f3f4f6; }
    .s-card .n { font-size:28px; font-weight:800; line-height:1; }
    .s-add  .n { color:#2e7d32; }
    .s-rem  .n { color:#b71c1c; }
    .s-neu  .n { color:#555; }
    .s-card .l { font-size:11px; margin-top:5px; text-transform:uppercase;
                 letter-spacing:.04em; color:#666; }

    section { background:#fff; border-radius:12px; padding:22px 24px;
              margin-bottom:18px; box-shadow:0 1px 4px rgba(0,0,0,.07); }
    section h2 { font-size:15px; font-weight:600; color:#37474f;
                 border-bottom:2px solid #eceff1; padding-bottom:10px; margin-bottom:16px; }

    table { width:100%; border-collapse:collapse; font-size:13px; }
    th { background:#eceff1; color:#37474f; font-weight:600;
         padding:9px 13px; text-align:left; white-space:nowrap; }
    td { padding:8px 13px; border-bottom:1px solid #f5f5f5; vertical-align:top; }
    tr:last-child td { border-bottom:none; }
    tr.added   td { background:#f1fdf4; }
    tr.removed td { background:#fff5f5; }
    tr.added:hover   td { background:#e4f8ea; }
    tr.removed:hover td { background:#ffebeb; }

    .pill { display:inline-block; border-radius:20px; padding:1px 8px; font-size:11px;
            font-weight:700; margin-right:4px; white-space:nowrap; }
    .pill-add { background:#2e7d32; color:#fff; }
    .pill-rem { background:#b71c1c; color:#fff; }

    .tag { display:inline-block; border-radius:4px; padding:1px 7px; font-size:11px;
           font-weight:600; margin:1px 2px; white-space:nowrap; }
    .t-priv { background:#fff8e1; color:#e65100; font-family:monospace; }
    .t-type { background:#e8eaf6; color:#3949ab; }
    .t-user { background:#e3f2fd; color:#1565c0; }
    .t-sp   { background:#ede7f6; color:#4527a0; }
    .t-grp  { background:#e8f5e9; color:#2e7d32; }

    .empty { color:#aaa; font-style:italic; }
    footer { text-align:center; font-size:12px; color:#aaa; margin-top:24px; padding-bottom:16px; }
    a { color:#37474f; }
"""


def render_diff_html(diff: "AuditDiff") -> str:
    """Return a complete self-contained HTML diff page."""
    ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    mode_label = "Group" if diff.mode == "group" else "Principal"
    member_label = "Members" if diff.mode == "group" else "Group memberships"

    n_ga = len(diff.grants_added)
    n_gr = len(diff.grants_removed)
    n_ma = len(diff.members_added)
    n_mr = len(diff.members_removed)

    # ── no-changes state ──────────────────────────────────────────────────────
    if not diff.has_changes:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>No changes — {_e(diff.target)}</title>
  <style>{_STYLE}</style>
</head>
<body>
<div class="wrapper">
  <header>
    <h1>Access diff — {_e(diff.target)}</h1>
    <div class="meta">{_e(mode_label)} · Generated {ts_now}</div>
    <div class="timeline">
      <div class="ts-box">{_e(diff.baseline_timestamp)}</div>
      <span class="ts-arrow">→</span>
      <div class="ts-box">{_e(diff.current_timestamp)}</div>
    </div>
  </header>
  <div class="no-changes">
    <div class="icon">✅</div>
    <h2>No changes detected</h2>
    <p>Access configuration matches the baseline snapshot exactly.</p>
  </div>
  <footer>Generated by <a href="https://github.com/lukaleet/databricks-access-audit">databricks-access-audit</a></footer>
</div>
</body>
</html>"""

    # ── summary cards ─────────────────────────────────────────────────────────
    def s_card(n: int, label: str, cls: str) -> str:
        return (f'<div class="s-card {cls}">'
                f'<div class="n">{n}</div><div class="l">{_e(label)}</div></div>')

    summary_html = (
        s_card(n_ga, "grants added",    "s-add") +
        s_card(n_gr, "grants removed",  "s-rem") +
        s_card(n_ma, f"{member_label.lower()} added",   "s-add") +
        s_card(n_mr, f"{member_label.lower()} removed", "s-rem")
    )

    # ── grant changes table ───────────────────────────────────────────────────
    def _grant_rows() -> str:
        rows = []
        for g in diff.grants_added:
            privs = " ".join(f'<span class="tag t-priv">{_e(p)}</span>'
                             for p in g.get("privileges", []))
            stype = g.get("securable_type", "")
            rows.append(
                f'<tr class="added">'
                f'<td><span class="pill pill-add">+</span></td>'
                f'<td><span class="tag t-type">{_e(stype)}</span></td>'
                f'<td>{_e(g.get("securable_name", ""))}</td>'
                f'<td>{_e(g.get("principal", g.get("via_group", "")))}</td>'
                f'<td>{privs}</td>'
                f'<td>{_e(g.get("workspace_name", ""))}</td></tr>'
            )
        for g in diff.grants_removed:
            privs = " ".join(f'<span class="tag t-priv">{_e(p)}</span>'
                             for p in g.get("privileges", []))
            stype = g.get("securable_type", "")
            rows.append(
                f'<tr class="removed">'
                f'<td><span class="pill pill-rem">−</span></td>'
                f'<td><span class="tag t-type">{_e(stype)}</span></td>'
                f'<td>{_e(g.get("securable_name", ""))}</td>'
                f'<td>{_e(g.get("principal", g.get("via_group", "")))}</td>'
                f'<td>{privs}</td>'
                f'<td>{_e(g.get("workspace_name", ""))}</td></tr>'
            )
        if not rows:
            return '<tr><td colspan="6" class="empty">No grant changes.</td></tr>'
        return "\n".join(rows)

    # ── member changes table ──────────────────────────────────────────────────
    def _member_rows() -> str:
        rows = []
        for m in diff.members_added:
            name = m.get("display_name", m.get("group_name", ""))
            mtype = m.get("type", "GROUP").upper()
            t_cls = {"USER": "t-user", "SERVICE_PRINCIPAL": "t-sp"}.get(mtype, "t-grp")
            rows.append(
                f'<tr class="added">'
                f'<td><span class="pill pill-add">+</span></td>'
                f'<td><strong>{_e(name)}</strong></td>'
                f'<td><span class="tag {t_cls}">{_e(mtype)}</span></td></tr>'
            )
        for m in diff.members_removed:
            name = m.get("display_name", m.get("group_name", ""))
            mtype = m.get("type", "GROUP").upper()
            t_cls = {"USER": "t-user", "SERVICE_PRINCIPAL": "t-sp"}.get(mtype, "t-grp")
            rows.append(
                f'<tr class="removed">'
                f'<td><span class="pill pill-rem">−</span></td>'
                f'<td><strong>{_e(name)}</strong></td>'
                f'<td><span class="tag {t_cls}">{_e(mtype)}</span></td></tr>'
            )
        if not rows:
            return '<tr><td colspan="3" class="empty">No membership changes.</td></tr>'
        return "\n".join(rows)

    # ── compose ───────────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access diff — {_e(diff.target)}</title>
  <style>{_STYLE}</style>
</head>
<body>
<div class="wrapper">

  <header>
    <h1>Access diff — {_e(diff.target)}</h1>
    <div class="meta">{_e(mode_label)} · Generated {ts_now}</div>
    <div class="timeline">
      <div class="ts-box">Baseline: {_e(diff.baseline_timestamp)}</div>
      <span class="ts-arrow">→</span>
      <div class="ts-box">Current: {_e(diff.current_timestamp)}</div>
    </div>
  </header>

  <div class="summary">{summary_html}</div>

  <section>
    <h2>Grant changes</h2>
    <table>
      <tr><th></th><th>Type</th><th>Securable</th><th>Principal</th><th>Privileges</th><th>Workspace</th></tr>
      {_grant_rows()}
    </table>
  </section>

  <section>
    <h2>{_e(member_label)} changes</h2>
    <table>
      <tr><th></th><th>Name</th><th>Type</th></tr>
      {_member_rows()}
    </table>
  </section>

  <footer>Generated by <a href="https://github.com/lukaleet/databricks-access-audit">databricks-access-audit</a></footer>

</div>
</body>
</html>"""
