# Visualizing access: who can reach what, and how

Your manager asks: "Can you show me exactly what Thomas has access to — all workspaces, all catalogs, which groups connect him to each one?"

Or your auditor asks: "Has data-engineers' access changed since last quarter? Show me the diff."

The text output answers both questions. The HTML access map and ASCII tree make the answers _explainable_.

---

## Principal audit — `--output html` and `--tree`

### `--output html`

```bash
databricks-access-audit --principal "thomas@company.com" --output html > thomas.html
```

Open `thomas.html` in a browser. You get:

- **Access graph** — Mermaid flowchart: principal → groups (solid edges = direct, dashed = transitive) → workspaces and UC securables. Defaults to catalog-level view; a **Schema view** button renders a deeper diagram on demand (requires `--scan-schemas`). In schema view, catalogs connect to schemas via dashed hierarchy edges; groups with `ALL_PRIVILEGES` on a catalog don't repeat redundant schema-level arrows — the hierarchy edge implies them. Groups that grant only specific schemas still show their edges directly. Tables are not shown in the chart — they appear in the grants table below it.
- **Summary stats** — direct groups, transitive groups, workspaces, UC grants at a glance.
- **Data tables** — group memberships, workspace access, UC permissions, workspace objects (if `--scan-workspace-objects` is set).

The page is fully self-contained — one `.html` file, no server, Mermaid renders client-side.

```bash
# Include workspace object ACLs (jobs, clusters, dashboards, pipelines, …)
databricks-access-audit --principal "thomas@company.com" \
  --scan-workspace-objects \
  --output html > thomas_full.html
```

### `--tree`

For a compact terminal view organised the same way — "what does thomas get *via* data-engineers?" — use `--tree`:

```bash
databricks-access-audit --principal "thomas@company.com" --tree
```

```
==============================================================
  Thomas Müller  (USER · external)
==============================================================

  ├─ via  data-engineers  [direct · Entra/IdP-managed]
  │     Workspaces:
  │       prod-workspace                           USER
  │     Unity Catalog:
  │       CATALOG    main                          USE_CATALOG, SELECT  [prod-workspace]

  └─ via  ml-consumers  [direct · Entra/IdP-managed]
        Workspaces:
          analytics-workspace                      USER

──────────────────────────────────────────────────────────────
  2 direct groups · 3 transitive · 2 workspaces · 3 UC grants
==============================================================
```

Useful in terminals, CI logs, or for pasting into a Slack message or incident ticket.

---

## Group audit — `--output html` and `--tree`

The same two output modes work for `--group`, but organised around the group's access footprint rather than an individual's.

### `--output html`

```bash
databricks-access-audit --group "data-engineers" --output html > data-engineers.html
```

- **Access graph** — group → parent groups that grant it access (dashed) → workspaces and UC catalogs. Defaults to catalog-level view; a **Schema view** button is unlocked when `--scan-schemas` is passed. In schema view, schemas connect to their parent catalog via dashed hierarchy edges; groups with `ALL_PRIVILEGES` on a catalog don't draw redundant schema-level edges — the hierarchy edge implies them.
- **Redundancy highlighted** — amber warning stat + dedicated table when members hold personal grants the group already covers. Shown before the full grant list so it's hard to miss.
- **Members table** — all users and SPs with direct/transitive and IdP/Databricks tags.
- **UC grants table** — catalog, schema, and table grants for the group itself, tagged `Direct` or `Upstream`. Member personal grants are not shown here — they appear exclusively in the redundancy section.

### `--tree`

```bash
databricks-access-audit --group "data-engineers" --tree
```

```
════════════════════════════════════════════════════════════════
  data-engineers  (Databricks-managed · 12 members)
════════════════════════════════════════════════════════════════

  ├─ via  all-data-team  [parent group]
  │     Unity Catalog:
  │       CATALOG    main                          USE_CATALOG, SELECT  [prod-workspace]

  ├─ Direct  [group holds these grants]
  │     Unity Catalog:
  │       CATALOG    raw                           USE_CATALOG          [analytics-workspace]

  └─ Member direct  [personal grants — not via group]
        alice@company.com                            2 grants  [⚠ Full redundancy]

  ⚠  Redundant personal grants: 1 full, 0 partial  (run --revoke-script for REVOKE SQL)

────────────────────────────────────────────────────────────────
  12 members · 2 workspaces · 3 direct grants · 1 upstream · 2 member-direct
════════════════════════════════════════════════════════════════
```

The structure answers: what does the group hold directly, what does it inherit from parent groups, and who has personal grants that shadow the group's access?

---

## Compliance diff — `--baseline --output html`

Databricks has no built-in permission changelog. The diff HTML creates a shareable one.

```bash
# Save a baseline at the start of the quarter
databricks-access-audit --group "data-engineers" --save-snapshot snapshots/Q1.json

# At the end of the quarter, generate a diff page
databricks-access-audit --group "data-engineers" --baseline snapshots/Q1.json \
  --output html > q1-q2-diff.html
```

The diff page shows:

- **Timeline header** — baseline timestamp → current timestamp, clearly marked.
- **Summary cards** — +N grants added, −N grants removed, +N members added, −N members removed in green/red.
- **Color-coded tables** — green rows for additions, red rows for removals. One table for grant changes, one for membership changes.
- **No-changes state** — renders a clean "✅ No changes detected" page if access matches the baseline exactly. Suitable for committing to a repo as compliance evidence.

Works for both group and principal audits.

```bash
# Principal diff
databricks-access-audit --principal "alice@company.com" \
  --baseline snapshots/alice-Q1.json \
  --output html > alice-q1-q2-diff.html
```

---

## Resource audit — `--resource --output html`

The identity-first views (`--principal`, `--group`) show what an identity can reach. The resource view inverts that: start from a catalog, schema, table, or workspace and see every identity that can access it.

```bash
databricks-access-audit --resource "main" --output html > main_access.html
```

The HTML output uses a teal colour scheme to visually distinguish it from principal and group reports. It includes:

- **Stat cards** — total direct grants, via-group grants, unique individuals
- **Mermaid flowchart** — resource at the left, direct principals connected with solid arrows, group nodes with dashed arrows to their members. Groups = orange, users = teal, service principals = purple.
- **Direct grants table** — every principal with an explicit grant on the resource, with privilege list and IdP/Databricks tag
- **Via-group grants table** — individuals who inherit access through a group, with the group name shown

```bash
# Group-level view only — faster, cleaner for an overview
databricks-access-audit --resource "main.analytics" \
  --no-expand-groups \
  --output html > analytics_access.html
```

---

## When to use each

| Format | Mode | Best for |
|---|---|---|
| `--output text` | all | Quick checks in the terminal |
| `--tree` | `--principal`, `--group` | Structured terminal view grouped by access path |
| `--output html` | `--principal`, `--group` | Sharing with managers, access reviews, onboarding sign-offs |
| `--output html` | `--resource` | "Who can access this catalog?" — shareable diagram for a manager or auditor |
| `--output html` | `--baseline` | Quarterly compliance diffs, audit evidence |
| `--output csv` | all | Bulk analysis in spreadsheets or BI tools |
| `--output json` | all | Scripting and automation pipelines |

---

## Combining with other flags

```bash
# Principal: deep scan with workspace objects and escalation risks
databricks-access-audit --principal "thomas@company.com" \
  --scan-workspace-objects \
  --escalation-check \
  --output html > thomas_deep.html

# Group: full depth — catalog → schema → table
databricks-access-audit --group "data-engineers" \
  --scan-schemas --scan-tables \
  --output html > data-engineers-deep.html

# Group tree with workspace objects
databricks-access-audit --group "data-engineers" \
  --scan-workspace-objects \
  --tree
```

Escalation findings appear in both `--output html` and `--tree` output when `--escalation-check` is set (principal audit).  Redundancy findings appear in both group audit modes automatically.
