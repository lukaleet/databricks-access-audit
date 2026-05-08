# Quick reference

The fastest path from "I have a question" to "here's the command."

---

## Pick your mode

| Your question | Mode | Command |
|---|---|---|
| What can alice access — workspaces, catalogs, objects? | Principal audit | `--principal "alice@company.com"` |
| What does data-engineers access? Who in it has personal grants? | Group audit | `--group "data-engineers"` |
| Who can access the main catalog? | Resource audit | `--resource "main"` |
| Who has a workspace role on prod-workspace? | Resource audit | `--resource "prod-workspace" --resource-type workspace` |
| Does thomas have the same groups as sarah? What's different? | Compare | `--compare "thomas@company.com" "sarah@company.com"` |
| Onboard thomas — give him exactly what sarah has | Clone | `--clone-from "sarah@company.com" --to "thomas@company.com"` |

---

## Pick your output format

| You want to... | Add this | Notes |
|---|---|---|
| Read it in the terminal | *(default)* | Human-readable text |
| See it as a visual diagram | `--output html` | Self-contained HTML + Mermaid graph. `--principal` and `--group` only |
| See it as a compact tree in the terminal | `--tree` | Grouped by access path. `--principal` and `--group` only |
| Export to a spreadsheet or BI tool | `--output csv` | One row per grant, pipe to a file |
| Process it in a script | `--output json` | Machine-readable, all fields |
| Generate a compliance diff page | `--baseline PATH --output html` | Color-coded additions and removals |

---

## Pick your scan depth

Start shallow, go deeper when you need to.

| You want... | Add this | Cost |
|---|---|---|
| Catalog-level UC grants | *(default)* | Baseline — always included |
| Schema-level grants too | `--scan-schemas` | +1 API call per accessible catalog |
| Table/view grants too | `--scan-schemas --scan-tables` | +1 API call per schema |
| Jobs, clusters, dashboards, pipelines, warehouses… | `--scan-workspace-objects` | +1 API call per object type per workspace |
| Specific object types only | `--scan-workspace-objects --workspace-object-types jobs,clusters` | Faster than full scan |

---

## Add analysis layers

These stack on top of any audit run.

| You want to... | Add this | Works with |
|---|---|---|
| Flag ALL_PRIVILEGES and MANAGE grants | `--escalation-check` | `--principal` |
| Find grants with no recent activity | `--stale-days 90 --sql-warehouse-id ID` | `--group` |
| Generate REVOKE SQL for redundant personal grants | `--revoke-script` | `--group` |
| Check for workspace-local groups not in account SCIM | `--check-local-groups` | `--group` |

---

## Compliance and drift tracking

| You want to... | Command |
|---|---|
| Save a snapshot for later comparison | `--save-snapshot snapshots/Q1.json` |
| Diff against a previous snapshot (text) | `--baseline snapshots/Q1.json` |
| Diff as a shareable HTML page | `--baseline snapshots/Q1.json --output html > diff.html` |
| Diff as CSV for a spreadsheet | `--baseline snapshots/Q1.json --output csv` |

---

## Provisioning workflows

| You want to... | Command |
|---|---|
| See what groups alice has that bob doesn't | `--compare "alice@company.com" "bob@company.com"` |
| See the full provisioning plan for bob | `--clone-from "alice@company.com" --to "bob@company.com"` |
| Apply Databricks-managed group changes immediately | add `--apply` |
| Check whether unverified groups have UC grants | add `--scan-uc` |

---

## Sharing results

| Audience | Format | Command snippet |
|---|---|---|
| Manager or access reviewer | HTML diagram + tables | `--output html > report.html` |
| Auditor (quarterly access review) | HTML diff page | `--baseline Q1.json --output html > diff.html` |
| Security team (incident) | JSON for automation | `--output json \| jq ...` |
| Spreadsheet / BI tool | CSV | `--output csv > grants.csv` |
| Slack message or incident ticket | Terminal tree | `--tree` |
| CI/CD pipeline | JSON or CSV to artifact | `--output json > audit.json` |

---

## Common full examples

```bash
# Resource audit — who can access main catalog?
databricks-access-audit --resource "main"

# Resource audit — group-level view only, export to CSV
databricks-access-audit --resource "main.analytics" \
  --no-expand-groups \
  --output csv > analytics_access.csv

# Resource audit — visual HTML report
databricks-access-audit --resource "main" --output html > main_access.html

# Offboarding checklist — everything alice can reach
databricks-access-audit --principal "alice@company.com" \
  --scan-workspace-objects \
  --escalation-check \
  --output html > alice_offboarding.html

# Group access review — full depth, visual output
databricks-access-audit --group "data-engineers" \
  --scan-schemas \
  --scan-workspace-objects \
  --output html > data-engineers-review.html

# Find and clean up redundant personal grants
databricks-access-audit --group "data-engineers" --revoke-script

# Quarterly compliance diff
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/Q1.json \
  --output html > q1-q2-diff.html

# Onboard thomas to match sarah (dry run first, then apply)
databricks-access-audit --clone-from "sarah@company.com" --to "thomas@company.com"
databricks-access-audit --clone-from "sarah@company.com" --to "thomas@company.com" --apply

# Stale access report
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "069ea67f31a3ac71" \
  --output csv > stale_grants.csv
```
