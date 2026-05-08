# Resource-Centric Access Audit

## When to use it

The `--resource` mode answers: **"Given this resource, who has access to it?"**

It is the inverse of `--principal` and `--group`. Those modes start from an identity and discover what it can reach. `--resource` starts from a resource and discovers every identity that can reach it.

| Situation | Why `--resource` | vs. `--principal` |
|---|---|---|
| Quarterly access review on `main.pii` | You need a list of every person with access — you don't know who that is yet | You'd have to audit every user individually |
| You inherited a catalog and want to know who can read it | One command, full member list — no guessing which groups have grants | You'd have to know all the identities upfront |
| Offboarding: verify alice is fully removed from `main` | Run `--resource "main"` and confirm alice doesn't appear | `--principal alice` could miss indirect grants via new groups |
| Compliance: prove no unexpected principals have access to `main.pii` | The output is the attestation — pipe to CSV and sign off | Would need to audit every principal and manually correlate |

Use `--no-expand-groups` for a fast overview of the access shape (groups only). Use the default (with expansion) when you need to see the actual individuals.

---

## Who has access to this catalog?

```bash
databricks-access-audit --resource "main"
```

Example output:

```
============================================================
  Resource audit: main (CATALOG)
============================================================

  Direct grants (3):
    GROUP                data-engineers          [external]  USE_CATALOG, SELECT
    GROUP                all-data-team           [external]  ALL_PRIVILEGES
    USER                 alice@company.com                   USE_CATALOG, SELECT

  Via group (12 individuals):
    data-engineers (4 members):
      USER    alice@company.com                        USE_CATALOG, SELECT
      USER    bob@company.com                          USE_CATALOG, SELECT
      SERVICE_PRINCIPAL  ETL-Bot                      USE_CATALOG, SELECT
    all-data-team (8 members):
      USER    carol@company.com                        ALL_PRIVILEGES
      ...
============================================================
```

The output shows:
1. **Direct grants** — principals with an explicit UC grant on `main`
2. **Via group** — individuals who inherit access through a group

---

## Who has access to this schema?

```bash
databricks-access-audit --resource "main.analytics"
```

The resource type is auto-detected from the dot-count in the name. One dot = schema.

---

## Who has workspace roles on prod-workspace?

```bash
# By workspace URL — always auto-detected
databricks-access-audit --resource "https://adb-1234.azuredatabricks.net"

# By name containing "databricks" — auto-detected
databricks-access-audit --resource "prod-databricks-ws"

# By any other name — use --resource-type to override auto-detection
databricks-access-audit --resource "prod-workspace" --resource-type workspace
```

!!! warning "Auto-detection and workspace names"
    The tool auto-detects a workspace when the name contains `databricks` or starts with `https://`. A name like `prod-workspace` has no dots and no "databricks", so without `--resource-type workspace` it would be queried as a UC catalog — and silently return empty results if no such catalog exists. When in doubt, pass `--resource-type workspace` explicitly.

Workspace resources use the Account API `/workspaces/{id}/permissionassignments` endpoint to enumerate who has `ADMIN` or `USER` roles. Group principals are expanded to individual members by default.

---

## Visual diagram

```bash
databricks-access-audit --resource "main" --output html > main_access.html
```

The HTML output includes:
- A teal-themed header with stat cards (direct grants, via-group grants, unique principals)
- A Mermaid LR flowchart: resource at the center, direct principals connected with solid arrows, group members connected with dashed arrows
- Color coding: groups = orange, users = teal, service principals = purple
- Full direct grants table and via-group grants table

---

## Export to CSV for access reviews

```bash
databricks-access-audit --resource "main.pii" --output csv > pii_schema_access.csv
```

The CSV has 8 columns: `resource_type`, `resource_name`, `principal_name`, `principal_type`, `principal_source`, `privileges`, `via_group`, `workspace_name`.

Import directly into Excel, Google Sheets, or a BI tool for review.

---

## Group-level view only

By default, `--resource` expands group grants to show every individual member. To see only the groups themselves (no expansion), use `--no-expand-groups`:

```bash
databricks-access-audit --resource "main" --no-expand-groups
```

This is faster and better for an initial overview. Use the default (with expansion) when you need to know exactly which human beings can access the resource.

---

## Python API

```python
from databricks_access_audit import create_client, ResourceAuditor

client = create_client(cloud="azure", client_id="...", client_secret="...", account_id="...")
auditor = ResourceAuditor(client, account_id="...", cloud="azure")

result = auditor.audit(
    "main.pii",           # catalog, schema, table, or workspace name
    resource_type=None,   # auto-detect from name format
    expand_groups=True,   # expand group grants to individual members
    max_workers=8,
)

for grant in result.grants:
    via = f" via {grant.via_group}" if grant.via_group else " (direct)"
    print(f"{grant.principal_type:<20} {grant.principal_name:<40} {', '.join(grant.privileges)}{via}")
```

To render the result yourself:

```python
from databricks_access_audit.csv_output import write_resource_audit_csv
from databricks_access_audit._resource_html_renderer import render_resource_html

# CSV to stdout
write_resource_audit_csv(result)

# Self-contained HTML string
html = render_resource_html(result)
with open("main_pii_access.html", "w") as f:
    f.write(html)
```

---

## Access review checklist

- [ ] Every direct grant is expected and documented
- [ ] No individual appears via a group they shouldn't be in
- [ ] Service principals have only the privileges they need (no `ALL_PRIVILEGES`)
- [ ] `--no-expand-groups` overview reviewed first; full expansion used for sign-off
- [ ] CSV exported and attached to the access review ticket

---

## Common full examples

```bash
# Who can access the main catalog? Full member list, text output
databricks-access-audit --resource "main"

# Schema-level access review, group-only view, exported to CSV
databricks-access-audit --resource "main.analytics" \
  --no-expand-groups \
  --output csv > analytics_access.csv

# Visual HTML report for a manager or auditor
databricks-access-audit --resource "main.pii" \
  --output html > pii_access_$(date +%F).html

# JSON for scripting/automation
databricks-access-audit --resource "main" \
  --no-expand-groups \
  --output json | jq '.grants[] | select(.principal_type == "USER")'

# Specific workspace only
databricks-access-audit --resource "main" \
  --workspace-urls "https://adb-111.azuredatabricks.net" \
  --output text
```
