# CLI Reference

## Synopsis

```bash
databricks-access-audit (--group NAME | --principal NAME | --compare A B | --clone-from NAME | --resource NAME) [OPTIONS]
```

`--group`, `--principal`, `--compare`, `--clone-from`, and `--resource` are mutually exclusive and one is required.

---

## Credentials

### `--profile NAME`

Load credentials from a named section in `~/.databrickscfg`.  
Default: `DEFAULT` (env: `DATABRICKS_CONFIG_PROFILE`).

```bash
databricks-access-audit --group "data-engineers" --profile prod
```

### `--client-id ID`

Service principal application (client) ID.  
Env: `DATABRICKS_CLIENT_ID`

### `--client-secret SECRET`

Service principal secret.  
Env: `DATABRICKS_CLIENT_SECRET`

### `--account-id ID`

Databricks account ID.  
Env: `DATABRICKS_ACCOUNT_ID`

### `--cloud {azure,aws,gcp}`

Cloud provider. Auto-detected from the `host` field in `~/.databrickscfg` when using `--profile`. Default: `azure`.

**Credential resolution order:** CLI flags → environment variables → `~/.databrickscfg` profile.

---

## Target

### `--group NAME`

Audit a group: who's in it, what can they access, who has redundant personal grants.

### `--principal NAME`

Audit a principal: every workspace and UC object this user, service principal, or group can reach.  
Accepts: email address, SP display name, SP application ID, or group name.

### `--compare A B`

Compare group memberships between two principals. Pure read — no writes.

```bash
databricks-access-audit --compare "alice@company.com" "bob@company.com" --cloud azure
```

Shows which groups are unique to each principal and which are shared. Each group is annotated with:

- **Source** — `external` (IdP-synced via Entra/Okta) or `internal` (Databricks-managed)
- **Directness** — whether the membership is direct or transitive
- **Path** — the full membership chain

Works with all `--output` formats (`text`, `json`, `csv`).

### `--clone-from NAME`

Build a provisioning report to replicate one principal's group access onto another.  
Requires `--to TARGET`.

```bash
databricks-access-audit --clone-from "alice@company.com" --to "bob@company.com" --cloud azure
```

Each of the source's **direct** group memberships is classified as:

| Action | Meaning |
|---|---|
| `Databricks` | Group is Databricks-managed and provides access — can be applied with `--apply` |
| `IdP required` | Group is IdP-synced (Entra/Okta) — must be managed in your identity provider |
| `Unverified` | Group is Databricks-managed but no workspace assignment detected — use `--scan-uc` to resolve |
| `Skipped` | Verified dead-end — no workspace or UC grants (requires `--scan-uc`) |

### `--resource NAME`

Discover who has access to a resource — the inverse of `--principal`.  
Resource type is auto-detected:

| Name format | Detected type |
|---|---|
| `main` (0 dots) | Catalog |
| `main.analytics` (1 dot) | Schema |
| `main.analytics.orders` (2+ dots) | Table |
| `https://...` or name containing "databricks" | Workspace |

```bash
databricks-access-audit --resource "main"                        # catalog
databricks-access-audit --resource "main.analytics"             # schema
databricks-access-audit --resource "main.analytics.orders"      # table
databricks-access-audit --resource "prod-databricks-workspace"  # workspace
```

Scans all discovered workspaces in parallel and deduplicates by `(principal, via_group, privileges)`. Works with all `--output` formats.

### `--resource-type {catalog,schema,table,workspace}`

Override auto-detected resource type for `--resource`. Use when the name is ambiguous — for example, a workspace whose name doesn't contain "databricks":

```bash
databricks-access-audit --resource "prod-workspace" --resource-type workspace
```

### `--no-expand-groups`

For `--resource` mode: show only the direct grants on the resource. Default is to expand each GROUP principal to its individual members (users and service principals).

```bash
# Group-only view
databricks-access-audit --resource "main" --no-expand-groups

# Full individual-member view (default)
databricks-access-audit --resource "main"
```

### `--to TARGET`

Target principal for `--clone-from`. Accepts the same identifier formats as `--principal`.

### `--apply`

Execute the provisioning — perform SCIM PATCH for each `Databricks`-classified group, adding the target as a member. Without `--apply` the command is a dry-run that only prints the report.

```bash
databricks-access-audit --clone-from "alice@company.com" --to "bob@company.com" \
  --apply --cloud azure
```

### `--scan-uc`

For `--clone-from`: scan Unity Catalog grants to resolve `Unverified` groups.  
Groups with UC grants → classified as `Databricks`. Groups with no grants → classified as `Skipped`.

Off by default because it adds catalog-scan API calls per workspace. Use when source has UC-only groups (no workspace assignment but catalog access).

---

## Scan depth

### `--scan-schemas`

Include schema-level Unity Catalog grants. Off by default.

### `--scan-tables`

Include table and view-level grants. Implies schema scanning. Off by default.

### `--scan-volumes`

Include Unity Catalog volume-level grants. Requires schema enumeration (triggers the same `(catalog, schema)` traversal as `--scan-tables`). Off by default. Can be combined with `--scan-tables` without double-scanning schemas.

### `--scan-workspace-objects`

Scan workspace object ACLs: jobs, clusters, SQL warehouses, pipelines, cluster policies, dashboards, Genie spaces, MLflow experiments, registered models, serving endpoints, apps. Off by default — adds significant API calls.

### `--workspace-object-types LIST`

Comma-separated list of object types to include when `--scan-workspace-objects` is set. Default: all 13 types.

| Value | Object type |
|---|---|
| `jobs` | Jobs |
| `clusters` | Interactive clusters |
| `cluster_policies` | Cluster policies |
| `pipelines` | Delta Live Tables pipelines |
| `sql_warehouses` | SQL warehouses |
| `sql_queries` | SQL queries |
| `sql_alerts` | SQL alerts |
| `lakeview_dashboards` | Lakeview dashboards |
| `genie_spaces` | Genie spaces |
| `mlflow_experiments` | MLflow experiments |
| `registered_models` | Registered models |
| `serving_endpoints` | Model serving endpoints |
| `apps` | Databricks Apps |

```bash
databricks-access-audit --principal "alice@company.com" \
  --scan-workspace-objects \
  --workspace-object-types jobs,pipelines
```

### `--workspace-urls URLS`

Comma-separated workspace URLs. When omitted the tool discovers all workspaces in the account automatically.

---

## Output

### `--output {text,json,csv,html}`

Output format. Default: `text`.

- `text` — human-readable console output
- `json` — machine-readable JSON (logs go to stderr)
- `csv` — one row per grant, written to stdout (pipe to a file)
- `html` — self-contained HTML page with a Mermaid access graph and data tables (logs go to stderr). Supported by `--principal`, `--group`, `--resource`, and `--baseline` (diff page).

```bash
# Principal access map
databricks-access-audit --principal "alice@company.com" --output html > alice.html

# Group access map
databricks-access-audit --group "data-engineers" --output html > data-engineers.html

# Resource access map — who can reach catalog main?
databricks-access-audit --resource "main" --output html > main_catalog.html

# Compliance diff page (baseline → current)
databricks-access-audit --group "data-engineers" --baseline snapshots/Q1.json --output html > q1-q2-diff.html
```

### `--summary`

Print a compact executive summary after the audit: member counts, UC grant totals by level, and key risk indicators (redundancy, stale grants, escalations, workspace-local groups). Supported by `--group`, `--principal`, and `--resource`.

For `--output json`, `csv`, or `html` the summary is written to stderr so machine-readable stdout is not corrupted.

```bash
# One-page summary alongside the default text report
databricks-access-audit --group "data-engineers" --summary

# Summary only alongside JSON (summary goes to stderr, JSON to stdout)
databricks-access-audit --group "data-engineers" --output json --summary > grants.json
```

Example output:

```
==============================================================
  SUMMARY  —  data-engineers
==============================================================
  Members       12 users, 2 SPs  (10 IdP-synced, 4 Databricks-managed)
  UC grants     24 total  (8 catalog | 10 schema | 4 table | 2 volume)
  Personal      3 member-direct grant(s)
  Risks         3 fully redundant, 1 partial | 1 stale (>90d inactive)
==============================================================
```

### `--tree`

Render audit output as an ASCII tree grouped by grant source rather than securable type. Supported by both `--principal` and `--group`.

- **Principal audit** — organises by granting group: "what does alice get *via* data-engineers?"
- **Group audit** — organises by grant source: direct grants the group holds, upstream grants inherited from parent groups, member-direct personal grants with redundancy callout.

```bash
databricks-access-audit --principal "alice@company.com" --tree
databricks-access-audit --group "data-engineers" --tree
```

### `--revoke-script`

Print copy-paste REVOKE SQL for redundant member-direct grants. Group audit only.

---

## Snapshots and diff

### `--save-snapshot PATH`

Save a timestamped JSON snapshot of this audit run to `PATH`. Creates parent directories as needed. Combine with `--baseline` to save and compare in a single run.

### `--baseline PATH`

Compare this run against a previous snapshot and print what changed: new grants, removed grants, added/removed members. Compatible with all `--output` formats.

---

## Permission elevation

### `--auto-elevate`

Temporarily grant the audit SP Workspace Admin on any workspace where it lacks that role, then restore the prior state after the audit (success or failure). Requires Account Admin.

### `--dry-run-elevation`

Preview which workspaces would be elevated without writing any permission changes. Implies `--auto-elevate`.

---

## Security analysis

### `--escalation-check`

Flag `ALL_PRIVILEGES` and `MANAGE` grants inherited by the principal. Principal audit (`--principal`) only.

### `--stale-days N`

Flag member-direct catalog grants with no recorded activity in `system.access.audit` for the last N days.

Requires `--sql-warehouse-id`. `system.access.audit` must be enabled on the account.

### `--sql-warehouse-id ID`

SQL warehouse used to query `system.access.audit`. Required when `--stale-days` is set.

### `--sql-workspace-url URL`

Workspace URL whose `system.access.audit` to query. Defaults to the first discovered workspace.

### `--check-local-groups`

Scan each workspace's SCIM directory and flag groups that exist only at the workspace level (not in account SCIM). These are legacy workspace-local groups pending migration.

---

## Performance

### `--workers N`

Number of parallel threads for workspace, schema, and table scanning. Default: `8`. Set to `1` to scan sequentially.

### `--no-sdk`

Force the raw HTTP client even when `databricks-sdk` is installed. Use this when:

- You're authenticating via a PAT token in `~/.databrickscfg` and the SDK's auth chain isn't picking it up.
- You want explicit control over retry behaviour via `--max-retries` / `--retry-*` flags (SDK manages its own retries independently).

### `--max-retries N`

Maximum retry attempts on 429 / 5xx responses (raw HTTP client only). Default: `5`.

### `--retry-base-delay SECONDS`

Initial backoff delay in seconds. Default: `1.0`.

### `--retry-max-delay SECONDS`

Maximum backoff delay cap in seconds. Default: `60.0`.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Audit completed (including when changes are detected in diff mode) |
| `1` | Fatal error — missing credentials, unknown principal, network failure |
