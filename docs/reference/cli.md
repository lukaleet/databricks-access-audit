# CLI Reference

## Synopsis

```bash
databricks-access-audit (--group NAME | --principal NAME) [OPTIONS]
```

`--group` and `--principal` are mutually exclusive and one is required.

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

---

## Scan depth

### `--scan-schemas`

Include schema-level Unity Catalog grants. Off by default.

### `--scan-tables`

Include table and view-level grants. Implies schema scanning. Off by default.

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

### `--output {text,json,csv}`

Output format. Default: `text`.

- `text` — human-readable console output
- `json` — machine-readable JSON (logs go to stderr)
- `csv` — one row per grant, written to stdout (pipe to a file)

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

Force the raw HTTP client even when `databricks-sdk` is installed.

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
