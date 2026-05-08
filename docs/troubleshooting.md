# Troubleshooting

Common issues and how to fix them.

---

## "0 workspace roles" — did my principal audit miss something?

No. This is expected Databricks behaviour.

The `permissionassignments` API only returns **explicit** workspace role grants — typically `ADMIN` assignments made directly on the principal. It does not return access granted through the implicit built-in "account users" group. Most users reach workspaces through that built-in group and will show `0 workspace roles` here.

Their Unity Catalog permissions are still discovered correctly via the catalog scan, because those are stored in the metastore, not in workspace role assignments.

**If you expected an explicit `ADMIN` grant and it isn't showing:** confirm the grant exists via the Account Console → workspace → Permissions. If it does exist, try `--no-sdk` to rule out SDK auth caching the wrong identity.

---

## `--resource "prod-workspace"` returns empty results

The tool auto-detects workspace names that contain `"databricks"` or start with `"https://"`. A name like `prod-workspace` has neither — so without `--resource-type workspace`, it queries Unity Catalog for a catalog named `prod-workspace` and silently returns nothing when no such catalog exists.

**Fix:**

```bash
databricks-access-audit --resource "prod-workspace" --resource-type workspace
```

Or use the workspace URL directly — it's always auto-detected:

```bash
databricks-access-audit --resource "https://adb-1234.azuredatabricks.net"
```

---

## Auth error on first run — 401 / 403 / "oauth-m2m rejected"

**Step 1 — check the host in your `~/.databrickscfg`.**

For Azure: `host = https://accounts.azuredatabricks.net`  
For AWS: `host = https://accounts.cloud.databricks.com`  
For GCP: `host = https://accounts.gcp.databricks.com`

The `cloud` is auto-detected from the host. If you're passing `--cloud` explicitly, make sure it matches.

**Step 2 — verify the SP has Account Admin.**

The audit SP must have the Account Admin role in your Databricks account. Workspace Admin alone is not enough for cross-workspace scanning.

**Step 3 — SDK auth is caching stale credentials.**

If you store a PAT token in `~/.databrickscfg` alongside OAuth credentials, the SDK may pick up the wrong one. Add `--no-sdk` to force the raw HTTP client, which reads your profile directly:

```bash
databricks-access-audit --principal "alice@company.com" --no-sdk
```

---

## 403 on group modifications (`--apply` or `--clone-from`)

You're trying to SCIM PATCH a group that is IdP-synced. Groups created in Entra ID, Okta, or AWS SSO have a SCIM `externalId` field set. Databricks mirrors their membership — it cannot write to it. Any SCIM PATCH against these groups returns `403 Forbidden`.

The tool classifies groups before applying and skips IdP-synced ones automatically. The output tells you which groups need to be modified in your IdP:

```
  Actions required in your identity provider (2):
    ! data-engineers     [external — add in Entra/Okta]
```

---

## Snapshot diff fails with "Cannot diff snapshots of different modes"

You're comparing a group snapshot against a principal snapshot (or vice versa). Snapshots are mode-specific — a group run produces a group snapshot, a principal run produces a principal snapshot. They can't be diffed against each other.

Re-run the same command that produced the baseline snapshot to generate the current snapshot, then diff:

```bash
# If the baseline was created with --group, use --group for the current run too
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/baseline.json \
  --save-snapshot snapshots/current.json
```

---

## Catalog scan returns no grants but I know grants exist

Two common causes:

**1. The SP lacks `MANAGE` on the catalog.**  
The audit SP needs Metastore Admin or `MANAGE` on each catalog to read its grants via `SHOW GRANTS`. Without it, the catalog scan returns empty results with no error. Grant `MANAGE` on the catalog, or use `--auto-elevate` to temporarily add the SP as a Workspace Admin.

**2. The workspace and metastore are not linked.**  
If a workspace doesn't have a metastore attached, the catalog scan for that workspace returns nothing. This is normal — the tool moves on to the next workspace.

---

## Performance is slow on large accounts

**Increase worker parallelism:**

```bash
databricks-access-audit --group "data-engineers" \
  --scan-tables \
  --workers 16
```

Default is 8 workers. Each workspace scan runs in a separate thread — adding workers reduces wall-clock time proportionally up to the API rate limit.

**Scope the scan:**

```bash
# Target specific workspaces instead of auto-discovering all
databricks-access-audit --group "data-engineers" \
  --workspace-urls "https://adb-111.azuredatabricks.net,https://adb-222.azuredatabricks.net"

# Scan schemas but skip tables on the first pass
databricks-access-audit --group "data-engineers" --scan-schemas
```

**Tune retry behaviour** if you're hitting rate limits:

```bash
databricks-access-audit --group "data-engineers" \
  --max-retries 8 \
  --retry-max-delay 120
```
