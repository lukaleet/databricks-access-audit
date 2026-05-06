# Capabilities

## Multi-workspace scanning

The Databricks UI shows you one workspace at a time. INFORMATION_SCHEMA shows you one metastore at a time. Neither has a cross-workspace view.

This tool discovers all workspaces in your account automatically via the Account API and scans them in parallel — one command covers your entire Databricks estate.

```bash
# Auto-discover and scan everything
databricks-access-audit --principal "alice@company.com"

# Or target specific workspaces
databricks-access-audit --principal "alice@company.com" \
  --workspace-urls "https://adb-111.azuredatabricks.net,https://adb-222.azuredatabricks.net"
```

Every grant, workspace role, and object ACL in the output is tagged with the workspace it came from:

```
  Workspace access (2):
    * prod-workspace: USER (via data-engineers)
    * analytics-workspace: USER (via data-engineers)

  UC permissions (3):
    * [CATALOG] main: USE_CATALOG, SELECT via data-engineers (prod-workspace)
    * [CATALOG] raw: USE_CATALOG via data-engineers (analytics-workspace)
    * [SCHEMA]  main.analytics: USE_SCHEMA via data-engineers (prod-workspace)
```

With `--workers N` (default: 8) all workspace scans run in parallel — scanning 10 workspaces takes about the same wall-clock time as scanning 1.

---

## Recursive group resolution

Databricks groups nest. A user in `data-engineers` might inherit access through `data-engineers → all-data-team → platform-users`. The Databricks UI doesn't trace this — it shows you direct memberships, not the full chain.

This tool traces every level of nesting and shows the exact path:

```
  Group memberships (3, 3 IdP-synced, 0 Databricks-managed):
    * data-engineers (direct, external)
      path: alice@company.com → data-engineers
    - all-data-team (transitive, external)
      path: alice@company.com → data-engineers → all-data-team
    - platform-users (transitive, external)
      path: alice@company.com → data-engineers → all-data-team → platform-users
```

`*` = direct membership. `-` = transitive. Each path shows the exact chain — so when you want to revoke access, you know which group to modify and exactly what that change will affect downstream.

For group audit, all users and SPs are bulk pre-fetched upfront — no N+1 SCIM calls, even for groups with hundreds of members.

---

## Permission inheritance tracking

Not all grants are equal. A grant held by the group itself is different from a grant a parent group holds, which is different from a grant a member holds personally. This distinction determines what you can safely revoke and what the actual access vector is.

```bash
databricks-access-audit --group "data-engineers" --output csv
```

Every row in the output carries a `grant_source`:

| `grant_source` | What it means |
|---|---|
| `Direct` | The group itself holds this grant on the securable |
| `Upstream` | A parent group of `data-engineers` holds the grant — inherited |
| `Member Direct` | A member holds this grant personally — bypasses the group entirely |

A member's `Member Direct` grant on `main` while `data-engineers` also has a grant on `main` is redundancy — the member has the same access twice, and the personal copy will survive any group changes you make. This is what the [redundancy analysis](#redundancy-and-overlap-analysis) targets.

---

## IdP vs Databricks group classification

When you need to provision or modify group memberships, the critical question is: does Databricks own this group, or does your identity provider?

Groups synced from Entra ID, Okta, or AWS SSO have a SCIM `externalId` field set. Databricks mirrors their membership; it cannot write to it. Any SCIM PATCH against an IdP-synced group returns `403 Forbidden`. You have to go to your IdP.

Groups created directly in Databricks have no `externalId`. You can manage them via SCIM PATCH immediately.

The `--clone-from` and `--compare` modes surface this distinction on every group — so you know before you try which track each action belongs to:

```
  Actions required in your identity provider (2):
    ! data-engineers     [external — add in Entra/Okta]
    ! bi-consumers       [external — follows once data-engineers is done]

  Actions in Databricks (2):
    + npb-platform-users       [internal — applied with --apply]
    + scratch-workspace-admins [internal — applied with --apply]
```

---

## Schema and table drill-down

Catalog-level grants are the default scan depth. The Databricks UI often shows only catalog-level grants — but schema and table grants can be far more granular and are frequently set independently.

```bash
# Schema grants included
databricks-access-audit --group "data-engineers" --scan-schemas

# Full depth — catalog → schema → table/view
databricks-access-audit --group "data-engineers" --scan-schemas --scan-tables
```

The output cascades — you can see exactly where access starts and where it stops:

```
  UC permissions (6):
    * [CATALOG] main: USE_CATALOG, SELECT via data-engineers (prod-workspace)
    * [SCHEMA]  main.analytics: USE_SCHEMA via data-engineers (prod-workspace)
    * [SCHEMA]  main.raw: USE_SCHEMA via data-engineers (prod-workspace)
    * [TABLE]   main.analytics.events: SELECT via data-engineers (prod-workspace)
    * [TABLE]   main.analytics.sessions: SELECT via data-engineers (prod-workspace)
    * [TABLE]   main.raw.ingest: USE_SCHEMA via all-data-team (prod-workspace)
```

The last row — `main.raw.ingest` via `all-data-team` — is inherited from a parent group, not from `data-engineers` directly. This is invisible in the Databricks UI.

!!! note
    `--scan-tables` adds one API call per schema per workspace. On large metastores, use `--workers` to parallelise and `--scan-schemas` first to confirm the catalog picture before going deeper.

---

## Workspace object ACLs

Unity Catalog covers data access. Workspace objects — jobs, clusters, dashboards, pipelines — have their own ACL system that UC doesn't see. The tool scans both.

```bash
databricks-access-audit --principal "alice@company.com" --scan-workspace-objects
```

13 object types are covered:

| Category | Types |
|---|---|
| Compute | Clusters, cluster policies |
| Orchestration | Jobs, Delta Live Tables pipelines |
| SQL / Analytics | SQL warehouses, SQL queries, SQL alerts, Lakeview dashboards, Genie spaces |
| AI / ML | MLflow experiments, registered models, model serving endpoints |
| Apps | Databricks Apps |

Use `--workspace-object-types` to scan a subset:

```bash
databricks-access-audit --principal "alice@company.com" \
  --scan-workspace-objects \
  --workspace-object-types jobs,pipelines,clusters
```

---

## Redundancy and overlap analysis

Members sometimes hold personal catalog grants that the group already covers — grants set before the group had them, one-off access that was never revoked, or people who changed teams but kept old permissions. These grants are invisible in the UI, survive group membership changes, and accumulate silently.

The redundancy detector compares every `Member Direct` grant against the group's effective privileges and classifies the overlap:

- **Full** — every personal privilege is already covered by the group. Safe to revoke.
- **Partial** — some overlap, some not. Revoke only the covered portion.
- **None** — the personal grant is intentional (different catalog, or privileges the group doesn't have).

`ALL_PRIVILEGES` is expanded to component privileges before comparison — a group with `ALL_PRIVILEGES` correctly flags member-level `SELECT` as fully redundant.

```bash
databricks-access-audit --group "data-engineers" --revoke-script
```

Generates copy-paste REVOKE SQL for all redundant grants. The group grant is untouched.

---

## Escalation detection

`ALL_PRIVILEGES` and `MANAGE` aren't just access — they're the ability to grant access to others. An identity with `ALL_PRIVILEGES` on a production catalog can extend that access to anyone. That's a different category of risk.

```bash
databricks-access-audit --principal "alice@company.com" --escalation-check
```

Escalation findings include the specific privilege, the securable it covers, and whether it's held directly or through a group chain — so you know how deep the fix needs to go.

---

## Compliance snapshots and diff

Databricks has no built-in permission changelog. The snapshot and diff workflow creates one.

```bash
# Save
databricks-access-audit --group "data-engineers" --save-snapshot snapshots/Q1.json

# Diff (next quarter)
databricks-access-audit --group "data-engineers" --baseline snapshots/Q1.json
```

Snapshots are plain JSON — versioned, human-readable without the tool, safe to commit to version control. Diffs are deterministic: any privilege change appears as an explicit removal + addition pair. Nothing is silently updated.

See [Compliance Snapshots](use-cases/compliance.md) for the full audit workflow.

---

## Resilient API calls

Rate limits and transient errors are inevitable at scale. The raw HTTP client handles them automatically:

- **429 Too Many Requests** — respects the `Retry-After` response header when present; falls back to exponential backoff
- **5xx Server Errors** — retries up to `--max-retries` times (default: 5)
- **Per-host token cache** — OAuth tokens are cached per account host and refreshed before expiry, so parallel workspace scans don't each trigger a new token exchange

When using `databricks-sdk` (`pip install ".[sdk]"`), the SDK manages retries and auth independently.

Tune for high-volume scans:

```bash
databricks-access-audit --group "data-engineers" \
  --scan-tables \
  --workers 16 \
  --max-retries 8 \
  --retry-max-delay 120
```
