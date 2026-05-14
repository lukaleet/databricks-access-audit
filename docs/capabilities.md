# Capabilities

## Multi-workspace scanning

**Use this when:** you need to know whether an identity can access *any* workspace in your account — not just the one you're looking at right now. The Databricks UI forces you to check workspaces one at a time; this command covers all of them in a single run.

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

**Use this when:** someone has access you can't explain from their visible memberships, or you need to know exactly which group to modify to revoke access without breaking something else downstream.

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

**Use this when:** you're planning a cleanup and need to know which grants are safe to revoke versus which ones are load-bearing. Not all grants with the same privileges are equal — a personal grant can survive group changes entirely.

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

**Use this when:** you're about to modify group memberships and need to know which ones Databricks can apply directly and which ones require going to your identity provider first. Attempting a SCIM PATCH on an IdP-synced group returns 403 — knowing this upfront saves the round trip.

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

## Schema, table, and volume drill-down

**Use this when:** catalog-level grants don't tell the full story. Someone might have `USE_CATALOG` on `main` but `SELECT` on a sensitive schema inside it — that only appears at the schema or table level. Use this during deep access reviews or incident response when you need to know the exact data boundary.

Catalog-level grants are the default scan depth. The Databricks UI often shows only catalog-level grants — but schema, table, and volume grants can be far more granular and are frequently set independently.

```bash
# Schema grants included
databricks-access-audit --group "data-engineers" --scan-schemas

# Full depth — catalog → schema → table/view
databricks-access-audit --group "data-engineers" --scan-schemas --scan-tables

# UC volume grants (GA securable type — files, unstructured data)
databricks-access-audit --group "data-engineers" --scan-volumes

# Combine: tables + volumes in one pass (schemas enumerated once)
databricks-access-audit --group "data-engineers" --scan-tables --scan-volumes
```

The output cascades — you can see exactly where access starts and where it stops:

```
  UC permissions (7):
    * [CATALOG] main: USE_CATALOG, SELECT via data-engineers (prod-workspace)
    * [SCHEMA]  main.analytics: USE_SCHEMA via data-engineers (prod-workspace)
    * [SCHEMA]  main.raw: USE_SCHEMA via data-engineers (prod-workspace)
    * [TABLE]   main.analytics.events: SELECT via data-engineers (prod-workspace)
    * [TABLE]   main.analytics.sessions: SELECT via data-engineers (prod-workspace)
    * [TABLE]   main.raw.ingest: USE_SCHEMA via all-data-team (prod-workspace)
    * [VOLUME]  main.raw.uploads: READ_VOLUME via data-engineers (prod-workspace)
```

The last two rows demonstrate two different access vectors: `main.raw.ingest` is inherited from a parent group; `main.raw.uploads` is a volume grant held directly by the group. Both are invisible in the Databricks UI without dedicated queries.

!!! note
    `--scan-tables` and `--scan-volumes` each add one API call per schema per workspace. When combined, schema enumeration runs only once — the two scanners share the same `(catalog, schema)` triple list. On large metastores, use `--workers` to parallelise and `--scan-schemas` first to confirm the catalog picture before going deeper.

---

## Workspace object ACLs

**Use this when:** you're offboarding someone and need to know if they own any jobs, clusters, or dashboards that will break when their account is deleted — or when you need the full picture of what a principal can reach beyond just data.

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

**Use this when:** you removed someone from a group and they still have access — or you're trying to understand why. Personal grants survive all group changes silently. This surfaces exactly who has them and whether they're safe to revoke.

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

**Use this when:** you want to understand the full weight of a grant. `ALL_PRIVILEGES` and `MANAGE` aren't just data access — they're the ability to grant access to others. An identity with these privileges on a production catalog can extend that access to anyone. That's a different category than `SELECT`.

`ALL_PRIVILEGES` and `MANAGE` aren't just access — they're the ability to grant access to others. An identity with `ALL_PRIVILEGES` on a production catalog can extend that access to anyone. That's a different category of risk.

```bash
databricks-access-audit --principal "alice@company.com" --escalation-check
```

Escalation findings include the specific privilege, the securable it covers, and whether it's held directly or through a group chain — so you know how deep the fix needs to go.

---

## Compliance snapshots and diff

**Use this when:** your auditor asks whether access has changed since last quarter and you need a timestamped, reproducible answer — or when you want to track permission drift over time and catch unexpected changes before they become incidents.

Databricks has no built-in permission changelog. The snapshot and diff workflow creates one.

```bash
# Save
databricks-access-audit --group "data-engineers" --save-snapshot snapshots/Q1.json

# Diff (next quarter) — text, CSV, or a shareable HTML page
databricks-access-audit --group "data-engineers" --baseline snapshots/Q1.json
databricks-access-audit --group "data-engineers" --baseline snapshots/Q1.json --output html > q1-q2-diff.html
```

Snapshots are plain JSON — versioned, human-readable without the tool, safe to commit to version control. Diffs are deterministic: any privilege change appears as an explicit removal + addition pair. Nothing is silently updated.

See [Compliance Snapshots](use-cases/compliance.md) for the full audit workflow.

---

## Access visualization

**Use this when:** you need to explain access to someone who doesn't live in a terminal — a manager, a new team member, or an auditor who wants to see the full picture without reading a CSV. Also useful when you're tracing an unexpected access path and want to see all the group chains at once.

```bash
# HTML access map — Mermaid diagram + tables, opens in any browser
databricks-access-audit --principal "alice@company.com" --output html > alice.html
databricks-access-audit --group "data-engineers" --output html > data-engineers.html

# ASCII tree — same structure in the terminal, grouped by access path
databricks-access-audit --principal "alice@company.com" --tree
databricks-access-audit --group "data-engineers" --tree
```

The HTML output is self-contained — one file, no server required. The chart defaults to a catalog-level view; a **Schema view** toggle renders a deeper diagram on demand (requires `--scan-schemas`). The tree output is useful for CI logs, Slack messages, and incident tickets.

See [Visualizing Access](use-cases/access-map.md) for examples and when to use each format.

---

## Resilient API calls

**Use this when:** you're scanning a large account (many workspaces or deep catalogs) and hitting rate limits — or running scans in an automated pipeline where transient failures shouldn't cause silent data loss.

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

---

## Resource-centric access view

**Use this when:** you start from a resource — a catalog, schema, table, or workspace — and need to know exactly who can reach it. The `--principal` and `--group` modes answer "what can this identity access?"; `--resource` answers the inverse: "who can access this thing?" Use it for access reviews, scope analysis, and compliance attestation.

All other audit modes are identity-first. `--resource` is the only resource-first mode.

```bash
# Who has access to the main catalog?
databricks-access-audit --resource "main"

# Who has access to the main.analytics schema?
databricks-access-audit --resource "main.analytics"

# Who has access to a specific table?
databricks-access-audit --resource "main.analytics.orders"

# Who has a workspace role?
databricks-access-audit --resource "https://adb-123.azuredatabricks.net"
databricks-access-audit --resource "prod-workspace" --resource-type workspace

# Group-level view only (skip member expansion)
databricks-access-audit --resource "main" --no-expand-groups

# Visual diagram for a manager or auditor
databricks-access-audit --resource "main" --output html > main_access.html

# Export for a quarterly access review
databricks-access-audit --resource "main.pii" --output csv > pii_access.csv
```

Resource type is auto-detected from the name format:

| Name format | Detected as |
|---|---|
| `main` (0 dots) | Catalog |
| `main.analytics` (1 dot) | Schema |
| `main.analytics.orders` (2+ dots) | Table |
| `https://...` or name containing `databricks` | Workspace |

When the workspace name doesn't contain "databricks" (e.g. `prod-ws`), add `--resource-type workspace` to override auto-detection. Without it the tool would query UC for a catalog named `prod-ws` and silently return empty results.

**Group expansion:** by default, each group principal is expanded to its individual members so the output shows the actual humans who have access, not just abstract group names. Pass `--no-expand-groups` for a group-level summary. The default is more useful for incident response and offboarding verification; `--no-expand-groups` is faster for a quick overview of the access shape.

**Multi-workspace deduplication:** for UC resources (catalog/schema/table), the scan runs in parallel across all workspaces. When multiple workspaces share the same metastore, the same grant appears from each workspace — the tool deduplicates by `(principal, via_group, privileges)` so each grant appears exactly once.

**Schema and table audits show direct grants only:** `--resource "main.analytics"` returns the same set as `SHOW GRANTS ON SCHEMA main.analytics` — principals with an explicit grant on that schema. Principals who reach the schema via a catalog-level grant (e.g. `USE_CATALOG + SELECT` on `main`) are not included. To see the full access picture, run `--resource "main"` for catalog-level access and `--resource "main.analytics"` for schema-specific additions on top of that.

See [Resource Audit](use-cases/resource-audit.md) for the full workflow with example output and HTML diagrams.
