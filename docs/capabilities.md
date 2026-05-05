# Capabilities

The core engine behind both audit modes. Each of these works out of the box — no configuration beyond credentials.

---

## Multi-workspace scanning

Databricks spreads your estate across multiple workspaces. The tool discovers all of them automatically via the Account API and scans them in parallel.

```bash
# Scan every workspace in the account
databricks-access-audit --principal "alice@company.com"

# Or target specific workspaces
databricks-access-audit --principal "alice@company.com" \
  --workspace-urls "https://adb-111.azuredatabricks.net,https://adb-222.azuredatabricks.net"
```

Sample output shows workspace context on every grant:

```
  Workspace access (2):
    * prod-workspace: USER (via data-engineers)
    * analytics-workspace: USER (via data-engineers)

  UC permissions (4):
    * [CATALOG] main: USE_CATALOG, SELECT via data-engineers (prod-workspace)
    * [CATALOG] raw: USE_CATALOG via data-engineers (analytics-workspace)
    * [SCHEMA]  main.analytics: USE_SCHEMA via data-engineers (prod-workspace)
    * [TABLE]   main.analytics.events: SELECT via data-engineers (prod-workspace)
```

With `--workers N` (default: 8) all workspace scans run in parallel — scanning 10 workspaces takes about the same time as scanning 1.

---

## Recursive group resolution

Databricks groups nest. A user in `data-engineers` may inherit access through `all-data-team → platform-users → account-users`. The tool traces the full chain.

```bash
databricks-access-audit --principal "alice@company.com"
```

```
  Group memberships (3, 3 IdP-synced, 0 Databricks-managed):
    * data-engineers (direct, external)
      path: alice@company.com -> data-engineers
    - all-data-team (transitive, external)
      path: alice@company.com -> data-engineers -> all-data-team
    - platform-users (transitive, external)
      path: alice@company.com -> data-engineers -> all-data-team -> platform-users
```

`*` = direct membership, `-` = transitive. Each path shows the exact chain so you know which group to modify if you want to revoke access.

For group audit, the resolver bulk pre-fetches all users and SPs upfront — no N+1 SCIM calls even for groups with hundreds of members.

---

## Permission inheritance tracking

Every grant is classified by how the principal acquired it. This is what makes cleanup decisions safe.

```bash
databricks-access-audit --group "data-engineers" --scan-schemas --output csv
```

| `grant_source` | What it means |
|---|---|
| `Direct` | The group itself holds this grant on the securable |
| `Upstream` | A parent group of `data-engineers` holds the grant — inherited |
| `Member Direct` | A member of the group holds this grant personally — bypasses the group |

Example: the `main` catalog has three grant rows for `data-engineers`:

```
securable_name  principal           grant_source    privileges
main            data-engineers      Direct          USE_CATALOG, SELECT
main            all-data-team       Upstream        USE_CATALOG
main            bob@company.com     Member Direct   USE_CATALOG, SELECT
```

Bob's personal grant (`Member Direct`) duplicates what the group already provides. The tool flags this for cleanup (see [Redundancy analysis](#redundancy-and-overlap-analysis) below).

---

## Schema and table drill-down

Catalog-level grants are the default. When you need the full picture:

```bash
# Include schema-level grants
databricks-access-audit --group "data-engineers" --scan-schemas

# Include schema and table/view grants
databricks-access-audit --group "data-engineers" --scan-schemas --scan-tables

# Principal audit — same flags work
databricks-access-audit --principal "alice@company.com" --scan-schemas --scan-tables
```

The output cascades — catalog → schema → table — so you can see exactly where access starts and where it stops:

```
  UC permissions (6):
    * [CATALOG] main: USE_CATALOG, SELECT via data-engineers (prod-workspace)
    * [SCHEMA]  main.analytics: USE_SCHEMA via data-engineers (prod-workspace)
    * [SCHEMA]  main.raw: USE_SCHEMA via data-engineers (prod-workspace)
    * [TABLE]   main.analytics.events: SELECT via data-engineers (prod-workspace)
    * [TABLE]   main.analytics.sessions: SELECT via data-engineers (prod-workspace)
    * [TABLE]   main.raw.ingest: USE_SCHEMA via all-data-team (prod-workspace)
```

Note `main.raw.ingest` — inherited from `all-data-team` (an upstream group), not from `data-engineers` directly. This level of detail is invisible in the Databricks UI.

!!! note
    `--scan-tables` adds one API call per schema per workspace. On large metastores this can be slow — use `--workers` to parallelise and `--scan-schemas` first to confirm the catalog picture before going deeper.

---

## Resilient API calls

Rate limits and transient errors are inevitable at scale. The raw HTTP client handles them automatically:

- **429 Too Many Requests** — respects the `Retry-After` response header when present; falls back to exponential backoff
- **5xx Server Errors** — retries up to `--max-retries` times (default: 5)
- **Exponential backoff** — starts at `--retry-base-delay` seconds (default: 1.0), caps at `--retry-max-delay` seconds (default: 60.0)
- **Per-host token cache** — OAuth tokens are cached per account host and refreshed before expiry, so parallel workspace scans don't each trigger a new token exchange

When using `databricks-sdk` (`pip install ".[sdk]"`), the SDK manages retries and auth independently with its own battle-tested implementation.

Tune for high-volume scans:

```bash
databricks-access-audit --group "data-engineers" \
  --scan-tables \
  --workers 16 \
  --max-retries 8 \
  --retry-max-delay 120
```

---

## Principal group membership with hierarchy

The reverse of group audit — start from a person, trace upward through every group they belong to, and show what each group provides.

```bash
databricks-access-audit --principal "alice@company.com"
```

This resolves any principal type:

| Input | Resolves as |
|---|---|
| `alice@company.com` | User by email |
| `etl-pipeline-sp` | Service principal by display name |
| `00000000-0000-0000-0000-000000000001` | Service principal by application ID |
| `data-engineers` | Group — audits the group's own reachable permissions |

The membership list includes every group in the chain with `is_direct` and the full path, so you can see not just what Alice can access, but *why* — which specific group grants it and through how many hops.

**Groups with no workspace assignment** are reported separately:

```
  Groups with no workspace assignment (2):
    (may be UC-only access groups — check UC permissions below before acting)
    - catalog-main-readers
    - data-quality-monitors
```

This is not necessarily a problem. A group can be intentionally assigned to Unity Catalog securables (catalogs, schemas, tables) without being assigned to any workspace — this is a valid and recommended pattern for fine-grained data access control decoupled from workspace membership. Check the UC permissions section before treating these as cleanup candidates: if the group appears in the permissions list below, it is providing real access.

---

## Redundancy and overlap analysis

Members of a group sometimes hold personal catalog grants that the group already covers. The tool compares every `Member Direct` grant against the group's effective privileges and classifies the overlap:

```bash
databricks-access-audit --group "data-engineers" --revoke-script
```

**Full redundancy** — every privilege the member holds personally is already provided by the group:

```
  bob@company.com: SELECT, USE_CATALOG on main
    → Group already grants: SELECT, USE_CATALOG
    → Redundancy: FULL — safe to revoke entirely
```

**Partial redundancy** — the member has some privileges the group covers and some it doesn't:

```
  carol@company.com: SELECT, MODIFY, USE_CATALOG on staging
    → Group already grants: SELECT, USE_CATALOG
    → Additional (not covered): MODIFY
    → Redundancy: PARTIAL — revoke only the overlapping privileges
```

**No redundancy** — the personal grant is intentional (e.g. access to a catalog the group doesn't touch):

```
  dave@company.com: SELECT on sensitive_catalog
    → Group has no grant on sensitive_catalog
    → Redundancy: NONE
```

`ALL_PRIVILEGES` is expanded to its component privileges before comparison, so a group with `ALL_PRIVILEGES` on a catalog correctly flags member-level `SELECT` or `MODIFY` as fully redundant.

With `--revoke-script`, the tool generates copy-paste SQL for all redundant grants:

```sql
-- Full redundancy: bob@company.com
REVOKE USE_CATALOG, SELECT ON CATALOG main FROM `bob@company.com`;

-- Partial redundancy: only the covered privileges
REVOKE USE_CATALOG, SELECT ON CATALOG staging FROM `carol@company.com`;
```

The script targets individuals, not the group — the group grant is untouched.
