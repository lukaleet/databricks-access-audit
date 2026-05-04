# databricks-access-audit

> Databricks gives you no native way to answer *"what can this identity access across all my workspaces?"* — this tool does.

[![CI](https://img.shields.io/github/actions/workflow/status/lukaleet/databricks-access-audit/ci.yml?branch=main&label=CI)](https://github.com/lukaleet/databricks-access-audit/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

## The problem

The Account Console shows you one workspace at a time. `INFORMATION_SCHEMA` shows you one metastore at a time. Neither resolves nested group memberships across workspaces. Neither tells you whether a personal grant duplicates what the group already provides. Neither tells you what workspace objects (jobs, clusters, dashboards, pipelines) a principal can reach.

You're a Databricks admin. Your boss walks over and asks:

- *"What can alice@company.com access across all our workspaces?"*
- *"We're offboarding Bob — what exactly does he have direct access to before we deprovision him?"*
- *"Which groups have access to the `main` catalog? Who in those groups has their own redundant grants?"*
- *"Our quarterly access review is due. Can you export who has what and compare it against last quarter?"*

Answering any of these means opening each workspace, clicking through Unity Catalog, filtering by user, checking workspace assignments — then repeating for every workspace. You still can't see nested group inheritance. You still can't see whether a personal grant duplicates what the group already provides.

This tool answers those questions in one command, across all workspaces at once.

## Two modes

| Mode | Entry point | Question it answers |
|---|---|---|
| **Principal audit** | `--principal "alice@example.com"` | What can this user / SP / group access across every workspace? (Unity Catalog grants + workspace object ACLs) |
| **Group audit** | `--group "data-engineers"` | What does this group access? Who in it has redundant personal grants the group already covers? |

`--group` and `--principal` are mutually exclusive. Use `--group` to audit a group's grants and find cleanup opportunities; use `--principal` to reverse-lookup what a specific identity can reach.

### When to use this tool

| Scenario | Mode | Key flags |
|---|---|---|
| **Offboarding** — pull everything before deprovisioning | `--principal` | `--scan-workspace-objects --output csv` |
| **Access review** — export permissions, compare to last quarter | either | `--output csv --baseline last_quarter.json` |
| **Incident response** — map what a compromised identity can reach | `--principal` | `--escalation-check --scan-workspace-objects` |
| **Permission hygiene** — find redundant personal grants, generate cleanup SQL | `--group` | `--revoke-script` |
| **Stale access** — flag grants with no recorded activity | `--group` | `--stale-days 90 --sql-warehouse-id ...` |
| **Compliance snapshot** — prove permissions haven't drifted | either | `--save-snapshot` / `--baseline` |

## Prerequisites

**Python:** 3.9 or later.

**Databricks account:** Unity Catalog must be enabled. The tool uses the Account API and the per-workspace Unity Catalog API — it does **not** scan Hive Metastore or workspace-local permissions.

**Service Principal permissions:** The SP running the audit requires elevated access at three distinct levels:

| Level | Required role / privilege | Why |
|---|---|---|
| **Databricks account** | Account Admin | Required to call the SCIM API (list groups, users, SPs), list workspaces, and read workspace permission assignments — all account-level endpoints enforce Account Admin |
| **Each workspace** | Workspace Admin (recommended) or Workspace User | The SP must be assigned to each workspace it will scan; Workspace Admin is the safest choice since some permission assignment APIs are not visible to plain users |
| **Unity Catalog** | Metastore Admin, or `MANAGE` on every catalog to audit | The `GET /permissions/catalog/{name}` endpoint (and the equivalent schema/table endpoints) requires either Metastore Admin or `MANAGE` on the securable — `BROWSE` or `SELECT` are not sufficient to read grant lists |

The simplest setup that is guaranteed to work: grant the SP **Account Admin**, add it to each workspace as **Workspace Admin**, and assign it **Metastore Admin**. Scoping to minimum required permissions is possible but requires granting `MANAGE` on every individual catalog, which is difficult to maintain across a large account.

## Installation

The package is not yet published to PyPI. Install from source:

```bash
git clone https://github.com/lukaleet/databricks-access-audit.git
cd databricks-access-audit

# Core install (raw HTTP client only - no extra dependencies beyond requests)
pip install -e .

# Recommended: include the Databricks SDK for automatic auth and retries
pip install -e ".[sdk]"

# Full development install
pip install -e ".[sdk,dev]"
```

### Client backends

The tool ships two interchangeable API backends, selected automatically by `create_client()`:

| Client | Requires | Auth | Pagination | Retries |
|---|---|---|---|---|
| `DatabricksAPIClient` | `requests` (always included) | Manual OAuth + per-host token cache | Manual SCIM page walking | Exponential backoff (configurable) |
| `DatabricksSDKClient` | `databricks-sdk` (optional) | Automatic via SDK | Automatic iterators | Built-in SDK retries |

`create_client()` returns `DatabricksSDKClient` when `databricks-sdk` is installed, and falls back to `DatabricksAPIClient` otherwise. Pass `prefer_sdk=False` or `--no-sdk` to force the raw HTTP backend.

## Quick Start

### Credentials

All three credential flags can be set as environment variables:

```bash
export DATABRICKS_CLIENT_ID="your-sp-client-id"
export DATABRICKS_CLIENT_SECRET="your-sp-secret"
export DATABRICKS_ACCOUNT_ID="your-account-id"
```

### CLI - Principal Audit

```bash
# What can alice access across all workspaces?
databricks-access-audit --principal "alice@example.com" --cloud azure

# Include workspace object ACLs (jobs, clusters, dashboards, pipelines, ...)
databricks-access-audit \
    --principal "alice@example.com" \
    --cloud azure \
    --scan-workspace-objects \
    --escalation-check

# Deep scan including schema and table grants, export to CSV for a review
databricks-access-audit \
    --principal "alice@example.com" \
    --cloud azure \
    --scan-schemas \
    --scan-tables \
    --scan-workspace-objects \
    --output csv > alice_access_$(date +%F).csv

# Audit a service principal by display name or application ID
databricks-access-audit --principal "ETL-Bot" --cloud azure

# Audit a group (shows what it can access, not who is in it)
databricks-access-audit --principal "data-engineers" --cloud azure
```

### CLI - Group Audit

```bash
# Scan all workspaces, catalog level only
databricks-access-audit --group "data-engineers" --cloud azure

# Deep scan including schema and table grants, with REVOKE script
databricks-access-audit \
    --group "data-engineers" \
    --cloud azure \
    --scan-schemas \
    --scan-tables \
    --revoke-script

# JSON output (progress lines go to stdout before the JSON block)
databricks-access-audit --group "data-engineers" --output json

# Scan specific workspaces instead of all discovered ones
databricks-access-audit \
    --group "data-engineers" \
    --workspace-urls "https://adb-123.azuredatabricks.net,https://adb-456.azuredatabricks.net"

# Force raw HTTP client even when databricks-sdk is installed
databricks-access-audit --group "data-engineers" --no-sdk
```

### All CLI flags

```
Credentials (or set via env vars):
  --client-id          DATABRICKS_CLIENT_ID
  --client-secret      DATABRICKS_CLIENT_SECRET
  --account-id         DATABRICKS_ACCOUNT_ID

Target (mutually exclusive):
  --group NAME         Display name of the group to audit
  --principal ID       User email, SP app-ID/display name, or group name

Scan scope:
  --cloud              azure | aws | gcp  (default: azure)
  --workspace-urls     Comma-separated URLs; omit to scan all discovered workspaces
  --scan-schemas       Also scan schema-level grants
  --scan-tables        Also scan table/view-level grants (implies --scan-schemas)
  --scan-workspace-objects
                       Scan workspace-level object permissions across 13 types:
                       jobs, clusters, cluster_policies, pipelines, sql_warehouses,
                       sql_queries, sql_alerts, lakeview_dashboards, genie_spaces,
                       mlflow_experiments, registered_models, serving_endpoints, apps.
                       Off by default — adds significant API calls per workspace.
  --workspace-object-types LIST
                       Comma-separated subset of the 13 types to scan.
                       Default: all 13 types.
  --workers N          Parallel threads for workspace/schema/table scanning
                       (default: 8; set to 1 for sequential)

Output:
  --output             text | json | csv  (default: text)
  --revoke-script      Print REVOKE SQL for redundant grants (group audit only)

Snapshot / diff:
  --save-snapshot PATH Save a timestamped JSON snapshot of this run to PATH.
  --baseline PATH      Compare this run against a previous snapshot at PATH
                       and print what changed (new grants, removed grants,
                       new/removed members).  Compatible with all --output
                       formats.

Permission elevation:
  --auto-elevate       Temporarily grant the audit SP Workspace Admin on any
                       workspace where it lacks that role, then restore the
                       prior state after the audit completes (success or
                       failure).  Requires Account Admin.  Metastore Admin
                       must still be granted manually.
  --dry-run-elevation  Preview which workspaces would be elevated without
                       writing any permission changes.  Implies --auto-elevate.

Security analysis:
  --escalation-check   (principal audit) Flag ALL_PRIVILEGES and MANAGE
                       grants inherited transitively through group membership.
  --stale-days N       Flag member-direct catalog grants whose holders have
                       had no recorded activity in system.access.audit for
                       the last N days.  Requires --sql-warehouse-id.
  --sql-warehouse-id   SQL warehouse ID used to query system.access.audit.
  --sql-workspace-url  Workspace URL whose audit table to query (defaults to
                       first discovered workspace).
  --check-local-groups Scan workspace SCIM directories and flag groups that
                       exist only at workspace level (legacy local groups not
                       yet migrated to account SCIM).

Client:
  --no-sdk             Force raw HTTP client even if databricks-sdk is installed
  --max-retries        Retry attempts on 429/5xx (default: 5; raw client only)
  --retry-base-delay   Base delay in seconds (default: 1.0)
  --retry-max-delay    Maximum delay cap in seconds (default: 60.0)
```

## Just-in-Time Permission Elevation

Getting Workspace Admin on every workspace is a hard prerequisite for a full audit but granting it permanently can be undesirable. The `--auto-elevate` flag automates the lifecycle:

1. **Before the audit** — for each workspace where the SP lacks Workspace Admin, the tool calls the Account API to grant it temporarily.
2. **During the audit** — all workspace and Unity Catalog APIs are called with Workspace Admin in place.
3. **After the audit** — regardless of whether the audit succeeded or failed, the tool restores each workspace to its prior state:
   - If the SP had **no assignment** before elevation, the assignment is **deleted**.
   - If the SP had a **USER-level** assignment before elevation, it is **restored to USER**.

This cleanup guarantee is implemented as a context manager `__exit__`, so it runs unconditionally even if the audit raises an exception.

### Usage

```bash
# Elevate automatically, then restore
databricks-access-audit --group "data-engineers" --cloud azure --auto-elevate

# Preview which workspaces would be elevated (no writes)
databricks-access-audit --group "data-engineers" --cloud azure --dry-run-elevation
```

### Scope and limitations

| What is managed | How |
|---|---|
| **Workspace Admin** | Granted temporarily per-workspace; restored after the audit |
| **Metastore Admin** | **Not managed.** Must be granted manually before running the tool |
| **Account Admin** | **Not managed.** Hard prerequisite — must be in place before using `--auto-elevate` |

The SP can only be elevated on workspaces discovered through the Account API (workspaces with a known numeric workspace ID). Workspaces supplied via `--workspace-urls` have no known ID and are skipped with a warning — the SP must already be a Workspace Admin on those.

If cleanup fails (e.g. due to a network error), the tool:
- Logs an ERROR with explicit manual revocation instructions (workspace name, SP SCIM ID, and the `DELETE /permissionassignments/principals/{id}` endpoint to call).
- Raises `RuntimeError` so the failure is never silently swallowed.

### Programmatic usage

```python
from databricks_access_audit import create_client, PermissionElevator, WorkspaceDiscovery

client = create_client(cloud="azure", client_id="...",
                       client_secret="...", account_id="...")
workspaces = WorkspaceDiscovery(client, "azure").discover()

with PermissionElevator(client, sp_application_id="<client-id>") as elev:
    for ws in workspaces:
        elev.ensure_workspace_admin(ws.workspace_id, ws.workspace_name)
    # ... run audit ...
# prior workspace assignments are restored here, success or failure
```

Dry-run mode (preview only, no writes):

```python
with PermissionElevator(client, sp_application_id="<client-id>", dry_run=True) as elev:
    for ws in workspaces:
        elev.ensure_workspace_admin(ws.workspace_id, ws.workspace_name)
```

## Python API

### Principal audit

```python
from databricks_access_audit import create_client, PrincipalAuditor, WorkspaceDiscovery

client = create_client(cloud="azure", client_id="...",
                       client_secret="...", account_id="...")

auditor = PrincipalAuditor(
    client,
    workspace_discovery=WorkspaceDiscovery(client, "azure"),
    cloud_provider="azure",
)

result = auditor.audit("alice@example.com", scan_schemas=True)

for g in result.groups:
    tag = "direct" if g.is_direct else "transitive"
    print(f"  {g.group_name} ({tag}) - path: {' → '.join(g.path)}")

for r in result.workspace_roles:
    print(f"  {r.workspace_name}: {r.permission_level} via {r.via_group}")

for p in result.permissions:
    print(f"  [{p.securable_type}] {p.securable_name}: {', '.join(p.privileges)} via {p.via_group}")

if result.dead_end_groups:
    print(f"  Dead-end groups (no workspace access): {result.dead_end_groups}")
```

### Group audit

```python
from databricks_access_audit import (
    create_client,
    GroupMembershipResolver,
    WorkspaceDiscovery,
    CatalogPermissionScanner,
    RedundancyDetector,
    RevokeScriptGenerator,
)

client = create_client(
    cloud="azure",
    client_id="...",
    client_secret="...",
    account_id="...",
)

resolver = GroupMembershipResolver(client)
node = resolver.resolve_group("data-engineers")
members = resolver.get_all_members_flat(node)  # {"users": [...], "service_principals": [...]}

workspaces = WorkspaceDiscovery(client, "azure").discover()

scanner = CatalogPermissionScanner(client, resolver)
grants = scanner.scan_all_workspaces(workspaces, "data-engineers", node, members)

redundancy = RedundancyDetector().detect_redundancy(grants, "data-engineers")
print(RevokeScriptGenerator.generate(redundancy, include_partial=True))
```

## Databricks Notebook

Import `Databricks Access Audit.ipynb` into your workspace. The first cell installs the package — adjust the path to match your workspace location and run it, then **Run All**.

```python
# If the package is cloned into your Databricks workspace:
%pip install -q "/Workspace/Users/your.name@company.com/databricks-access-audit-tool[sdk]"

# Once published to PyPI:
# %pip install -q "databricks-access-audit[sdk]"
```

> Do **not** use `pip install -e` (editable mode) on a Databricks cluster — the cluster's setuptools may not support PEP 660 and editable installs serve no purpose on a cluster where you are not editing the source.

### Widgets

| Widget | Type | Description |
|---|---|---|
| `secret_scope` | text | *(optional)* Databricks secret scope whose keys `client_id`, `client_secret`, `account_id` take priority over plain-text widgets and environment variables |
| `client_id` | text | Service Principal application (client) ID |
| `client_secret` | text | Service Principal secret |
| `account_id` | text | Databricks account ID |
| `cloud` | dropdown | `azure` / `aws` / `gcp` |
| `target_group` | text | Group display name to audit |
| `principal_identifier` | text | *(optional)* User email, SP name/app-ID, or group name for the principal reverse-lookup |
| `workspace_urls` | text | *(optional)* Comma-separated workspace URLs; blank to scan all |
| `scan_schemas` | dropdown | `true` / `false` |
| `scan_tables` | dropdown | `true` / `false` |
| `scan_workspace_objects` | dropdown | `true` / `false` — scan 13 workspace object types (jobs, clusters, pipelines, SQL, Genie, MLflow, serving endpoints, apps) |
| `workspace_object_types` | text | Comma-separated object types; blank = all 13 types |
| `workers` | text | Number of parallel threads for workspace/schema/table scanning (default: `8`) |
| `auto_elevate` | dropdown | `true` / `false` — temporarily grant Workspace Admin to the audit SP |
| `dry_run_elevation` | dropdown | `true` / `false` — log elevation actions without applying them |
| `escalation_check` | dropdown | `true` / `false` — flag `ALL_PRIVILEGES` / `MANAGE` grants (principal audit) |
| `stale_days` | text | Stale-grant threshold in days; `0` disables the check |
| `sql_warehouse_id` | text | SQL warehouse ID for stale grant queries |
| `sql_workspace_url` | text | Workspace URL used for stale grant queries |
| `check_local_groups` | dropdown | `true` / `false` — detect workspace-local groups not in account SCIM |
| `save_snapshot` | text | *(optional)* Path to write a JSON snapshot of this audit run |
| `baseline_snapshot` | text | *(optional)* Path to a prior snapshot; produces a diff instead of a full report |
| `export_delta_path` | text | *(optional)* Delta table path for historical export (e.g. `abfss://container@account.dfs.core.windows.net/audit`) |

### Output DataFrames - Group Audit

| DataFrame | Contents |
|---|---|
| `df_grants` | All catalog-level grants (direct, upstream, member-direct) |
| `df_membership` | Users and SPs with IdP-sync source and full inheritance paths |
| `df_redundancy` | Redundancy analysis with revoke recommendations |
| `df_schema_grants` | Schema-level grants (populated when `scan_schemas=true`) |
| `df_table_grants` | Table/view-level grants (populated when `scan_tables=true`) |
| `df_top_members` | Members ranked by personal grant count, with redundancy level — the cleanup shortlist |
| `df_stale` | Member-direct grants with no recent audit-log activity (when `stale_days>0`) |
| `df_local_groups` | Workspace-local groups absent from account SCIM (when `check_local_groups=true`) |
| `df_workspace_objects` | Workspace object ACL grants across all 13 types (when `scan_workspace_objects=true`) |
| `_revoke_sql` | Auto-generated REVOKE SQL script (string) |

### Output DataFrames - Principal Audit

| DataFrame | Contents |
|---|---|
| `df_pa_groups` | All group memberships (direct + transitive) with full inheritance path |
| `df_pa_ws` | Workspace access roles with the source group |
| `df_pa_perms` | UC permissions (catalog/schema/table) with granting group and workspace |
| `df_escalation` | `ALL_PRIVILEGES` / `MANAGE` escalation findings (when `escalation_check=true`) |
| `df_pa_workspace_objects` | Workspace object ACL grants across all 13 types (when `scan_workspace_objects=true`) |

### Delta export

When `export_delta_path` is set, all DataFrames are appended to partitioned Delta tables under that path with `audit_timestamp` and `target_group` columns added. This supports incremental audit history and change tracking over time.

## Output Reference

### CLI - JSON (principal audit)

```json
{
  "principal": "Alice Smith",
  "principal_type": "USER",
  "timestamp": "2025-01-15T10:30:00",
  "groups": [
    {"name": "data-engineers", "direct": true,  "path": ["alice@example.com", "data-engineers"]},
    {"name": "all-data-team",  "direct": false, "path": ["alice@example.com", "data-engineers", "all-data-team"]}
  ],
  "workspace_roles": [
    {"workspace": "prod-ws", "permission": "USER", "via_group": "data-engineers"}
  ],
  "permissions": [
    {"type": "CATALOG", "name": "main", "privileges": ["USE_CATALOG", "SELECT"],
     "via_group": "data-engineers", "workspace": "prod-ws"}
  ],
  "dead_end_groups": ["compliance-readers"],
  "workspace_object_permissions": [
    {"object_type": "jobs", "object_name": "nightly-etl", "workspace": "prod-ws",
     "permission_level": "CAN_MANAGE", "grant_source": "DIRECT", "principal": "alice@example.com"}
  ]
}
```

### CLI - JSON (group audit)

```json
{
  "group": "data-engineers",
  "timestamp": "2025-01-15T10:30:00+00:00",
  "users": 12,
  "service_principals": 2,
  "catalog_grants": 8,
  "schema_grants": 0,
  "table_grants": 0,
  "full_redundancy": 3,
  "partial_redundancy": 1,
  "top_members": [
    {"principal": "alice@example.com", "personal_grants": 3, "redundancy": "Full"},
    {"principal": "bob@example.com",   "personal_grants": 1, "redundancy": "Partial"}
  ]
}
```

## Grant Classification

Each grant on a catalog, schema, or table is classified relative to the target group or principal:

| Classification | Meaning |
|---|---|
| **Direct** | The target group or principal itself holds this grant |
| **Upstream** | A parent (ancestor) group of the target holds this grant |
| **Member Direct** | An individual user or SP within the target group has a personal grant |

Principal matching handles backtick-quoted names, case-insensitive email addresses, display names, and service principal application IDs.

### Azure AD B2B guest users (Azure only)

Azure AD B2B guest users have **two** workspace SCIM records with different `userName` values:

| Record | `userName` | Used for |
|---|---|---|
| Account-synced | `alice@gmail.com` (the invitation email) | SCIM identity, group memberships |
| Azure AD guest | `alice_gmail.com#EXT#@tenant.onmicrosoft.com` (the B2B guest UPN) | Workspace object ACLs |

The principal audit automatically resolves both identities by searching workspace SCIM using the account `externalId` (shared by both records). The guest UPN is added as an alias so workspace object ACL entries stored under the B2B identity are correctly attributed to the principal.

## Redundancy Detection

Redundancy is computed at the **catalog level**. Member-direct grants are compared against the group's effective privileges after privilege hierarchy expansion (e.g. `ALL_PRIVILEGES` implies `SELECT`, `MODIFY` implies `SELECT`):

| Level | Meaning | Recommended action |
|---|---|---|
| **Full** | Every member privilege is covered by the group | Safe to REVOKE — `--revoke-script` generates the SQL |
| **Partial** | Some overlap, some privileges unique to the member | Review: the tool lists which privileges are redundant and which are unique |
| **None** | No overlap | No action needed |

The `--revoke-script` flag generates copy-paste REVOKE SQL for both full and partial redundancy findings.

## Architecture

```
databricks_access_audit/
├── __init__.py            # Public API exports
├── __main__.py            # python -m entry point
├── cli.py                 # argparse CLI (--group / --principal modes)
├── client.py              # AuditClient protocol, DatabricksAPIClient, create_client()
├── sdk_client.py          # DatabricksSDKClient (optional - requires databricks-sdk)
├── models.py              # All dataclasses and enums
├── group_resolver.py      # Recursive SCIM walker with bulk pre-fetch and caching
├── workspace.py           # Multi-cloud workspace discovery and URL resolution
├── catalog_scanner.py     # Catalog-level permission scanning
├── schema_scanner.py      # Schema-level permission scanning
├── table_scanner.py       # Table/view-level permission scanning
├── _classification.py     # classify_grant() and build_member_lookups() shared helpers
├── redundancy.py          # Privilege hierarchy expansion and redundancy detection
├── revoke.py              # REVOKE SQL generation from RedundancyResult objects
├── principal_auditor.py   # BFS reverse-lookup from user/SP/group
├── elevate.py             # Just-in-time Workspace Admin elevation with cleanup guarantee
├── escalation.py          # ALL_PRIVILEGES / MANAGE escalation detection
├── stale_checker.py       # Stale grant detection via system.access.audit SQL
├── local_groups.py        # Workspace-local (legacy) SCIM group detection
├── workspace_object_scanner.py  # Workspace-level ACL scanning (13 types)
├── csv_output.py          # CSV serialisation for group and principal audit results
└── snapshot.py            # Snapshot build/save/load and delta comparison
```

**Client protocol:** `AuditClient` is a structural `Protocol` in `client.py`. Both `DatabricksAPIClient` and `DatabricksSDKClient` satisfy it — all scanners, resolvers, and the auditor accept either backend without modification.

**SCIM performance:** `GroupMembershipResolver` bulk-fetches all users and service principals in two paginated calls before resolving individual members, avoiding N+1 API calls. For accounts with fewer than ~10 000 users this is significantly faster than per-member lookups.

## Identity Source Tagging (Internal vs. IdP-Synced)

Every user, service principal, and group in Databricks has an origin: either it was created directly inside Databricks (*Databricks-managed / internal*) or it was provisioned by an external identity provider via SCIM (*IdP-synced / external*).

The tool reads the SCIM `externalId` field — the standard SCIM indicator for IdP-provisioned principals — and tags every member accordingly.

| Source | Indicator | Examples |
|---|---|---|
| **IdP-synced** (`external`) | `externalId` present and non-empty | Users/groups from Azure Entra ID, Okta, AWS IAM Identity Center, OneLogin |
| **Databricks-managed** (`internal`) | `externalId` absent or empty | Accounts created in the Databricks UI, OAuth service principals, programmatically created SPs |

### Group audit output

```
  Users: 12 (8 IdP-synced, 4 Databricks-managed)  |  SPs: 2 (0 IdP-synced, 2 Databricks-managed)
```

JSON output adds `users_external`, `users_internal`, `sps_external`, `sps_internal` to the group audit result.

### Principal audit output

```
  Principal: alice@example.com (USER, external)

  Group memberships (3, 2 IdP-synced, 1 Databricks-managed):
    * data-engineers (direct, external)
    - all-data-team (transitive, external)
    - local-admins (transitive, internal)
```

JSON output adds `"source": "external"/"internal"` to each group in the `groups` array and a top-level `"principal_source"` field.

### Why this matters

- **Shadow accounts:** Internal (Databricks-managed) users that don't correspond to any IdP identity may be orphaned service accounts, test accounts, or users who bypassed the provisioning process.
- **Off-boarding gaps:** If an IdP user was removed from the IdP but their Databricks account wasn't deprovisioned, they'll appear as `internal` (no longer externally managed) — exactly the accounts that matter during an access review.
- **Compliance:** Many security policies require that all human users be provisioned through the corporate IdP. Internal users are exceptions that need justification.

### Python API

The `source` property is available on `GroupMember`, `GroupNode`, `GroupMembership`, and the `principal_source` property on `PrincipalAuditResult`:

```python
from databricks_access_audit import PrincipalSource

node = resolver.resolve_group("data-engineers")
members = resolver.get_all_members_flat(node)

external = [u for u in members["users"] if u.source == PrincipalSource.EXTERNAL]
internal = [u for u in members["users"] if u.source == PrincipalSource.INTERNAL]
print(f"{len(external)} IdP-synced, {len(internal)} Databricks-managed")
```

## Privilege Escalation Detection

The `--escalation-check` flag adds a security pass to the principal audit. After collecting all effective permissions it flags any grant that contains `ALL_PRIVILEGES` or `MANAGE` — the two privileges that represent meaningful escalation vectors in Unity Catalog:

| Privilege | Risk |
|---|---|
| `ALL_PRIVILEGES` | Grants unrestricted read/write/admin access to the securable and everything beneath it |
| `MANAGE` | Grants the ability to add and remove grants on the securable — can be used to self-escalate or escalate other principals |

```bash
databricks-access-audit --principal "alice@example.com" --cloud azure --escalation-check
```

Output (text):
```
  Escalation risks (2):
    ! RISK [CATALOG] main: ALL_PRIVILEGES via data-engineers (transitive)
    ! RISK [CATALOG] staging: MANAGE via all-admins (transitive)
```

Output (JSON) adds an `"escalation_findings"` array to the principal audit result.

**What it does not cover:** workspace-level admin roles (`WORKSPACE_ADMIN`) are already visible in the workspace roles section. Databricks account-level admin is out of scope for the Unity Catalog scan.

## Stale Grant Detection

The `--stale-days N` flag cross-references current member-direct catalog grants against `system.access.audit` — the Unity Catalog system table that records every API call, SQL command, and data-access event. Any grant holder with no recorded activity in the last N days is flagged as potentially stale.

### Prerequisites

- System tables must be enabled for the account (the `system` catalog must be visible in the metastore).
- The audit SP must have `SELECT` on `system.access.audit` (requires Metastore Admin or explicit grant).
- A **SQL warehouse** with access to the system catalog must be available.

### Usage

```bash
# Flag grants with no activity in 90 days
databricks-access-audit \
    --group "data-engineers" \
    --cloud azure \
    --stale-days 90 \
    --sql-warehouse-id "abc123def456" \
    --sql-workspace-url "https://adb-123.azuredatabricks.net"
```

The tool queries:
```sql
SELECT principal, DATE(MAX(event_time)) AS last_seen_date
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
  AND principal IS NOT NULL
GROUP BY 1
```

Grant holders absent from this result (no activity in the window) are returned as `StaleFinding` objects with `last_access = None`.

**Stale findings do not automatically generate REVOKE SQL.** Review them manually: absence from the audit log may indicate legitimate inactivity (e.g. a batch job that runs quarterly) rather than an unused grant.

## Workspace-Local Group Detection

The `--check-local-groups` flag scans every workspace's SCIM directory and flags groups that exist **only at the workspace level**, absent from the account-level SCIM directory.

Workspace-local groups are a legacy artefact from before Unity Catalog. They cannot hold Unity Catalog grants, are not visible to the Account API, and are invisible to account-level SCIM tooling. If your account still has workspace-local groups, they will not appear in group audit results — this flag helps you find them.

```bash
databricks-access-audit --group "data-engineers" --cloud azure --check-local-groups
```

Output:
```
  Workspace-local groups (2):
    ! legacy-analysts in 'prod-workspace' (5 members) - not in account SCIM
    ! old-read-only in 'staging-workspace' (2 members) - not in account SCIM
```

Works with both `--group` and `--principal` modes, and is available as a standalone Python API:

```python
from databricks_access_audit import LocalGroupChecker, WorkspaceDiscovery

checker = LocalGroupChecker(client)
workspaces = WorkspaceDiscovery(client, "azure").discover()
findings = checker.check_all_workspaces(workspaces)
for f in findings:
    print(f"  {f.group_name} in '{f.workspace_name}' ({f.member_count} members) - workspace-local")
```

## CSV Output

Pass `--output csv` to get audit results as comma-separated values — the format auditors and security leads need to share findings with people who won't run a CLI themselves.

```bash
# Group audit - export all grants to a spreadsheet
databricks-access-audit --group "data-engineers" --cloud azure \
  --output csv > grants_$(date +%F).csv

# Principal audit - export all permissions
databricks-access-audit --principal "alice@example.com" --cloud azure \
  --output csv > alice_permissions.csv
```

**Group audit CSV** contains up to three sections:
- **Grants table** — one row per grant (catalog, schema, or table level) with columns: `securable_type`, `workspace`, `securable_name`, `principal`, `principal_type`, `privileges` (pipe-separated), `grant_source`, `inherited_from`.
- **Redundancy table** (appended after a blank row when redundancies are found) — one row per redundant personal grant with `redundancy_level` and `recommendation`.
- **Workspace objects table** (appended when `--scan-workspace-objects` is used) — one row per workspace ACL grant with `object_type`, `object_id`, `object_name`, `workspace`, `principal`, `permission_level`, `grant_source`.

**Principal audit CSV** contains:
- **Permissions table** — one row per effective Unity Catalog permission with `securable_type`, `securable_name`, `privileges`, `via_group`, `workspace`.
- **Escalation table** (appended when `--escalation-check` is used) — one row per escalation risk.

Combine with other flags — `--scan-schemas --scan-tables` expands scope before export, `--escalation-check` adds the escalation section to a principal audit CSV.

---

## Diff / Delta Mode

Every audit run can save a timestamped JSON snapshot to disk. Pass a previous snapshot as `--baseline` and the tool reports exactly what changed: new grants, removed grants, new or removed group members.

This is the SOC 2 / ISO 27001 evidence workflow: *"Prove permissions haven't drifted since the last quarterly review."*

```bash
# Save the current state
databricks-access-audit --group "data-engineers" --cloud azure \
  --save-snapshot snapshots/data-engineers_$(date +%F).json

# Three months later - run again and compare
databricks-access-audit --group "data-engineers" --cloud azure \
  --baseline snapshots/data-engineers_2025-01-01.json
```

Output when changes are found:
```
============================================================
  Diff: data-engineers (group)
  Baseline:  2025-01-01T00:00:00+00:00
  Current:   2025-04-01T12:34:56+00:00
============================================================

  Grants added (1):
    + [CATALOG] main - bob@example.com (USE_CATALOG|SELECT)

  Grants removed (1):
    + [CATALOG] staging - carol@example.com (MODIFY)

  Members added (1):
    + Bob Jones (User)
============================================================
```

When nothing has changed:
```
  No changes detected.
```

**Snapshot format:** plain JSON, human-readable without this library. Snapshots are versioned (`"version": "1"`) and safe to store in version control alongside other compliance artefacts.

**Change detection rules:**
- A grant is "added" or "removed" based on a full-field fingerprint — any field change (including privilege modifications) is reported as a removal and addition pair, making every change explicit.
- Member identity is tracked by ID and type only — display-name changes are not flagged as membership churn.

`--output csv` and `--baseline` compose: `--output csv --baseline previous.json` exports the diff as CSV, one row per change, for import into a spreadsheet or SIEM.

`--save-snapshot` and `--baseline` are independent and can be combined in a single run:

```bash
databricks-access-audit --group "data-engineers" --cloud azure \
  --baseline last_quarter.json \
  --save-snapshot snapshots/data-engineers_$(date +%F).json
```

Python API:

```python
from databricks_access_audit import (
    build_group_snapshot, save_snapshot, load_snapshot, diff_snapshots,
)

# After running a group audit
snap = build_group_snapshot("data-engineers", members, catalog_grants, schema_grants, table_grants)
save_snapshot(snap, "snapshots/data-engineers_2025-04-01.json")

# Compare against a previous snapshot
baseline = load_snapshot("snapshots/data-engineers_2025-01-01.json")
diff = diff_snapshots(baseline, snap)
if diff.has_changes:
    print(f"  {len(diff.grants_added)} grants added")
    print(f"  {len(diff.grants_removed)} grants removed")
    print(f"  {len(diff.members_added)} members added")
    print(f"  {len(diff.members_removed)} members removed")
```

---

## When Not to Use This Tool

If you only need to query permissions within a **single workspace**, Databricks Unity Catalog provides built-in system views you can query directly via SQL, without any external tooling:

```sql
-- Catalog-level grants in the current workspace
SELECT * FROM system.information_schema.catalog_privileges
WHERE grantee = 'data-engineers';

-- Schema-level grants
SELECT * FROM system.information_schema.schema_privileges
WHERE grantee = 'data-engineers';

-- Table-level grants
SELECT * FROM system.information_schema.table_privileges
WHERE grantee = 'data-engineers';
```

Use this tool when you need what `INFORMATION_SCHEMA` does not provide:

- **Cross-workspace aggregation** — scan all workspaces from a single entry point
- **Recursive group membership resolution** — nested groups, users, and SPs via SCIM
- **Upstream group detection** — grants inherited through ancestor groups
- **Redundancy detection** — personal grants that duplicate what the group already provides
- **REVOKE script generation** — automated cleanup recommendations
- **Principal reverse lookup** — map any identity to all accessible resources across the account

## Known Limitations

- **Unity Catalog only.** The tool reads grants via the UC permission API and workspace object ACLs via the permissions REST API. Hive Metastore permissions and workspace-local table ACLs are not scanned.
- **Workspace object scanning is opt-in.** `--scan-workspace-objects` covers 13 object types: jobs, clusters, cluster policies, DLT pipelines, SQL warehouses, SQL queries, SQL alerts, Lakeview dashboards, Genie spaces, MLflow experiments, registered models (workspace registry), model serving endpoints, and Databricks Apps. Notebook ACLs are not covered — listing them requires recursively walking the workspace file tree (unbounded API calls).
- **Redundancy detection is catalog-level.** Schema and table grants are reported but not included in the redundancy/REVOKE analysis.
- **Stale detection is account-wide, not per-catalog.** `system.access.audit` does not always record per-catalog or per-object access; the stale check flags principals with no *any* recorded activity, which is a conservative but imprecise signal.
- **Escalation detection covers UC privileges only.** `WORKSPACE_ADMIN` escalation through group membership is visible in the workspace roles section but not scored as an escalation finding.
- **Identity-federation workspace limitation.** `/workspaces/{id}/permissionassignments` only returns explicit assignments. Principals who access a workspace solely through a built-in group like "account users" (no explicit assignment) will show no workspace roles, but the tool still scans their workspace object permissions using all discovered workspaces as a fallback.

## Multi-Cloud Support

| Cloud | Account host | Workspace domain |
|---|---|---|
| Azure | `accounts.azuredatabricks.net` | `.azuredatabricks.net` |
| AWS | `accounts.cloud.databricks.com` | `adb-<workspace-id>.cloud.databricks.com` |
| GCP | `accounts.gcp.databricks.com` | `.gcp.databricks.com` |

For AWS workspaces, the tool prefers the `deployment_url` field returned by the Account API (the canonical `adb-<id>` format) and falls back to constructing from `workspace_id` when that field is absent.

Only `RUNNING` workspaces are scanned. Workspaces in `NOT_RUNNING`, `PROVISIONING`, `FAILED`, `BANNED`, `CANCELLING`, or `DELETED` state are automatically skipped.

## Development

```bash
pip install -e ".[sdk,dev]"

# Run all tests
pytest

# Run a single test file
pytest tests/test_catalog_scanner.py

# Run a single test by name
pytest tests/test_redundancy.py::test_full_redundancy

# Lint
ruff check .
```

Tests use the `responses` library for HTTP mocking — no real Databricks connection is required.

## License

Apache 2.0 — see [LICENSE](LICENSE).
