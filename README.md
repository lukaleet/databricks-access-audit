# databricks-group-audit

> Audit Databricks group membership and Unity Catalog permissions across all workspaces in your account.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

## Why?

Databricks admins have no single tool to answer:

- *"What can this group actually access across all workspaces?"*
- *"Are there personal grants that duplicate what the group already provides?"*
- *"Which users have the most individual catalog-level grants?"*
- *"What can a specific user, SP, or group access across the entire account?"*

This tool fills that gap with two complementary audit modes:

| Mode | Entry point | Question it answers |
|---|---|---|
| **Group audit** | `--group "data-engineers"` | What does this group see, and who has redundant personal grants? |
| **Principal audit** | `--principal "alice@example.com"` | What can this user/SP/group access across all workspaces? |

## What it does

### Group Audit

```
┌────────────────────┐
│  Service Principal │  OAuth client-credentials flow
│  (client_id/secret)│  with retry on 429/5xx
└────────┬───────────┘
         │
         ▼
┌────────────────────┐     ┌──────────────────────┐
│  Account SCIM API  │────▶│  Group Hierarchy Tree │
│  (paginated)       │     │  Users + SPs + Nested │
└────────┬───────────┘     └──────────────────────┘
         │
         ▼
┌────────────────────┐     ┌──────────────────────┐
│  Account API       │────▶│  Workspace List       │
│  /workspaces       │     │  (or explicit URLs)   │
└────────┬───────────┘     └──────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────┐
│  Per-Workspace Unity Catalog API                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Catalogs │─▶│ Schemas  │─▶│ Tables / Views   │  │
│  │ (dedup)  │  │(optional)│  │   (optional)     │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
└────────┬───────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────┐
│  Grant Classification                               │
│  • Direct    → group itself has the grant           │
│  • Upstream  → parent group has the grant           │
│  • Member    → individual user/SP personal grant    │
└────────┬───────────────────────────────────────────┘
         │
         ▼
┌────────────────────┐     ┌──────────────────────┐
│  Redundancy        │────▶│  REVOKE SQL Script   │
│  Detection         │     │  (copy-paste ready)  │
│  (Full / Partial)  │     └──────────────────────┘
└────────────────────┘
```

### Principal Audit (Reverse Lookup)

Starting from a user email, service principal, or group name, walks *upward*
through the group hierarchy to build a complete access map:

```
alice@example.com
├── member of: data-engineers (⭐ direct)
│   ├── workspace: prod-ws (USER)
│   │   └── catalog main → USE_CATALOG, SELECT
│   └── workspace: dev-ws (USER)
│       └── catalog dev → ALL_PRIVILEGES
├── member of: all-data-team (↳ transitive via data-engineers)
│   └── workspace: prod-ws (ADMIN)
│       └── catalog main → ALL_PRIVILEGES
└── member of: compliance-readers (⭐ direct)
    └── ⚠️ no workspace access (dead-end group)
        └── catalog audit_log → SELECT (metastore-level only)
```

The six-step process:

1. **Find principal** — resolve user by email, SP by app-ID or display name, group by name (SCIM filter)
2. **Resolve memberships** — BFS upward through all SCIM groups to find every direct + transitive membership
3. **Discover workspaces** — via Account API or explicit URLs
4. **Map workspace access** — query `/permissionassignments` for each workspace, match against principal + group IDs
5. **Scan UC grants** — for each accessible workspace, scan catalog (optionally schema/table) grants matching the principal's groups
6. **Detect dead ends** — groups the principal belongs to that have no workspace assignment

## Installation

```bash
pip install databricks-group-audit
```

Or install from source:

```bash
git clone https://github.com/yourusername/databricks-group-audit.git
cd databricks-group-audit
pip install -e ".[dev]"
```

## Quick Start

### CLI — Group Audit

```bash
# Set credentials as env vars (or pass via flags)
export DATABRICKS_CLIENT_ID="your-sp-client-id"
export DATABRICKS_CLIENT_SECRET="your-sp-secret"
export DATABRICKS_ACCOUNT_ID="your-account-id"

# Basic audit
databricks-group-audit --group "data-engineers" --cloud azure

# Deep scan with REVOKE script
databricks-group-audit \
    --group "data-engineers" \
    --cloud azure \
    --scan-schemas \
    --scan-tables \
    --revoke-script

# JSON output for CI/CD pipelines
databricks-group-audit --group "data-engineers" --output json

# Scan specific workspaces only
databricks-group-audit \
    --group "data-engineers" \
    --workspace-urls "https://adb-123.azuredatabricks.net,https://adb-456.azuredatabricks.net"
```

### CLI — Principal Audit

```bash
# Audit a user by email
databricks-group-audit --principal "alice@example.com" --cloud azure

# Audit a service principal by app-ID or display name
databricks-group-audit --principal "ETL-Bot" --cloud azure

# Audit a group (reverse: shows what the group can access, not who's in it)
databricks-group-audit --principal "data-engineers" --cloud azure

# Deep scan with JSON output
databricks-group-audit \
    --principal "alice@example.com" \
    --cloud azure \
    --scan-schemas \
    --scan-tables \
    --output json
```

> **Note:** `--group` and `--principal` are mutually exclusive. Use `--group`
> to audit a group's grants and membership; use `--principal` to audit what
> a specific identity can access.

### Python — Group Audit

```python
from databricks_group_audit import (
    DatabricksAPIClient,
    GroupMembershipResolver,
    WorkspaceDiscovery,
    CatalogPermissionScanner,
    RedundancyDetector,
    RevokeScriptGenerator,
)

client = DatabricksAPIClient.for_cloud(
    cloud="azure",
    client_id="...",
    client_secret="...",
    account_id="...",
)

resolver = GroupMembershipResolver(client)
node = resolver.resolve_group("data-engineers")
members = resolver.get_all_members_flat(node)

workspaces = WorkspaceDiscovery(client, "azure").discover()

scanner = CatalogPermissionScanner(client, resolver)
grants = scanner.scan_all_workspaces(workspaces, "data-engineers", node, members)

redundancy = RedundancyDetector().detect_redundancy(grants, "data-engineers")
print(RevokeScriptGenerator.generate(redundancy, include_partial=True))
```

### Python — Principal Audit

```python
from databricks_group_audit import DatabricksAPIClient, PrincipalAuditor
from databricks_group_audit.workspace import WorkspaceDiscovery

client = DatabricksAPIClient.for_cloud(cloud="azure", ...)
ws_disc = WorkspaceDiscovery(client, "azure")
auditor = PrincipalAuditor(client, workspace_discovery=ws_disc, cloud_provider="azure")

result = auditor.audit("alice@example.com", scan_schemas=True)

print(f"Principal: {result.principal_name} ({result.principal_type})")
print(f"Groups:      {len(result.groups)}")
print(f"Workspaces:  {len(result.workspace_roles)}")
print(f"Permissions: {len(result.permissions)}")
print(f"Dead ends:   {result.dead_end_groups}")

# Inspect individual results
for g in result.groups:
    tag = "direct" if g.is_direct else "transitive"
    print(f"  {g.group_name} ({tag}) — path: {' → '.join(g.path)}")

for r in result.workspace_roles:
    print(f"  {r.workspace_name}: {r.permission_level} via {r.via_group}")

for p in result.permissions:
    print(f"  [{p.securable_type}] {p.securable_name}: {', '.join(p.privileges)} via {p.via_group}")
```

### Databricks Notebook

Import the included `Databricks Group Audit Tool` notebook into your workspace.
Fill in the widgets at the top and **Run All**.

The notebook auto-detects the installed package. When `pip install databricks-group-audit`
is available, it imports from the package and skips inline class definitions. Otherwise
it falls back to self-contained inline code — no external dependencies beyond `requests`.

| Widget | Description |
|---|---|
| `secret_scope` | *(optional)* Secret scope with `client_id`, `client_secret`, `account_id` keys |
| `client_id` | Service Principal application (client) ID |
| `client_secret` | Service Principal secret |
| `account_id` | Databricks Account ID (auto-detected if blank) |
| `cloud_provider` | `azure` / `aws` / `gcp` |
| `target_group` | Group display name to audit |
| `principal_identifier` | *(optional)* User email, SP name, or group name for reverse lookup |
| `workspace_urls` | *(optional)* Comma-separated workspace URLs |
| `scan_schemas` | `true`/`false` |
| `scan_tables` | `true`/`false` |
| `export_delta_path` | *(optional)* Delta path for historical export |
| `max_retries` | Retry attempts for 429/5xx (default: 5) |
| `retry_base_delay` | Base delay in seconds (default: 1.0) |
| `retry_max_delay` | Max delay cap in seconds (default: 60.0) |

## Output

### Group Audit DataFrames (Notebook)

| DataFrame | Contents |
|---|---|
| `df_permissions` | All catalog-level grants (direct, upstream, member) |
| `df_membership` | Users & SPs with full inheritance paths |
| `df_inheritance` | Permission source trace |
| `df_redundancy` | Overlap analysis with revoke recommendations |
| `df_schema_grants` | Schema-level grants (when enabled) |
| `df_table_grants` | Table/view-level grants (when enabled) |
| `revoke_sql` | Auto-generated REVOKE cleanup script |

### Principal Audit DataFrames (Notebook)

| DataFrame | Contents |
|---|---|
| `df_principal_groups` | All group memberships (direct + transitive) with inheritance path |
| `df_principal_ws` | Workspace access roles with source group |
| `df_principal_perms` | UC permissions (catalog/schema/table) with granting group and workspace |

### Principal Audit JSON Output (CLI)

```json
{
  "principal": "Alice Smith",
  "principal_type": "USER",
  "timestamp": "2025-01-15T10:30:00",
  "groups": [
    {"name": "data-engineers", "direct": true, "path": ["alice@example.com", "data-engineers"]},
    {"name": "all-data-team", "direct": false, "path": ["alice@example.com", "data-engineers", "all-data-team"]}
  ],
  "workspace_roles": [
    {"workspace": "prod-ws", "permission": "USER", "via_group": "data-engineers"}
  ],
  "permissions": [
    {"type": "CATALOG", "name": "main", "privileges": ["USE_CATALOG", "SELECT"],
     "via_group": "data-engineers", "workspace": "prod-ws"}
  ],
  "dead_end_groups": ["compliance-readers"]
}
```

## Grant Classification

For each catalog (and optionally schema/table), every grant is classified:

| Type | Meaning |
|---|---|
| **Direct** | The target group itself holds this grant |
| **Upstream** | A parent group of the target holds this grant (inherited) |
| **Member Direct** | An individual user or SP *within* the group has a personal grant |

## Redundancy Detection

Member-direct grants are compared against the group's effective privileges
(with hierarchy expansion, e.g. `ALL_PRIVILEGES` implies `SELECT`):

| Level | Meaning | Action |
|---|---|---|
| **Full** | All member privileges covered by group | Safe to REVOKE |
| **Partial** | Some overlap, some unique | Review recommended |
| **None** | No overlap | No action needed |

## Single-Workspace Alternative: INFORMATION_SCHEMA

If you only need to audit permissions within a **single workspace** and don't
need membership correlation or redundancy detection, Databricks Unity Catalog
provides built-in system views you can query directly via SQL:

```sql
-- Catalog-level grants
SELECT * FROM system.information_schema.catalog_privileges
WHERE grantee = 'data-engineers';

-- Schema-level grants
SELECT * FROM system.information_schema.schema_privileges
WHERE grantee = 'data-engineers';

-- Table-level grants
SELECT * FROM system.information_schema.table_privileges
WHERE grantee = 'data-engineers';
```

These views cover the current workspace only. This tool adds value when you need:

- **Cross-workspace aggregation** — scan all workspaces from a single entry point
- **Recursive group membership** — resolve nested groups, users, and service principals via SCIM
- **Upstream group detection** — find grants inherited from parent groups
- **Redundancy detection** — identify personal grants that duplicate what the group already provides
- **REVOKE script generation** — automated cleanup recommendations
- **Principal reverse lookup** — map any identity to all accessible resources across the account

## Multi-Cloud Support

| Cloud | Account Host | Workspace Domain |
|---|---|---|
| Azure | `accounts.azuredatabricks.net` | `.azuredatabricks.net` |
| AWS | `accounts.cloud.databricks.com` | `adb-<id>.cloud.databricks.com` |
| GCP | `accounts.gcp.databricks.com` | `.gcp.databricks.com` |

> **Note:** AWS workspace URLs use the `adb-<workspace-id>` format. The tool
> prefers the `deployment_url` field returned by the Account API and falls
> back to constructing from the workspace ID when unavailable.

## Architecture

```
databricks_group_audit/
├── __init__.py            # Public API exports (v0.2.0)
├── __main__.py            # python -m entry point
├── cli.py                 # argparse CLI (--group / --principal)
├── client.py              # HTTP client with OAuth, retry, pagination
├── models.py              # 18 dataclasses + 4 enums
├── group_resolver.py      # SCIM walking with bulk pre-fetch + caching
├── workspace.py           # Multi-cloud workspace discovery
├── catalog_scanner.py     # Catalog-level permission scanning
├── schema_scanner.py      # Schema-level scanning
├── table_scanner.py       # Table/view-level scanning
├── _classification.py     # Shared classify_grant + build_member_lookups
├── redundancy.py          # Privilege hierarchy + redundancy detection
├── revoke.py              # REVOKE SQL generation
└── principal_auditor.py   # Reverse lookup from user/SP/group
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## License

Apache 2.0
