# databricks-group-audit

> Audit Databricks group membership and Unity Catalog permissions across all workspaces in your account.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

## Why?

Databricks admins have no single tool to answer:

- *"What can this group actually access across all workspaces?"*
- *"Are there personal grants that duplicate what the group already provides?"*
- *"Which users have the most individual catalog-level grants?"*

This tool fills that gap.

## What it does

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

### CLI

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

### Python

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

### Databricks Notebook

Import the included `Databricks Group Audit Tool` notebook into your workspace.
Fill in the widgets at the top and **Run All**.

| Widget | Description |
|---|---|
| `secret_scope` | *(optional)* Secret scope with `client_id`, `client_secret`, `account_id` keys |
| `client_id` | Service Principal application (client) ID |
| `client_secret` | Service Principal secret |
| `account_id` | Databricks Account ID (auto-detected if blank) |
| `cloud_provider` | `azure` / `aws` / `gcp` |
| `target_group` | Group display name to audit |
| `workspace_urls` | *(optional)* Comma-separated workspace URLs |
| `scan_schemas` | `true`/`false` |
| `scan_tables` | `true`/`false` |
| `export_delta_path` | *(optional)* Delta path for historical export |
| `max_retries` | Retry attempts for 429/5xx (default: 5) |
| `retry_base_delay` | Base delay in seconds (default: 1.0) |
| `retry_max_delay` | Max delay cap in seconds (default: 60.0) |

## Output DataFrames (Notebook)

| DataFrame | Contents |
|---|---|
| `df_permissions` | All catalog-level grants (direct, upstream, member) |
| `df_membership` | Users & SPs with full inheritance paths |
| `df_inheritance` | Permission source trace |
| `df_redundancy` | Overlap analysis with revoke recommendations |
| `df_schema_grants` | Schema-level grants (when enabled) |
| `df_table_grants` | Table/view-level grants (when enabled) |
| `revoke_sql` | Auto-generated REVOKE cleanup script |

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

## Multi-Cloud Support

| Cloud | Account Host | Workspace Domain |
|---|---|---|
| Azure | `accounts.azuredatabricks.net` | `.azuredatabricks.net` |
| AWS | `accounts.cloud.databricks.com` | `.cloud.databricks.com` |
| GCP | `accounts.gcp.databricks.com` | `.gcp.databricks.com` |

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## License

Apache 2.0
