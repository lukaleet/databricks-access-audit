# Output Formats

## Text (default)

Human-readable console output. Designed for interactive use — summaries at the top, details below.

```
============================================================
  Audit complete for group: data-engineers
  Users: 12 (10 IdP-synced, 2 Databricks-managed)  |  SPs: 2 (2 IdP-synced, 0 Databricks-managed)
  Catalog grants: 8  |  Schema: 24  |  Table: 0
  Redundancy: 1 full, 3 partial
============================================================

  Top 3 member(s) by personal grants:
    1. bob@company.com  —  3 grant(s)  [Full redundancy]
    2. carol@company.com  —  2 grant(s)  [Partial redundancy]
    3. dave@company.com  —  1 grant(s)  [Partial redundancy]
============================================================
```

---

## JSON

Machine-readable JSON written to stdout. All progress messages go to stderr so the output can be piped cleanly.

```bash
databricks-access-audit --group "data-engineers" --output json | jq '.catalog_grants'
```

**Group audit JSON shape:**

```json
{
  "group": "data-engineers",
  "timestamp": "2025-04-01T12:00:00+00:00",
  "users": 12,
  "users_external": 10,
  "users_internal": 2,
  "service_principals": 2,
  "catalog_grants": 8,
  "schema_grants": 24,
  "table_grants": 0,
  "full_redundancy": 1,
  "partial_redundancy": 3,
  "top_members": [
    {"principal": "bob@company.com", "personal_grants": 3, "redundancy": "Full"}
  ],
  "workspace_object_grants": [...],
  "stale_findings": [...],
  "local_group_findings": [...]
}
```

**Principal audit JSON shape:**

```json
{
  "principal": "alice@company.com",
  "principal_type": "USER",
  "timestamp": "2025-04-01T12:00:00+00:00",
  "groups": [
    {"name": "data-engineers", "direct": true, "path": ["alice", "data-engineers"], "source": "external"}
  ],
  "workspace_roles": [
    {"workspace": "prod-workspace", "permission": "USER", "via_group": "data-engineers"}
  ],
  "permissions": [
    {"type": "CATALOG", "name": "main", "privileges": ["USE_CATALOG", "SELECT"], "via_group": "data-engineers", "workspace": "prod-workspace"}
  ],
  "dead_end_groups": [],   // groups with no workspace assignment — may be UC-only access groups
  "principal_source": "external",
  "escalation_findings": [...],
  "workspace_object_permissions": [...]
}
```

---

## CSV

One row per grant, written to stdout. Import into Excel, Google Sheets, or a SIEM.

```bash
databricks-access-audit --group "data-engineers" --output csv > audit.csv
```

**Group audit CSV columns:**

| Column | Description |
|---|---|
| `securable_type` | `CATALOG`, `SCHEMA`, or `TABLE` |
| `securable_name` | Catalog name, `catalog.schema`, or `catalog.schema.table` |
| `workspace_name` | Workspace that holds the grant |
| `principal` | User email, SP name, or group name |
| `principal_type` | `USER`, `SERVICE_PRINCIPAL`, or `GROUP` |
| `privileges` | Comma-separated privilege list |
| `grant_source` | `Direct`, `Upstream`, or `Member Direct` |
| `inherited_from` | Upstream group name (when `grant_source` is `Upstream`) |
| `redundancy_level` | `Full`, `Partial`, or `None` (for `Member Direct` grants) |
| `recommendation` | Plain-English action to take |
| `object_type` | Workspace object type (when `--scan-workspace-objects`) |
| `object_name` | Object name |
| `permission_level` | `CAN_VIEW`, `CAN_RUN`, `CAN_MANAGE`, etc. |

**Diff CSV columns:**

When `--baseline` is set, the CSV contains the change log:

| Column | Description |
|---|---|
| `change_type` | `GRANT_ADDED`, `GRANT_REMOVED`, `MEMBER_ADDED`, `MEMBER_REMOVED` |
| `securable_type` | Grant: catalog/schema/table. Member: `USER`, `SERVICE_PRINCIPAL`, `GROUP` |
| `securable_name` | Grant: object name. Member: display name |
| `principal` | Who has (or had) the grant |
| `privileges` | Privilege list |
| `baseline_timestamp` | When the baseline snapshot was taken |
| `current_timestamp` | When this run was executed |

---

## Snapshot format

Snapshots are plain JSON, readable without this tool, safe to commit to version control.

```json
{
  "version": "1",
  "mode": "group",
  "target": "data-engineers",
  "timestamp": "2025-04-01T12:34:56+00:00",
  "grants": [
    {
      "securable_type": "CATALOG",
      "securable_name": "main",
      "workspace_name": "prod-workspace",
      "principal": "data-engineers",
      "principal_type": "GROUP",
      "privileges": ["SELECT", "USE_CATALOG"],
      "grant_source": "Direct",
      "inherited_from": null
    }
  ],
  "members": {
    "users": [
      {"id": "abc123", "display_name": "Alice", "type": "User", "external_id": "azure-oid"}
    ],
    "service_principals": []
  }
}
```

The `version` field is `"1"`. Future schema changes will be handled with explicit migrations — stored snapshots remain loadable across tool upgrades.
