# Python API

All public symbols are importable directly from `databricks_access_audit`.

```python
from databricks_access_audit import create_client, PrincipalAuditor, ...
```

---

## Client factory

### `create_client(...) → AuditClient`

```python
from databricks_access_audit import create_client

client = create_client(
    cloud="azure",            # "azure" | "aws" | "gcp"
    client_id="...",
    client_secret="...",
    account_id="...",
    prefer_sdk=True,          # use databricks-sdk when available (default True)
    max_retries=5,
    base_delay=1.0,
    max_delay=60.0,
)
```

Returns a `DatabricksSDKClient` when `databricks-sdk` is installed and `prefer_sdk=True`, otherwise a `DatabricksAPIClient` (raw HTTP).

---

## Group audit

### `GroupMembershipResolver`

Resolves a group and its full nested membership tree.

```python
from databricks_access_audit import GroupMembershipResolver

resolver = GroupMembershipResolver(client)
group_node = resolver.resolve_group("data-engineers")
members = resolver.get_all_members_flat(group_node)
# members = {"users": [GroupMember, ...], "service_principals": [GroupMember, ...]}
```

### `CatalogPermissionScanner`

Scans catalog-level Unity Catalog grants across all workspaces.

```python
from databricks_access_audit import CatalogPermissionScanner, WorkspaceDiscovery

ws_disc = WorkspaceDiscovery(client, cloud_provider="azure")
workspaces = ws_disc.discover()

scanner = CatalogPermissionScanner(client, resolver)
catalog_grants = scanner.scan_all_workspaces(
    workspaces, "data-engineers", group_node, members, max_workers=8
)
# Returns List[CatalogGrant]
```

### `SchemaPermissionScanner` / `TablePermissionScanner`

```python
from databricks_access_audit import SchemaPermissionScanner, TablePermissionScanner, WorkspaceInfo

sch_scanner = SchemaPermissionScanner(client)
schema_grants = sch_scanner.scan_schemas(workspace, catalog_name, group_name, members, upstream)

tbl_scanner = TablePermissionScanner(client)
table_grants = tbl_scanner.scan_tables(workspace, catalog_name, schema_name, group_name, members, upstream)
```

### `RedundancyDetector`

Compares member-direct grants against the group's effective privileges.

```python
from databricks_access_audit import RedundancyDetector

detector = RedundancyDetector()
redundancy = detector.detect_redundancy(catalog_grants, "data-engineers")
# Returns List[RedundancyResult]
```

### `RevokeScriptGenerator`

Generates REVOKE SQL for redundant grants.

```python
from databricks_access_audit import RevokeScriptGenerator

sql = RevokeScriptGenerator.generate(redundancy, include_partial=True)
print(sql)
```

---

## Principal audit

### `PrincipalAuditor`

Resolves every workspace and UC permission reachable by a principal.

```python
from databricks_access_audit import PrincipalAuditor, WorkspaceDiscovery

ws_disc = WorkspaceDiscovery(client, cloud_provider="azure")
auditor = PrincipalAuditor(client, workspace_discovery=ws_disc, cloud_provider="azure")

result = auditor.audit(
    identifier="alice@company.com",
    scan_schemas=True,
    scan_workspace_objects=True,
    max_workers=8,
)
# Returns PrincipalAuditResult
```

`result` fields:

| Field | Type | Description |
|---|---|---|
| `principal_name` | `str` | Email or display name |
| `principal_type` | `str` | `USER`, `SERVICE_PRINCIPAL`, or `GROUP` |
| `principal_source` | `PrincipalSource` | `EXTERNAL` (IdP) or `INTERNAL` (Databricks-managed) |
| `groups` | `List[GroupMembership]` | All group memberships (direct and transitive) |
| `workspace_roles` | `List[WorkspaceRole]` | Workspace access assignments |
| `permissions` | `List[EffectivePermission]` | Unity Catalog permissions |
| `workspace_object_grants` | `List[WorkspaceObjectGrant]` | Workspace object ACLs |
| `dead_end_groups` | `List[str]` | Groups with no workspace assignment AND no UC grants — provide nothing to the principal |
| `uc_only_groups` | `List[str]` | Groups with no workspace assignment but with UC grants — intentional fine-grained access pattern |
| `escalation_findings` | `List[EscalationFinding]` | Populated after `detect_escalations()` |

---

## Escalation detection

```python
from databricks_access_audit import detect_escalations

result.escalation_findings = detect_escalations(result)
```

Flags `ALL_PRIVILEGES` and `MANAGE` grants in a `PrincipalAuditResult`.

---

## Workspace object scanning

```python
from databricks_access_audit import WorkspaceObjectScanner

obj_scanner = WorkspaceObjectScanner(client, resolver)
grants = obj_scanner.scan_all_workspaces(
    workspaces, group_name, group_node, members,
    object_types=["jobs", "clusters"],   # None = all 13 types
    max_workers=8,
)
# Returns List[WorkspaceObjectGrant]
```

---

## Stale grant detection

```python
from databricks_access_audit import StaleGrantChecker

checker = StaleGrantChecker(
    client,
    workspace_url="https://adb-xxx.azuredatabricks.net",
    warehouse_id="abc123",
    stale_days=90,
)
findings = checker.check_catalog_grants(catalog_grants, workspace_name, workspace_url)
# Returns List[StaleFinding]
```

Requires `system.access.audit` to be enabled and the audit SP to have `SELECT` on it.

---

## Workspace-local group detection

```python
from databricks_access_audit import LocalGroupChecker

checker = LocalGroupChecker(client)
findings = checker.check_all_workspaces(workspaces)
# Returns List[LocalGroupFinding]
```

---

## Permission elevation

```python
from databricks_access_audit import PermissionElevator

with PermissionElevator(client, sp_client_id="...", dry_run=False) as elevator:
    for ws in workspaces:
        elevator.ensure_workspace_admin(ws.workspace_id, ws.workspace_name)
    # ... run audit ...
# Prior permission state is restored on exit (even on exception)
```

---

## Snapshots

```python
from databricks_access_audit import (
    build_group_snapshot, build_principal_snapshot,
    save_snapshot, load_snapshot, diff_snapshots,
)

# Group mode
snap = build_group_snapshot(group_name, members, catalog_grants, schema_grants, table_grants)
save_snapshot(snap, "snapshots/data-engineers_2025-Q1.json")

# Principal mode
snap = build_principal_snapshot(result)
save_snapshot(snap, "snapshots/alice_2025-Q1.json")

# Diff
baseline = load_snapshot("snapshots/data-engineers_2025-Q1.json")
diff = diff_snapshots(baseline, snap)

if diff.has_changes:
    print(f"{len(diff.grants_added)} added, {len(diff.grants_removed)} removed")
```

---

## CSV output

```python
from databricks_access_audit import write_group_audit_csv, write_principal_audit_csv
from databricks_access_audit.csv_output import write_diff_csv

write_group_audit_csv(catalog_grants, schema_grants, table_grants, redundancy)
write_principal_audit_csv(result, escalation_findings)
write_diff_csv(diff)
```

All three write to `sys.stdout` by default — pipe to a file or redirect in your shell.

---

## Workspace discovery

```python
from databricks_access_audit import WorkspaceDiscovery

ws_disc = WorkspaceDiscovery(client, cloud_provider="azure")
workspaces = ws_disc.discover()              # all workspaces in account
workspaces = ws_disc.discover("https://adb-xxx.azuredatabricks.net")  # explicit
# Returns List[WorkspaceInfo]
```

---

## Data models reference

All models are in `databricks_access_audit.models` and re-exported from the package root.

| Model | Key fields |
|---|---|
| `GroupMember` | `id`, `display_name`, `member_type`, `email`, `external_id`, `source` |
| `GroupNode` | `id`, `display_name`, `direct_users`, `nested_groups`, `external_id` |
| `WorkspaceInfo` | `workspace_id`, `workspace_name`, `workspace_url`, `cloud`, `region` |
| `CatalogGrant` | `catalog_name`, `principal`, `privileges`, `grant_source`, `workspace_name` |
| `SchemaGrant` | `catalog_name`, `schema_name`, `principal`, `privileges`, `grant_source` |
| `TableGrant` | `full_name`, `principal`, `privileges`, `grant_source` |
| `WorkspaceObjectGrant` | `object_type`, `object_name`, `permission_level`, `grant_source`, `workspace_name` |
| `RedundancyResult` | `principal`, `redundancy_level`, `redundant_privileges`, `additional_privileges` |
| `PrincipalAuditResult` | see table above |
| `GroupMembership` | `group_name`, `is_direct`, `path`, `source` |
| `WorkspaceRole` | `workspace_name`, `permission_level`, `via_group` |
| `EffectivePermission` | `securable_type`, `securable_name`, `privileges`, `via_group` |
| `EscalationFinding` | `privilege`, `securable_type`, `securable_name`, `via_group`, `is_transitive` |
| `StaleFinding` | `principal`, `catalog_name`, `privileges`, `last_access`, `stale_days` |
| `LocalGroupFinding` | `group_name`, `workspace_name`, `member_count` |
| `AuditDiff` | `grants_added`, `grants_removed`, `members_added`, `members_removed`, `has_changes` |
