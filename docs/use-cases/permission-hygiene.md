# Permission Hygiene

Over time, Databricks accounts accumulate personal grants that duplicate what a group already provides — members given direct catalog access before the group had it, one-off grants that were never cleaned up, or people who moved teams but kept their old permissions. The group audit finds all of it and generates the cleanup SQL.

## Find redundant personal grants

```bash
databricks-access-audit --group "data-engineers" --revoke-script
```

This scans every catalog the group can reach and compares each member's personal grants against the group's effective privileges. Members with overlap are classified:

**Full redundancy** — every personal privilege is already covered by the group. Safe to revoke entirely:

```
Top 3 member(s) by personal grants:
  1. bob@company.com  —  3 grant(s)  [Full redundancy]
  2. carol@company.com  —  2 grant(s)  [Partial redundancy]
  3. dave@company.com  —  1 grant(s)  [None]
```

**Partial redundancy** — some personal privileges are covered, some aren't. Only the overlapping ones are candidates for revocation.

**None** — the personal grant is on a different catalog, or covers privileges the group doesn't have. Leave it alone.

## Generated REVOKE SQL

```sql
-- Full redundancy: bob@company.com
REVOKE USE_CATALOG, SELECT ON CATALOG main FROM `bob@company.com`;

-- Partial redundancy: only the overlapping privileges
REVOKE SELECT ON CATALOG staging FROM `carol@company.com`;
```

The script targets individuals only — the group grant is untouched. Copy-paste into a SQL editor or run via the Databricks CLI.

!!! warning
    Review before running. Partial redundancy members may have the extra privilege for a reason. When in doubt, keep it.

## Export for a second opinion

```bash
databricks-access-audit --group "data-engineers" \
  --output csv > data_engineers_redundancy_$(date +%F).csv
```

The CSV includes `redundancy_level` and `recommendation` columns so a team lead can review offline before you run any SQL.

## Deep scan — schema and table grants

Personal grants at schema or table level aren't included in the redundancy analysis (which operates at catalog level), but they're reported:

```bash
databricks-access-audit --group "data-engineers" \
  --scan-schemas \
  --scan-tables \
  --output csv > deep_scan_$(date +%F).csv
```

Use the `grant_source` column to filter for `Member Direct` rows — those are the personal grants that bypass the group.

## Workspace object ACLs

Personal job, cluster, and dashboard ownership is separate from UC grants. To find members who own workspace objects directly:

```bash
databricks-access-audit --group "data-engineers" \
  --scan-workspace-objects \
  --output csv > objects_$(date +%F).csv
```

Filter the CSV for `grant_source = Direct` and `principal_type = USER` to find individual ownership that should be transferred to the group or a service principal.

## Automate in CI

Schedule a monthly hygiene check that exports the redundancy report and flags new personal grants:

```yaml
- name: Monthly permission hygiene check
  run: |
    databricks-access-audit --group "data-engineers" \
      --baseline snapshots/data-engineers_latest.json \
      --save-snapshot snapshots/data-engineers_$(date +%F).json \
      --revoke-script \
      --output csv > hygiene_$(date +%F).csv
  env:
    DATABRICKS_CLIENT_ID: ${{ secrets.DATABRICKS_CLIENT_ID }}
    DATABRICKS_CLIENT_SECRET: ${{ secrets.DATABRICKS_CLIENT_SECRET }}
    DATABRICKS_ACCOUNT_ID: ${{ secrets.DATABRICKS_ACCOUNT_ID }}
```

The `--baseline` diff catches any new personal grants added since the last run. The `--revoke-script` output gives you ready-to-run SQL for everything already redundant.

## Python API

```python
from databricks_access_audit import (
    create_client, GroupMembershipResolver, WorkspaceDiscovery,
    CatalogPermissionScanner, RedundancyDetector, RevokeScriptGenerator,
)

client = create_client(cloud="azure", client_id="...",
                       client_secret="...", account_id="...")
resolver = GroupMembershipResolver(client)
node = resolver.resolve_group("data-engineers")
members = resolver.get_all_members_flat(node)

workspaces = WorkspaceDiscovery(client, "azure").discover()
scanner = CatalogPermissionScanner(client, resolver)
grants = scanner.scan_all_workspaces(workspaces, "data-engineers", node, members)

redundancy = RedundancyDetector().detect_redundancy(grants, "data-engineers")

full = [r for r in redundancy if r.redundancy_level.value == "Full"]
partial = [r for r in redundancy if r.redundancy_level.value == "Partial"]
print(f"{len(full)} full, {len(partial)} partial redundancy findings")

print(RevokeScriptGenerator.generate(redundancy, include_partial=True))
```
