# Permission Hygiene

Three months ago you removed Bob from `data-engineers`. You were cleaning up — he'd moved to a different team and no longer needed production data access. You updated the group, moved on.

Bob still has access to the production catalog.

It turns out that two years ago, before `data-engineers` had catalog grants of its own, someone gave Bob direct `SELECT` and `USE_CATALOG` on `main`. When the group eventually got those grants, nobody noticed the overlap — it was invisible in the UI. When you removed Bob from the group, his personal grant was untouched. The group removal did nothing.

This is what the group audit finds: personal grants that bypass the group's membership, live in the background, and survive any group changes you make.

---

## Find redundant personal grants

```bash
databricks-access-audit --group "data-engineers" --revoke-script
```

This scans every catalog the group can reach and compares each member's personal grants against what the group itself provides. The redundancy classification tells you how to act:

**Full redundancy** — every personal privilege is already covered by the group. The personal grant is entirely redundant:

```
Top member(s) by personal grants:
  1. bob@company.com   — 2 grant(s)  [Full redundancy]
  2. carol@company.com — 1 grant(s)  [Partial redundancy]
```

**Partial redundancy** — some personal privileges overlap with the group, some don't. Only the overlapping ones are cleanup candidates.

**None** — the personal grant is on a different catalog or covers privileges the group doesn't have. Intentional. Leave it.

---

## Generated REVOKE SQL

With `--revoke-script`, the output includes copy-paste SQL for every redundant grant:

```sql
-- Full redundancy: bob@company.com
REVOKE USE_CATALOG, SELECT ON CATALOG main FROM `bob@company.com`;

-- Partial redundancy: carol@company.com (only the overlapping privileges)
REVOKE SELECT ON CATALOG staging FROM `carol@company.com`;
```

The script targets individuals only — the group grant is untouched. Paste into a SQL editor or run via the Databricks CLI. The group members' access continues through the group; nothing is disrupted.

!!! warning "Review before running"
    Partial redundancy findings may be intentional. Carol might have `MODIFY` on staging for a reason the group doesn't cover. Check the `additional_privileges` column in the CSV export before revoking.

---

## Export for a second opinion

```bash
databricks-access-audit --group "data-engineers" \
  --output csv > data_engineers_$(date +%F).csv
```

The CSV includes `redundancy_level` (`Full`, `Partial`, `None`) and `recommendation` columns. Share it with the team lead for sign-off before running any SQL. The `grant_source` column separates `Direct` group grants, `Upstream` inherited grants, and `Member Direct` personal bypass grants.

---

## Deep scan — schema and table grants

The redundancy analysis operates at catalog level. Schema and table grants are reported separately:

```bash
databricks-access-audit --group "data-engineers" \
  --scan-schemas \
  --scan-tables \
  --output csv > deep_scan_$(date +%F).csv
```

Filter the CSV for `grant_source = Member Direct` — those are the personal grants that bypass the group at any level.

---

## Workspace object ownership

Personal job, cluster, and dashboard ownership is separate from UC grants. Members who own workspace objects directly — instead of through the group — are a handover risk when they leave:

```bash
databricks-access-audit --group "data-engineers" \
  --scan-workspace-objects \
  --output csv > objects_$(date +%F).csv
```

Filter for `grant_source = Direct` and `principal_type = USER`. Jobs or clusters owned personally by an individual should be transferred to a service principal or group so ownership survives team changes.

---

## Catch new personal grants before they accumulate

Schedule a monthly hygiene run in CI that compares against the previous snapshot:

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

The `--baseline` diff flags any new personal grants added since last month. The `--revoke-script` output gives you the cleanup SQL. Run this before they accumulate for two years unnoticed.

---

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
print(f"{len(full)} full redundancy, {len(partial)} partial redundancy")

# Generate REVOKE SQL
print(RevokeScriptGenerator.generate(redundancy, include_partial=True))
```
