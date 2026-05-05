# Stale Access Detection

A member-direct catalog grant with no recorded activity in 90 days is a risk — the person may have changed roles, left the project, or simply never used the access. `--stale-days` cross-references current grants against `system.access.audit` and flags the quiet ones.

## Prerequisites

- **System tables must be enabled** — the `system` catalog must be visible in the metastore. Enable it in the Account Console under Settings → System tables.
- **The audit SP needs `SELECT` on `system.access.audit`** — grant it via Metastore Admin or directly:
  ```sql
  GRANT SELECT ON system.access.audit TO `your-sp-client-id`;
  ```
- **A SQL warehouse** with access to the system catalog must be running.

## Basic usage

```bash
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "abc123def456"
```

Output:

```
  Stale grants (2, no activity in 90 days):
    ! bob@company.com: SELECT, USE_CATALOG on main
    ! carol@company.com: USE_CATALOG on staging
```

If you have multiple workspaces, specify which one holds your system catalog:

```bash
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "abc123def456" \
  --sql-workspace-url "https://adb-123.azuredatabricks.net"
```

## Export for review

```bash
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "abc123def456" \
  --output csv > stale_$(date +%F).csv
```

The CSV includes `last_access` (last recorded date in the audit log, or blank if no activity at all within the window) and `stale_days` (the threshold you configured).

## Combine with redundancy analysis

Stale detection and redundancy analysis run in the same pass:

```bash
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "abc123def456" \
  --revoke-script \
  --output csv > full_hygiene_$(date +%F).csv
```

A grant that is both stale and redundant is a clear revocation candidate.

## What the query checks

The tool runs a query against `system.access.audit` to find the last recorded activity per principal within the configured window:

```sql
SELECT
  COALESCE(user_identity.email, user_identity.subject_name) AS principal,
  DATE(MAX(event_time)) AS last_seen_date
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
GROUP BY 1
```

Any grant holder absent from this result (no events in the window) is returned as a stale finding with `last_access = None`.

## Interpreting results

!!! warning "Absence of activity is a signal, not proof"
    Stale findings do not automatically generate REVOKE SQL. Some legitimate access patterns are infrequent — a quarterly batch job, an on-call script, a report that runs monthly. Review the finding before acting.

A sensible triage process:

1. Cross-reference with HR/IT to confirm the person is still active
2. Check if there's a job or pipeline running under their identity that you missed
3. If genuinely unused, revoke and document it in the access review record

## Adjusting the threshold

90 days is a common starting point for SOC 2 compliance. Some organisations use 60 days for sensitive catalogs or 180 days for rarely-accessed archives:

```bash
# Sensitive data — tighter window
databricks-access-audit --group "pii-readers" --stale-days 60 ...

# Archive catalog — longer window acceptable
databricks-access-audit --group "archive-readers" --stale-days 180 ...
```

## Python API

```python
from databricks_access_audit import (
    create_client, GroupMembershipResolver, WorkspaceDiscovery,
    CatalogPermissionScanner, StaleGrantChecker,
)

client = create_client(cloud="azure", client_id="...",
                       client_secret="...", account_id="...")
resolver = GroupMembershipResolver(client)
node = resolver.resolve_group("data-engineers")
members = resolver.get_all_members_flat(node)

workspaces = WorkspaceDiscovery(client, "azure").discover()
scanner = CatalogPermissionScanner(client, resolver)
grants = scanner.scan_all_workspaces(workspaces, "data-engineers", node, members)

ws_url = workspaces[0].workspace_url
checker = StaleGrantChecker(
    client,
    workspace_url=ws_url,
    warehouse_id="abc123def456",
    stale_days=90,
)
findings = checker.check_catalog_grants(grants, workspaces[0].workspace_name, ws_url)

for f in findings:
    last = f.last_access or "no activity recorded"
    print(f"{f.principal}: {', '.join(f.privileges)} on {f.catalog_name} — last seen: {last}")
```
