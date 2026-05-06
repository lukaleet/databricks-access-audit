# Stale Access Detection

Alice moved from the data team to engineering eight months ago. Her calendar is full of infrastructure tickets. She hasn't opened a notebook in months.

Her `SELECT` and `USE_CATALOG` grants on the production catalog are still there.

Nobody revoked them because the move happened through an org change, not an offboarding. She's still in `data-engineers` — she was just quietly reassigned. The access never came up because she never tried to use it. It's invisible until something goes wrong: a security review, an audit finding, or an incident where "former data team member" turns up in the audit log accessing production data.

`--stale-days` finds all of this by cross-referencing current grants against `system.access.audit`. Anyone holding a personal catalog grant with no recorded activity in the last N days gets flagged.

---

## Prerequisites

- **System tables must be enabled** — the `system` catalog must be visible in your metastore. Enable it in the Account Console under Settings → System tables.
- **The audit SP needs `SELECT` on `system.access.audit`:**
  ```sql
  GRANT SELECT ON system.access.audit TO `your-sp-client-id`;
  ```
- **A running SQL warehouse** with access to the system catalog.

---

## Basic usage

```bash
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "abc123def456"
```

```
  Stale grants (2, no activity in last 90 days):
    ! alice@company.com: SELECT, USE_CATALOG on main
      last recorded access: 2024-09-14
    ! mark@company.com: USE_CATALOG on staging
      last recorded access: never recorded in window
```

`last recorded access: never recorded in window` means no entry appeared in `system.access.audit` for this principal during the entire lookback period — they haven't touched Databricks in at least 90 days.

If your system tables span multiple workspaces, point to the right one:

```bash
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "abc123def456" \
  --sql-workspace-url "https://adb-123.azuredatabricks.net"
```

---

## Export for review

```bash
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "abc123def456" \
  --output csv > stale_$(date +%F).csv
```

The CSV includes `last_access` (last recorded date, or empty for no activity) and `stale_days` (the threshold configured). Share with the team lead or data steward for sign-off before revoking.

---

## Combine with redundancy analysis

Stale detection and redundancy analysis run together — it's one scan, one pass:

```bash
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "abc123def456" \
  --revoke-script \
  --output csv > full_hygiene_$(date +%F).csv
```

A grant that is both stale **and** redundant (also covered by the group) is the clearest possible revocation case: the person isn't using it, and the group already covers it anyway.

---

## What the query checks

The stale check queries `system.access.audit` for the last recorded activity per principal within the configured window:

```sql
SELECT
  COALESCE(user_identity.email, user_identity.subject_name) AS principal,
  DATE(MAX(event_time)) AS last_seen_date
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
GROUP BY 1
```

Any grant holder absent from this result — no events in the lookback window — is returned as a stale finding.

---

## Interpreting results

!!! warning "Absence of activity is a signal, not proof"
    The stale check does not generate REVOKE SQL automatically. Some legitimate access patterns are infrequent — a quarterly batch job, a monthly report, an on-call runbook. Review before acting.

A sensible triage process:

1. Cross-reference with HR/IT: is the person still in the role that warranted this access?
2. Check whether a job or pipeline runs under their identity — look in the workspace job list or `system.workflow.job_run_timeline`
3. If genuinely unused: revoke, document it in the access review record

---

## Adjusting the threshold

90 days is a common starting point. Adjust based on sensitivity:

```bash
# PII or sensitive catalog — tighter window
databricks-access-audit --group "pii-readers" --stale-days 60 ...

# Rarely-accessed archive — longer window acceptable
databricks-access-audit --group "archive-readers" --stale-days 180 ...
```

---

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
