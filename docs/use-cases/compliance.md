# Compliance Snapshots

SOC 2 and ISO 27001 both require evidence that access controls are reviewed periodically and that permissions haven't drifted between reviews. The snapshot and diff mode is built for this workflow.

## The evidence workflow

**At the start of the review period — save a baseline:**

```bash
databricks-access-audit --group "data-engineers" \
  --cloud azure \
  --save-snapshot snapshots/data-engineers_2025-Q1.json
```

The snapshot is plain JSON, human-readable without this tool, versioned, and safe to store in version control alongside other compliance artefacts.

**At the end of the review period — compare:**

```bash
databricks-access-audit --group "data-engineers" \
  --cloud azure \
  --baseline snapshots/data-engineers_2025-Q1.json \
  --save-snapshot snapshots/data-engineers_2025-Q2.json
```

**No changes:**
```
  No changes detected.
```

**Changes found:**
```
============================================================
  Diff: data-engineers (group)
  Baseline:  2025-01-01T00:00:00+00:00
  Current:   2025-04-01T12:34:56+00:00
============================================================

  Grants added (1):
    + [CATALOG] main - bob@example.com (USE_CATALOG|SELECT)

  Grants removed (1):
    - [CATALOG] staging - carol@example.com (MODIFY)

  Members added (1):
    + Bob Jones (User)
============================================================
```

Every change is explicit — a privilege modification is shown as a removal and addition pair, not a silent update.

## Export for auditors

Auditors rarely run CLI tools. Export the diff as CSV:

```bash
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/data-engineers_2025-Q1.json \
  --output csv > permission_drift_Q1_to_Q2.csv
```

One row per change, importable into Excel, Sheets, or a SIEM.

## Automate quarterly reviews

Schedule this in CI (GitHub Actions, Azure DevOps, etc.):

```yaml
- name: Quarterly Databricks access review
  run: |
    databricks-access-audit --group "data-engineers" \
      --baseline snapshots/data-engineers_latest.json \
      --save-snapshot snapshots/data-engineers_$(date +%F).json \
      --output csv > drift_report_$(date +%F).csv
  env:
    DATABRICKS_CLIENT_ID: ${{ secrets.DATABRICKS_CLIENT_ID }}
    DATABRICKS_CLIENT_SECRET: ${{ secrets.DATABRICKS_CLIENT_SECRET }}
    DATABRICKS_ACCOUNT_ID: ${{ secrets.DATABRICKS_ACCOUNT_ID }}
```

## Snapshot format

```json
{
  "version": "1",
  "type": "group",
  "target": "data-engineers",
  "timestamp": "2025-04-01T12:34:56+00:00",
  "members": [...],
  "grants": [...]
}
```

Snapshots are versioned (`"version": "1"`) — future schema changes will be handled with explicit migrations, so stored snapshots remain valid.

## Change detection rules

- A grant is "added" or "removed" based on a **full-field fingerprint** — any field change (including privilege modification) is reported as a removal and addition pair. Nothing is silently updated.
- **Member identity** is tracked by ID and type only — display-name changes are not flagged as membership churn.
- Snapshots from `--principal` mode track permissions and group memberships; snapshots from `--group` mode track grants and members.

## Python API

```python
from databricks_access_audit import (
    build_group_snapshot, save_snapshot, load_snapshot, diff_snapshots,
)

snap = build_group_snapshot("data-engineers", members, catalog_grants, schema_grants, table_grants)
save_snapshot(snap, "snapshots/data-engineers_2025-Q2.json")

baseline = load_snapshot("snapshots/data-engineers_2025-Q1.json")
diff = diff_snapshots(baseline, snap)

if diff.has_changes:
    print(f"{len(diff.grants_added)} grants added, {len(diff.grants_removed)} removed")
    print(f"{len(diff.members_added)} members added, {len(diff.members_removed)} removed")
else:
    print("No changes.")
```
