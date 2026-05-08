# Compliance Snapshots

Your auditor has one question: *"Has access to the production catalog changed since Q1?"*

Databricks has no built-in answer. There is no permission changelog, no audit trail of grant changes, no native diff between what access looked like three months ago and what it looks like today. You would have to export everything now, find an export from Q1 (if you saved one), and compare them manually — column by column, row by row.

The snapshot and diff mode exists specifically for this. Save a baseline, run the comparison at review time, get an exact list of what changed.

---

## The evidence workflow

**Start of the review period — save the baseline:**

```bash
databricks-access-audit --group "data-engineers" \
  --save-snapshot snapshots/data-engineers_2025-Q1.json
```

The snapshot is plain JSON — human-readable without this tool, safe to commit to version control alongside other compliance artefacts, and versioned so it remains loadable as the tool evolves.

**End of the review period — compare:**

```bash
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/data-engineers_2025-Q1.json \
  --save-snapshot snapshots/data-engineers_2025-Q2.json
```

**If nothing changed:**
```
  No changes detected.
```

**If something changed:**
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

Every change is explicit. A privilege modification — someone gaining `SELECT` while losing `MODIFY` — appears as a removal and an addition, not a silent update. Nothing is ambiguous.

---

## Export for auditors

Auditors rarely run CLI tools. Export the diff as a CSV they can open in Excel or import into a SIEM:

```bash
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/data-engineers_2025-Q1.json \
  --output csv > permission_drift_Q1_to_Q2.csv
```

One row per change: `change_type`, `securable_type`, `securable_name`, `principal`, `privileges`, `baseline_timestamp`, `current_timestamp`.

To cover every relevant group in one pass, wrap it in a script:

```bash
for group in data-engineers bi-consumers pii-readers; do
  databricks-access-audit --group "$group" \
    --baseline "snapshots/${group}_2025-Q1.json" \
    --output csv >> full_permission_drift_Q1_to_Q2.csv
done
```

---

## Automate quarterly reviews

Schedule in CI so the review happens even if someone forgets:

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

If the drift report is non-empty, fail the job and alert. Zero-change runs are a clean compliance record.

---

## Principal audit snapshots

The same workflow works for individual users or service principals:

```bash
# Save
databricks-access-audit --principal "alice@company.com" \
  --save-snapshot snapshots/alice_2025-Q1.json

# Compare
databricks-access-audit --principal "alice@company.com" \
  --baseline snapshots/alice_2025-Q1.json
```

Principal snapshots include workspace roles and UC permissions with full `via_path` chains, so the diff tells you not just *that* a grant changed but *which group chain* changed.

---

## What the snapshot captures

| Snapshot mode | Contents |
|---|---|
| Group (`--group`) | Members (users + SPs), catalog / schema / table grants with grant source and principal |
| Principal (`--principal`) | Group memberships, workspace roles, UC permissions — all with `via_path` |

Snapshots are versioned (`"version": "1"`) — future schema changes are handled with explicit migrations so stored snapshots remain loadable across tool upgrades.

---

## Change detection rules

- A grant is "added" or "removed" based on a **full-field fingerprint**. Any field change — privilege added, privilege removed, workspace changed — appears as an explicit removal + addition pair. Nothing is silently updated.
- **Member identity** is tracked by SCIM ID and type, not display name. Renames don't generate false-positive membership churn.
- **Timestamps** are embedded in each snapshot file, so the diff always shows the exact window it covers.

---

## Python API

```python
from databricks_access_audit import (
    build_group_snapshot, build_principal_snapshot,
    save_snapshot, load_snapshot, diff_snapshots,
)

# Group mode
snap = build_group_snapshot("data-engineers", members, catalog_grants, schema_grants, table_grants)
save_snapshot(snap, "snapshots/data-engineers_2025-Q2.json")

baseline = load_snapshot("snapshots/data-engineers_2025-Q1.json")
diff = diff_snapshots(baseline, snap)

if diff.has_changes:
    print(f"{len(diff.grants_added)} added, {len(diff.grants_removed)} removed")
    print(f"{len(diff.members_added)} members added, {len(diff.members_removed)} removed")
else:
    print("No changes — clean for the review period.")
```
