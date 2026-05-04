# Access Review

Periodic access reviews are a requirement for SOC 2, ISO 27001, and most enterprise security policies. The typical ask: *"Show me who has access to what, and prove it hasn't changed since last quarter."*

## Export permissions for review

### Group audit — who's in the group and what can they access?

```bash
databricks-access-audit --group "data-engineers" \
  --scan-schemas \
  --output csv > data_engineers_$(date +%F).csv
```

The CSV contains:

- All catalog, schema, and table grants for the group (direct, upstream, member-direct)
- Redundancy analysis — members whose personal grants duplicate what the group already provides
- IdP sync status — which members are provisioned through the IdP vs created manually in Databricks

### Principal audit — everything a specific user can reach

```bash
databricks-access-audit --principal "alice@company.com" \
  --scan-schemas \
  --scan-workspace-objects \
  --output csv > alice_$(date +%F).csv
```

## Save a snapshot and compare next quarter

**Save the current state:**

```bash
databricks-access-audit --group "data-engineers" \
  --save-snapshot snapshots/data-engineers_$(date +%F).json
```

**Three months later — compare:**

```bash
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/data-engineers_2025-01-01.json
```

Output when changes are found:

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

When nothing has changed:

```
  No changes detected.
```

**Export the diff as CSV** for import into a spreadsheet or SIEM:

```bash
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/data-engineers_2025-01-01.json \
  --output csv > diff_$(date +%F).csv
```

## Combine save and compare in one run

```bash
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/data-engineers_2025-01-01.json \
  --save-snapshot snapshots/data-engineers_$(date +%F).json \
  --output csv
```

This compares against the baseline, prints the diff, and saves a new snapshot for next quarter — all in one command.

## Flag stale grants

Members with catalog grants but no recorded activity in 90 days:

```bash
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "abc123def456"
```

!!! note
    Stale detection queries `system.access.audit`. System tables must be enabled and the audit SP must have `SELECT` on `system.access.audit`.

## Reviewer checklist

A good access review covers:

- [ ] All current members are still expected to be in the group
- [ ] No `MEMBER_DIRECT` grants duplicate what the group already provides (`--revoke-script` generates cleanup SQL)
- [ ] No unexpected `ALL_PRIVILEGES` or `MANAGE` grants (`--escalation-check`)
- [ ] No members with no recorded activity for N days (`--stale-days`)
- [ ] No workspace-local groups that should have been migrated to account SCIM (`--check-local-groups`)
