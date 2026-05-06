# Access Review

Every quarter, your CISO wants evidence that access to production data is controlled, appropriate, and hasn't silently drifted. The auditor's ask is always some version of: *"Show me who has access to the production catalog, and show me what changed since last quarter."*

In a multi-workspace Databricks account, this question has no native answer. You can query `INFORMATION_SCHEMA.GRANTS` in each workspace — but that's one metastore at a time, it doesn't resolve nested group memberships, and it gives you a point-in-time snapshot with nothing to compare against. You can click through the Account Console — one workspace, one group, one user at a time. By the time you've covered 12 workspaces and 47 groups, the quarter is nearly over.

---

## Export the current state

### What does data-engineers access right now?

```bash
databricks-access-audit --group "data-engineers" \
  --scan-schemas \
  --output csv > data_engineers_$(date +%F).csv
```

The CSV covers every workspace in the account, includes group membership (with IdP sync status), and classifies every grant as `Direct`, `Upstream`, or `Member Direct` — so reviewers can immediately see what the group holds versus what individuals have bypassed the group to obtain personally.

### What can a specific person access?

```bash
databricks-access-audit --principal "alice@company.com" \
  --scan-schemas \
  --scan-workspace-objects \
  --output csv > alice_$(date +%F).csv
```

---

## The quarterly diff — proving nothing drifted

The snapshot workflow turns point-in-time exports into a compliance audit trail.

**Save the baseline at the start of the review period:**

```bash
databricks-access-audit --group "data-engineers" \
  --save-snapshot snapshots/data-engineers_$(date +%F).json
```

**At review time, compare:**

```bash
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/data-engineers_2025-01-01.json \
  --output csv > drift_Q1_to_Q2.csv
```

If nothing changed, the output is three words: `No changes detected.` That's your evidence.

If something changed, the diff is explicit — every new grant, every removed grant, every membership change, timestamped and exportable:

```
  Grants added (1):
    + [CATALOG] main - bob@example.com (USE_CATALOG|SELECT)

  Members added (1):
    + Bob Jones (User, external)
```

**Save and compare in one pass** — compare against the old baseline, save a new one for next quarter:

```bash
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/data-engineers_2025-Q1.json \
  --save-snapshot snapshots/data-engineers_2025-Q2.json \
  --output csv > drift_Q1_to_Q2.csv
```

---

## Cover multiple groups

Most access reviews cover more than one group. Wrap the command in a loop:

```bash
for group in data-engineers bi-consumers pii-readers platform-admins; do
  databricks-access-audit --group "$group" \
    --baseline "snapshots/${group}_latest.json" \
    --save-snapshot "snapshots/${group}_$(date +%F).json" \
    --output csv >> full_review_$(date +%F).csv
done
```

One combined CSV, one pass, every group covered.

---

## Flag problems during the review

A good access review doesn't just confirm that memberships match expectations — it actively looks for things that shouldn't be there.

**Redundant personal grants** (members with direct access that duplicates what the group already provides):

```bash
databricks-access-audit --group "data-engineers" --revoke-script
```

The `--revoke-script` flag adds copy-paste REVOKE SQL to the output. If you find redundancy during the review, you can clean it up in the same session.

**Escalation risks** (`ALL_PRIVILEGES`, `MANAGE`):

```bash
databricks-access-audit --principal "alice@company.com" --escalation-check
```

**Stale grants** (members with catalog access but no recorded activity):

```bash
databricks-access-audit --group "data-engineers" \
  --stale-days 90 \
  --sql-warehouse-id "abc123def456"
```

**Workspace-local groups** (groups that exist only in workspace SCIM, bypassing account-level management):

```bash
databricks-access-audit --group "data-engineers" --check-local-groups
```

---

## Automate the review cycle

Schedule quarterly snapshots in CI so the review happens even if no one remembers to kick it off manually:

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

A zero-diff run produces a clean compliance record. A non-empty diff triggers an alert and review. Either way, there's evidence.

---

## Reviewer checklist

- [ ] Current membership matches expected team composition
- [ ] No `Member Direct` grants duplicating what the group already provides (`--revoke-script`)
- [ ] No unexpected `ALL_PRIVILEGES` or `MANAGE` grants (`--escalation-check`)
- [ ] No members with no recorded activity for N days (`--stale-days`)
- [ ] No workspace-local groups that should be migrated to account SCIM (`--check-local-groups`)
- [ ] Diff from last quarter reviewed and any changes explained
