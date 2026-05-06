# Access Provisioning

## The scenario

> "We need to onboard a new hire.  Give them the same access as Alice — she's already in all the right groups."

In a large Databricks account this is surprisingly hard to answer from the UI.  A principal can be a direct or transitive member of hundreds of groups.  Some groups are synced from Entra ID or Okta (you can't manage them from Databricks), others are Databricks-managed (you can add members via SCIM).  Some groups carry workspace assignments, others exist only for Unity Catalog access, and some are dead-ends that grant nothing at all.

`--compare` shows you the gap.  `--clone-from` tells you exactly what to do about it — and with `--apply`, does it for you.

---

## Compare two principals

Before provisioning, see what Alice has that Bob doesn't:

```bash
databricks-access-audit \
  --compare "alice@company.com" "bob@company.com" \
  --cloud azure
```

```
Compare: alice@company.com  vs  bob@company.com

Only alice@company.com (3):
  data-engineers          [external]  direct
  bi-consumers            [external]  via: alice → bi-consumers
  scratch-workspace-admins [internal]  direct

Only bob@company.com (1):
  legacy-etl-users        [internal]  direct

Shared (5):
  account-users           [internal]  ...
  ...
```

Each group shows:

- **source** — `external` means it's synced from an IdP (Entra/Okta); `internal` means it's Databricks-managed.
- **directness** — `direct` vs transitive (with the full chain).

Use `--output json` or `--output csv` to pipe the diff into a SIEM or spreadsheet.

---

## Build a provisioning plan

```bash
databricks-access-audit \
  --clone-from "alice@company.com" \
  --to "bob@company.com" \
  --cloud azure
```

```
Clone report: alice@company.com → bob@company.com

[IdP required] (2 groups)  — add bob@company.com in Entra / Okta
  data-engineers          workspaces: prod-workspace, dev-workspace
  bi-consumers            workspaces: prod-workspace

[Databricks] (1 group)  — will be applied with --apply
  scratch-workspace-admins  workspaces: scratch-workspace

[Unverified] (1 group)  — run with --scan-uc to check UC grants
  ml-catalog-readers      (no workspace assignment detected)

Dry-run complete. Pass --apply to execute Databricks actions.
```

The tool only considers **direct** memberships from the source.  Transitive group memberships follow automatically once the direct ones are in place — you never need to manually add someone to a parent group's nested groups.

---

## Understanding the four action types

### `Databricks` — you can act now

The group is created and managed inside Databricks.  It has a workspace assignment (or UC grants when `--scan-uc` is used).  Pass `--apply` to SCIM-PATCH the target into it immediately.

### `IdP required` — act in your identity provider

The group is synced from an external IdP — its `externalId` field in SCIM is set.  Databricks mirrors IdP state; it does not own it.  You must add the target in Entra, Okta, or whichever IdP manages this group.  Once the sync runs (usually minutes), the membership will appear in Databricks automatically.

!!! tip
    `--output json` prints the `group_id` for each IdP-required group.  You can use that ID to look up the exact Entra/Okta group name if your IAM tooling supports it.

### `Unverified` — no workspace assignment detected, UC unknown

The group is Databricks-managed (no `externalId`) but does not appear in any workspace's `permissionassignments` response.  This can happen for:

- **UC-only groups** — the group has Unity Catalog grants but no workspace assignment.  Common for fine-grained catalog/schema access control.
- **Dead-end groups** — the group was created but never had grants assigned.

Pass `--scan-uc` to resolve these:

```bash
databricks-access-audit \
  --clone-from "alice@company.com" \
  --to "bob@company.com" \
  --scan-uc \
  --cloud azure
```

Groups with detected UC grants are promoted to `Databricks`; groups with neither workspace nor UC grants are marked `Skipped`.

### `Skipped` — verified dead-end

Requires `--scan-uc`.  The group is Databricks-managed, has no workspace assignment, and has no UC grants.  Adding the target would have no practical effect.

---

## Apply the Databricks actions

```bash
databricks-access-audit \
  --clone-from "alice@company.com" \
  --to "bob@company.com" \
  --apply \
  --cloud azure
```

Without `--apply` the command is a dry-run — it only prints the report.  With `--apply`, it performs a SCIM PATCH for each `Databricks`-classified group and reports the result:

```
[Databricks] scratch-workspace-admins  ✓ applied
```

If a PATCH fails (e.g. the target is already a member, or a permissions error) the error is shown per-group and the rest of the actions continue.

---

## Python API

```python
from databricks_access_audit import create_client, PrincipalComparer, AccessCloner

client = create_client(cloud="azure", client_id="...", client_secret="...", account_id="...")

# Compare
comparer = PrincipalComparer(client, cloud_provider="azure")
diff = comparer.compare("alice@company.com", "bob@company.com")

for g in diff.only_in_a:
    print(f"Alice only: {g.group_name}  source={g.source.value}  direct={g.is_direct_in_a}")

# Clone (dry-run)
cloner = AccessCloner(client, cloud_provider="azure")
report = cloner.build_report(
    source="alice@company.com",
    target="bob@company.com",
    scan_uc=True,
    max_workers=8,
)

print("IdP actions:", [a.group_name for a in report.idp_actions])
print("Databricks: ", [a.group_name for a in report.databricks_actions])

# Apply
target_scim_id = "12345678901234"  # account-level SCIM ID of bob
cloner.apply(report, target_scim_id)

for action in report.databricks_actions:
    if action.applied:
        print(f"✓ {action.group_name}")
    elif action.error:
        print(f"✗ {action.group_name}: {action.error}")
```

---

## CSV output

```bash
# Compare diff as CSV
databricks-access-audit \
  --compare "alice@company.com" "bob@company.com" \
  --output csv \
  --cloud azure > compare.csv

# Clone report as CSV
databricks-access-audit \
  --clone-from "alice@company.com" \
  --to "bob@company.com" \
  --output csv \
  --cloud azure > clone_plan.csv
```

Clone report CSV columns: `action_type`, `group_name`, `group_id`, `source`, `path`, `workspace_accesses`, `uc_grants_summary`, `applied`, `error`.

---

## Notes and caveats

- **Transitive groups are not cloned.** Only direct memberships from the source are in the report.  If Alice is directly in `team-A` which is nested in `data-engineers`, only `team-A` appears — `data-engineers` access follows transitively once Bob is in `team-A`.
- **`--apply` is additive.** It only adds the target to groups; it does not remove any existing memberships the target already has.
- **IdP sync lag.** After adding in Entra/Okta, the Databricks SCIM sync typically runs within minutes but may take up to an hour depending on your IdP's provisioning schedule.
- **Service-principal cloning.** Both source and target can be users, service principals, or groups.  Cloning to a service principal is useful when provisioning a new automation account that should mirror an existing SP's access.
