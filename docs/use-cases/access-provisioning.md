# Access Provisioning

> "Please add Uwe to Databricks. He should have the same access as Thomas."
>
> "OK — what groups is Thomas in?"
>
> "I don't know. He's been here three years."

In a large account this is a surprisingly hard question. Thomas might be in 40 groups. Some are synced from Entra ID — you can't manage those from Databricks, you need to go to your identity provider. Some are Databricks-managed — you can add Uwe directly. Some are nested: Thomas is in group A because group A is nested inside group B, not because anyone added him to B directly. And some groups exist only for Unity Catalog access, with no workspace assignment at all.

Without tooling, you open the Account Console. You find Thomas. You see his direct groups. You start clicking through each one. Forty groups, two types (some with a little Entra icon, some without), and you're not sure which ones grant what. An hour later you have a list, half of it wrong, and you still don't know which ones you can actually provision from Databricks.

---

## Step 1 — see the gap

Before doing anything, compare Thomas and Uwe's current memberships:

```bash
databricks-access-audit --compare "thomas@company.com" "uwe@company.com"
```

```
============================================================
  Comparison: Thomas Müller  vs  Uwe Becker
============================================================

  Groups Thomas has that Uwe does not (5):
    data-engineers         (direct, external)   ← must add in Entra
      path: Thomas Müller → data-engineers
    bi-consumers           (transitive, external) ← follows once data-engineers is done
      path: Thomas Müller → data-engineers → bi-consumers
    npb-platform-users     (direct, internal)   ← can add in Databricks
      path: Thomas Müller → npb-platform-users
    scratch-workspace-admins (direct, internal) ← can add in Databricks
      path: Thomas Müller → scratch-workspace-admins
    ml-catalog-readers     (direct, internal)   ← no workspace assignment, run --scan-uc

  Groups Uwe has that Thomas does not (1):
    legacy-etl-users       (direct, internal)   ← different project, leave it

  Groups both belong to (3):
    account users  |  npb-developers  |  ...

============================================================
```

This tells you the exact gap — not all of Thomas's memberships, just the ones Uwe is missing. And crucially, it tells you the **source** of each group: `external` means Entra/Okta, `internal` means Databricks-managed.

---

## Step 2 — build the provisioning plan

```bash
databricks-access-audit --clone-from "thomas@company.com" --to "uwe@company.com" --scan-uc
```

```
============================================================
  Access provisioning report
  Source: Thomas Müller (thomas@company.com)
  Target: Uwe Becker (uwe@company.com)
============================================================

  Actions required in your identity provider (2):
  (Cannot be done from Databricks — add target in Entra ID / Okta / etc.)
    ! data-engineers     [workspaces: prod-workspace, dev-workspace]
    ! bi-consumers       [transitive — follows once data-engineers is done]

  Actions in Databricks (2):
    + npb-platform-users      [workspaces: prod-workspace]
    + scratch-workspace-admins [workspaces: scratch-workspace]

  Skipped — verified dead-end, no effective grants (1):
    - ml-catalog-readers  (no workspace assignment, no UC grants detected)

  Dry run — pass --apply to write the 2 Databricks group addition(s).

============================================================
```

The plan splits into two actionable tracks:

**Identity provider (Entra/Okta):** Add Uwe to `data-engineers`. Once the SCIM sync runs (usually minutes), `bi-consumers` follows automatically because it's nested inside `data-engineers` — you don't need to add him there separately.

**Databricks:** Two groups you can provision immediately with `--apply`. No IdP ticket needed.

---

## Why the IdP split matters

If you didn't know which groups were Entra-synced, here's what would happen: you'd try to PATCH Uwe into `data-engineers` from Databricks. You'd get a `403 Forbidden`. You'd try again. Still 403. You'd assume it's a permissions issue and spend time debugging — when the real answer is that Databricks doesn't own this group. Entra does.

The tool checks SCIM `externalId` on each group. If it's set, the group is managed by an external IdP. Databricks mirrors that state; it can't write to it. The only path is your IdP.

---

## Step 3 — apply the Databricks actions

```bash
databricks-access-audit \
  --clone-from "thomas@company.com" \
  --to "uwe@company.com" \
  --scan-uc \
  --apply
```

```
  Applied (2/2):
    + npb-platform-users       ✓ applied
    + scratch-workspace-admins ✓ applied
```

The Databricks side is done. Go add Uwe to `data-engineers` in Entra and the rest follows through the SCIM sync.

---

## What gets cloned

Only **direct** memberships from the source are in the provisioning plan. Transitive memberships follow automatically once the direct ones are in place — you never need to manually add someone to every nested group in a chain.

In the example above: Thomas is directly in `data-engineers`. `bi-consumers` is a transitive membership (he's in it because `data-engineers` is nested inside `bi-consumers`). The plan only asks you to add Uwe to `data-engineers`. Once that's done, `bi-consumers` access follows on its own.

---

## UC-only groups and `--scan-uc`

Some groups have no workspace assignment — they exist purely to grant Unity Catalog access (a catalog, a schema, a table). These don't appear in workspace `permissionassignments` responses, so without extra scanning they're classified as `Unverified`.

Pass `--scan-uc` to check them against actual catalog grants:

- Groups with UC grants → promoted to `Databricks` (SCIM PATCH works, and it matters)
- Groups with no grants anywhere → `Skipped` (adding Uwe would have no effect)

`--scan-uc` adds catalog-scan API calls per workspace, so it's off by default. Worth running when the source might have UC-only access.

---

## Service principal provisioning

The same flow works for service principals. Useful when a new automation account needs to mirror an existing SP:

```bash
databricks-access-audit \
  --clone-from "etl-pipeline-sp" \
  --to "new-etl-pipeline-sp" \
  --apply
```

---

## Python API

```python
from databricks_access_audit import create_client, PrincipalComparer, AccessCloner

client = create_client(cloud="azure", client_id="...", client_secret="...", account_id="...")

# See the gap
comparer = PrincipalComparer(client, cloud_provider="azure")
diff = comparer.compare("thomas@company.com", "uwe@company.com")

print("Thomas only:")
for g in diff.only_in_a:
    print(f"  {g.group_name}  source={g.source.value}  direct={g.is_direct_in_a}")

# Build the plan
cloner = AccessCloner(client, cloud_provider="azure")
report = cloner.build_report(
    source="thomas@company.com",
    target="uwe@company.com",
    scan_uc=True,
)

print("IdP actions — add in Entra/Okta:")
for a in report.idp_actions:
    print(f"  {a.group_name}")

print("Databricks actions — will apply via SCIM:")
for a in report.databricks_actions:
    print(f"  {a.group_name}  workspaces: {a.workspace_accesses}")

# Apply
cloner.apply(report, target_scim_id="<uwe's account SCIM ID>")

for action in report.databricks_actions:
    status = "✓" if action.applied else f"✗ {action.error}"
    print(f"  {action.group_name}: {status}")
```

---

## CSV output

```bash
# The gap as a spreadsheet
databricks-access-audit --compare "thomas@company.com" "uwe@company.com" \
  --output csv > compare.csv

# The provisioning plan (e.g. to attach to an IT ticket)
databricks-access-audit --clone-from "thomas@company.com" --to "uwe@company.com" \
  --scan-uc --output csv > provisioning_plan.csv
```

The clone report CSV includes `action_type` (what to do), `source` (internal/external), `workspace_accesses` (which workspaces this group grants access to), and an `error` column that captures any SCIM failures if `--apply` is run.
