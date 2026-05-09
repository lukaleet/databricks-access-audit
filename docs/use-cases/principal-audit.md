# Principal Audit

You've just joined the platform team. A colleague asks: "Can you check what Alice can access? She's moving to a read-only role next week and we want to baseline her before the change."

You open the Account Console. You find Alice. You see her direct group memberships — five of them. You click into each group to see what workspaces it grants. Some groups are nested inside other groups, so you start clicking into those too. Two workspaces have Unity Catalog attached — you open INFORMATION_SCHEMA in each one. An hour later you have a partial picture across two workspaces, two metastores, and maybe a third of her groups. You haven't touched workspace objects yet.

`--principal` does this in one command, across every workspace simultaneously.

---

## The basic audit

```bash
databricks-access-audit --principal "alice@company.com"
```

```
============================================================
  Principal audit: alice@company.com (USER, external)
============================================================

  Group memberships (3, 3 IdP-synced, 0 Databricks-managed):
    * data-engineers  (direct, external)
      path: alice@company.com → data-engineers
    - all-data-team   (transitive, external)
      path: alice@company.com → data-engineers → all-data-team
    - platform-users  (transitive, external)
      path: alice@company.com → data-engineers → all-data-team → platform-users

  Workspace access (1):
    * prod-workspace: USER (via data-engineers)

  UC permissions (3):
    [CATALOG] main:            USE_CATALOG, SELECT  via data-engineers  (prod-workspace)
    [SCHEMA]  main.analytics:  USE_SCHEMA           via data-engineers  (prod-workspace)
    [TABLE]   main.analytics.events: SELECT         via data-engineers  (prod-workspace)
============================================================
```

Each line tells you:

- **`*` vs `-`** — direct membership vs transitive (inherited through a chain)
- **`path:`** — the exact group chain. If you want to remove access, this tells you which group to modify and what else that change will affect downstream
- **`via data-engineers`** on every UC permission — Alice doesn't hold any of these grants personally. They all flow through the same group. Remove her from `data-engineers` and all of this disappears

---

## When the path matters

The path isn't just informational. It's the answer to "why does Alice have access to `main`?" without which you can't safely revoke it.

If Alice is in `data-engineers` because `data-engineers` is nested inside `all-data-team`, removing her from `data-engineers` also removes the `all-data-team` membership — and anything that comes with it. The output traces that chain so you know exactly what changes cascade.

---

## Go deeper — schemas and workspace objects

By default the audit scans catalog-level UC grants. Add flags to go further:

```bash
# Include schema and table grants
databricks-access-audit --principal "alice@company.com" --scan-schemas

# Include workspace object ACLs (jobs, clusters, dashboards, pipelines, ...)
databricks-access-audit --principal "alice@company.com" --scan-workspace-objects

# Both at once
databricks-access-audit --principal "alice@company.com" \
  --scan-schemas \
  --scan-workspace-objects
```

Workspace objects matter when you need to know:
- Which jobs Alice can trigger or modify
- Which clusters she can attach to
- Whether she owns any dashboards or pipelines personally (these survive group changes)

---

## Check for elevated privileges

```bash
databricks-access-audit --principal "alice@company.com" --escalation-check
```

`ALL_PRIVILEGES` and `MANAGE` on a production catalog mean Alice can grant that catalog's access to anyone — including herself after any future deprovisioning. `--escalation-check` flags these explicitly so they're not buried in a long permissions list.

---

## Export to CSV for a baseline or access review

```bash
databricks-access-audit --principal "alice@company.com" \
  --scan-schemas \
  --scan-workspace-objects \
  --escalation-check \
  --output csv > alice_$(date +%F).csv
```

The CSV has one row per grant. Import into Excel, Google Sheets, or attach to a ticket. The `grant_source` column separates grants Alice holds personally (`Member Direct`) from those she inherits through groups — useful when you're deciding what to revoke vs what handles itself through group membership changes.

---

## Visualize for a manager

```bash
databricks-access-audit --principal "alice@company.com" --output html > alice.html
```

Opens in any browser — no server required. Shows a Mermaid flowchart of Alice's full access graph (groups → workspaces → catalogs), summary stats, and full data tables. Useful for sign-offs, handover documents, and access review conversations with stakeholders who don't live in a terminal.

For a compact terminal view:

```bash
databricks-access-audit --principal "alice@company.com" --tree
```

---

## Service principals

The same command works for service principals. Pass the SP display name or application ID:

```bash
databricks-access-audit --principal "etl-pipeline-sp"
databricks-access-audit --principal "a1b2c3d4-0000-0000-0000-111122223333"
```

For SPs, pay particular attention to `--scan-workspace-objects` — jobs and pipelines with the SP as the run-as identity are the most operationally significant grants. If the SP is deprovisioned without transferring those, the workflows break.

---

## Audit a group as a principal

Passing a group name to `--principal` treats the group itself as the subject — what can `data-engineers` access directly (not its members)?

```bash
databricks-access-audit --principal "data-engineers"
```

This differs from `--group "data-engineers"`, which audits the group's access AND analyses its members' personal grants for redundancy. Use `--principal` on a group when you just want the access picture; use `--group` when you want the full membership + redundancy analysis.

---

## Python API

```python
from databricks_access_audit import create_client, PrincipalAuditor, WorkspaceDiscovery

client = create_client(cloud="azure", client_id="...", client_secret="...", account_id="...")

ws_disc = WorkspaceDiscovery(client, cloud_provider="azure")
auditor = PrincipalAuditor(client, workspace_discovery=ws_disc, cloud_provider="azure")

result = auditor.audit(
    identifier="alice@company.com",
    scan_schemas=True,
    scan_workspace_objects=True,
    max_workers=8,
)

print(f"{result.principal_name} is in {len(result.groups)} groups")
print(f"Workspace roles: {len(result.workspace_roles)}")
print(f"UC permissions:  {len(result.permissions)}")

for perm in result.permissions:
    via = perm.via_group or "(direct)"
    print(f"  [{perm.securable_type}] {perm.securable_name}: {', '.join(perm.privileges)} via {via}")
```

---

## Checklist

- [ ] Group memberships reviewed — direct and transitive
- [ ] Every UC grant traced to its source group (no unexplained `Member Direct` grants)
- [ ] Workspace object ownership checked (`--scan-workspace-objects`)
- [ ] `ALL_PRIVILEGES` / `MANAGE` grants reviewed (`--escalation-check`)
- [ ] CSV exported and saved as baseline

---

## Related

- [Offboarding](offboarding.md) — full pre-deprovisioning workflow using `--principal`
- [Incident Response](incident-response.md) — scope mapping under time pressure
- [Group Audit](../capabilities.md#redundancy-and-overlap-analysis) — when you need the full group picture including member redundancy
- [Visualizing Access](access-map.md) — HTML and tree output options in depth
