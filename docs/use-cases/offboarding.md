# Offboarding

It's Thursday afternoon. Sarah's last day is tomorrow. Your IT ticket says "deprovision access." You open the Databricks Account Console — and realise you have six workspaces, no cross-workspace view, and no idea how many groups she's in.

You start clicking. Workspace one: she's in four groups. Workspace two: three groups, maybe some overlap. You open `INFORMATION_SCHEMA.GRANTS` — that's one metastore. She might have direct grants in others. By the time you've pieced it together across everything, it's 6pm. You still don't know if she has personal catalog grants that will survive the deprovisioning.

This is what offboarding looks like without the tool.

---

## Pull the full picture in one command

```bash
databricks-access-audit --principal "sarah@company.com" \
  --scan-workspace-objects \
  --scan-schemas \
  --output csv > sarah_offboarding_$(date +%F).csv
```

In under two minutes you have a single CSV with everything:

- Every Unity Catalog grant she holds — catalog, schema, and table level — across every workspace
- Every workspace object ACL: jobs she can manage, clusters she can attach to, dashboards, pipelines, SQL warehouses, and 8 more types
- The exact group chain that gives her each permission (`via data-engineers → all-data-team → ...`)
- Which memberships are IdP-synced vs Databricks-managed
- Which grants are personal (survive deprovisioning) vs group-inherited (removed when she's deprovisioned)

---

## Check for escalation risks before you sign off

Before anyone countersigns the offboarding, check whether she had privileges that could have been misused:

```bash
databricks-access-audit --principal "sarah@company.com" \
  --escalation-check \
  --output json | jq '.escalation_findings'
```

`ALL_PRIVILEGES` on a catalog means she could have granted access to anyone. `MANAGE` means she could modify permissions on that securable. Worth noting in the offboarding record — especially if access was unexpectedly broad.

---

## The thing that catches everyone out

Removing a user from your IdP removes them from IdP-synced groups. It does **not** revoke Unity Catalog grants made directly to that user.

After deprovisioning, those rows still exist in the UC grant table. They resolve to nothing while the account is deprovisioned — but if the account is ever reinstated (contractor returning, rehire), the grants come back.

The CSV output tells you exactly which grants are `Member Direct` (personal). Deal with those explicitly:

```sql
-- Generated from --revoke-script on any group she belonged to,
-- or constructed manually from the CSV output:
REVOKE SELECT ON CATALOG main FROM `sarah@company.com`;
REVOKE USE_CATALOG ON CATALOG analytics FROM `sarah@company.com`;
```

---

## Azure AD B2B guest users

If Sarah is an Azure AD B2B guest, she has two workspace identities: her account email and a guest UPN (`sarah_company.com#EXT#@tenant.onmicrosoft.com`). Workspace object ACLs are stored under the guest UPN. The Databricks UI shows you one; this tool resolves both automatically using the SCIM `externalId`, so nothing is missed.

See [Azure AD B2B Guests](../how-it-works/azure-b2b-guests.md) for the full explanation.

---

## Service principal offboarding

Same command. Pass the SP display name or application ID:

```bash
databricks-access-audit --principal "etl-pipeline-sp" \
  --scan-workspace-objects \
  --output csv > etl_sp_offboarding_$(date +%F).csv
```

For SPs, pay particular attention to jobs and pipelines with `CAN_MANAGE` or `IS_OWNER` — those workflows may need a new run-as identity before you deprovision the SP.

---

## Verify removal is complete

After the account is deprovisioned, confirm the principal no longer appears anywhere:

```bash
# Run --resource on every catalog they had access to — confirm they're gone
databricks-access-audit --resource "main" | grep "sarah@company.com"
databricks-access-audit --resource "analytics" | grep "sarah@company.com"
```

If the principal still appears — as a direct grant, or as a member of a group that wasn't updated — the `--resource` output shows exactly where and via which path. This is faster than re-running the full principal audit and easier to attach to the offboarding ticket as evidence.

---

## Offboarding checklist

- [ ] Full access export saved as CSV (attach to the offboarding ticket)
- [ ] Escalation findings reviewed (`--escalation-check`)
- [ ] `Member Direct` grants revoked from UC (`REVOKE` SQL)
- [ ] Jobs / pipelines with personal ownership transferred to a group or service principal
- [ ] User removed from IdP (propagates through SCIM to Databricks automatically)
- [ ] Post-deprovisioning verification: `--resource` on affected catalogs confirms the name is gone
