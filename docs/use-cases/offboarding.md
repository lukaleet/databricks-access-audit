# Offboarding

When someone leaves the organisation, you need to know exactly what they have access to before deprovisioning their account. Databricks spreads this across multiple workspaces with no native cross-workspace view.

## The workflow

**Step 1 — pull their full access picture**

```bash
databricks-access-audit --principal "alice@company.com" \
  --scan-workspace-objects \
  --scan-schemas \
  --output csv > alice_offboarding_$(date +%F).csv
```

This produces a CSV with:

- All Unity Catalog grants (catalog, schema, table level)
- All workspace object ACLs — jobs, clusters, dashboards, pipelines, SQL warehouses, and 8 more types
- The group memberships that give access (direct vs transitive)
- The workspace where each grant lives

**Step 2 — check for escalation risks**

Before you deprovision, flag anything that could be misused:

```bash
databricks-access-audit --principal "alice@company.com" \
  --escalation-check \
  --output json | jq '.escalation_findings'
```

`ALL_PRIVILEGES` or `MANAGE` grants on a catalog or schema mean Alice could modify permissions. Worth noting in the offboarding record.

**Step 3 — hand the CSV to the access owner**

The CSV is readable without this tool. Share it with the team lead or security team for sign-off before removing the account.

**Step 4 — deprovision via your IdP**

Removing the user from your IdP (Azure Entra ID, Okta, etc.) propagates through SCIM to Databricks automatically — assuming SCIM sync is configured. The Databricks account and workspace accounts are deprovisioned, and UC grants made directly to the user are effectively orphaned (they remain in the grant table but resolve to nothing).

!!! warning "Direct grants stay in the catalog"
    Databricks does not automatically revoke UC grants when a user is deprovisioned. Run a group audit on any groups the user belonged to after offboarding and check for `MEMBER_DIRECT` grants that now point to a non-existent principal.

## Handling Azure AD B2B guests

Azure AD B2B guest users have two workspace identities — the account email and a guest UPN (`alice_company.com#EXT#@tenant.onmicrosoft.com`). Workspace object ACLs are stored under the guest UPN.

The tool resolves both automatically using the SCIM `externalId`, so the CSV will include grants under both identities. No extra flags needed.

See [Azure AD B2B Guests](../how-it-works/azure-b2b-guests.md) for the full explanation.

## Service principal offboarding

Same command, pass the SP display name or application ID:

```bash
databricks-access-audit --principal "etl-pipeline-sp" \
  --scan-workspace-objects \
  --output csv > etl_sp_offboarding_$(date +%F).csv
```
