# Azure AD B2B Guests

Azure AD B2B guest users have two separate identities in Databricks workspaces. The tool resolves both automatically — no extra flags needed.

---

## The problem

When an external user (e.g. a consultant from another tenant) is invited to Azure Entra ID as a B2B guest, they get two UPNs:

| Identity | Example |
|---|---|
| Account email | `alice@partner.com` |
| Guest UPN (workspace) | `alice_partner.com#EXT#@yourtenant.onmicrosoft.com` |

Databricks workspace object ACLs (jobs, clusters, dashboards, etc.) are stored under the **guest UPN**, not the account email. If you search for `alice@partner.com` in workspace permissions, you find nothing — the grants are filed under the `#EXT#` address.

Unity Catalog grants, on the other hand, are stored under the account email.

---

## How the tool resolves it

`_get_workspace_principal_aliases()` in `principal_auditor.py` discovers both identities:

1. Resolve the principal via account SCIM → get `external_id` (the Azure Object ID)
2. Search each workspace's SCIM directory for `externalId eq "{external_id}"`
3. When a workspace SCIM record is found that has a different `userName` (the guest UPN), add it as an alias
4. Pass the alias to `scan_workspace_for_principal` so ACL matches aren't missed

If workspace SCIM lookup by `externalId` fails (some workspaces don't index it), the tool falls back to a direct `/Users/{id}` lookup.

---

## What you see in the output

The CSV and JSON output will include grants under both identities, tagged with the workspace where they apply. The output doesn't distinguish "this is the guest UPN alias" — both appear as grants belonging to the same principal.

---

## Offboarding implications

When offboarding a B2B guest:

1. Remove from Azure Entra ID → SCIM propagates the deprovision
2. UC grants under `alice@partner.com` are effectively orphaned (remain in the grant table but resolve to nothing)
3. Workspace object ACLs under `alice_partner.com#EXT#@...` are also cleaned up by the workspace SCIM deprovision

Run a post-offboarding group audit to check for `MEMBER_DIRECT` grants pointing to the now-deprovisioned account.
