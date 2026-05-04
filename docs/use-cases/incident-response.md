# Incident Response

A credential is compromised. A service principal behaves unexpectedly. An insider threat is suspected. You need to know the blast radius in minutes, not hours.

## Map blast radius immediately

```bash
databricks-access-audit --principal "compromised@company.com" \
  --scan-workspace-objects \
  --escalation-check \
  --output json > blast_radius_$(date +%F_%H%M).json
```

This gives you in one pass:

- Every workspace the identity can reach and at what permission level
- All Unity Catalog grants (catalog → schema → table) with the granting group chain
- All workspace object ACLs — jobs they can run or manage, clusters they can attach to, dashboards, pipelines
- Any `ALL_PRIVILEGES` or `MANAGE` grants that represent escalation paths

## Key things to look for

**Workspace Admin access**

```bash
databricks-access-audit --principal "compromised@company.com" --output json \
  | jq '.workspace_roles[] | select(.permission_level == "ADMIN")'
```

A compromised identity with Workspace Admin can read secrets, modify cluster configs, and access all data in that workspace.

**Escalation risks**

```bash
databricks-access-audit --principal "compromised@company.com" \
  --escalation-check --output json \
  | jq '.escalation_findings'
```

`ALL_PRIVILEGES` on a catalog means the identity can grant access to anyone. `MANAGE` means it can modify grants on that securable.

**Jobs and pipelines**

```bash
databricks-access-audit --principal "compromised@company.com" \
  --scan-workspace-objects \
  --workspace-object-types jobs,pipelines \
  --output json \
  | jq '.workspace_object_permissions[] | select(.permission_level | test("MANAGE|OWN"))'
```

Jobs and pipelines can exfiltrate data, run arbitrary code, or write to external locations.

## Contain the incident

Once you know what the identity can reach:

1. **Revoke workspace roles** — remove the SP or user from workspaces via the Account Console or API
2. **Rotate the credential** — invalidate the compromised client secret or PAT
3. **Revoke UC grants** — for any direct grants, use the REVOKE SQL from `--revoke-script` (group audit) or construct manually
4. **Audit job run history** — check `system.access.audit` for recent activity under the compromised identity

## Audit log cross-reference

If you know the approximate time of compromise, check what the identity actually did:

```sql
SELECT
  event_time,
  action_name,
  request_params,
  response.status_code
FROM system.access.audit
WHERE COALESCE(user_identity.email, user_identity.subject_name) = 'compromised@company.com'
  AND event_time >= '2025-01-15T00:00:00Z'
ORDER BY event_time DESC
LIMIT 100;
```

## Service principal compromise

For a compromised SP, also check which jobs and workflows use it as a run-as identity — those may need to be reviewed or paused even after the credential is rotated.

```bash
databricks-access-audit --principal "etl-pipeline-sp" \
  --scan-workspace-objects \
  --workspace-object-types jobs,pipelines \
  --output csv > sp_jobs_$(date +%F).csv
```
