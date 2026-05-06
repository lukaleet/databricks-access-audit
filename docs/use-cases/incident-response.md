# Incident Response

A service principal started making unusual API calls. A credential was found in a public repository. An employee is under investigation. Whatever triggered the alert — you need to know the blast radius immediately. Not tomorrow. Now.

The problem: Databricks spreads access across workspaces, groups, and object-level ACLs with no single place to look. By the time you've clicked through the Account Console, run INFORMATION_SCHEMA queries across multiple metastores, and pieced together which jobs and clusters this identity can reach, an hour has passed. In incident response, an hour is a long time.

---

## Map blast radius in one command

```bash
databricks-access-audit --principal "compromised@company.com" \
  --scan-workspace-objects \
  --escalation-check \
  --output json > blast_radius_$(date +%F_%H%M).json
```

In a single pass this gives you:

- **Every workspace** the identity can reach, at what permission level, and through which group chain
- **All Unity Catalog grants** — catalog, schema, and table level — with the exact path (`via data-engineers → all-data-team → ...`)
- **All workspace object ACLs** — jobs they can trigger or modify, clusters they can attach to, dashboards, pipelines, SQL warehouses, serving endpoints
- **Escalation risks** — any `ALL_PRIVILEGES` or `MANAGE` grants that let this identity modify permissions or grant access to others

The JSON output goes to stdout, progress to stderr — pipe it, store it, attach it to the incident ticket.

---

## The questions that matter in the first 30 minutes

**Does it have Workspace Admin anywhere?**

```bash
cat blast_radius.json | jq '.workspace_roles[] | select(.permission_level == "ADMIN")'
```

Workspace Admin means it can read secrets, modify cluster configs, impersonate other users, and access all data in that workspace. This determines the severity tier immediately.

**Does it have escalation privileges — can it grant access to others?**

```bash
cat blast_radius.json | jq '.escalation_findings'
```

`ALL_PRIVILEGES` on a catalog means the identity can `GRANT` to any principal. `MANAGE` means it can modify grants on that securable. If either appears, the incident scope extends beyond what the identity itself accessed — assume any grant in that catalog could have been modified.

**What jobs and pipelines can it run or modify?**

```bash
cat blast_radius.json | jq '
  .workspace_object_permissions[]
  | select(.permission_level | test("MANAGE|OWN|RUN"))
  | {object_type, object_name: (.object_name // .object_id), permission_level, workspace_name}
'
```

Jobs and pipelines can exfiltrate data, write to external locations, or run arbitrary code. Any job this identity owns or can manage is part of the blast radius — and may have already been tampered with.

---

## Service principal compromise

For a compromised SP, the `run-as` identity of jobs is critical:

```bash
databricks-access-audit --principal "etl-sp-name" \
  --scan-workspace-objects \
  --workspace-object-types jobs,pipelines \
  --output csv > sp_owned_jobs_$(date +%F).csv
```

If the SP is the `run-as` identity for production pipelines, those pipelines may need to be paused even after the credential is rotated — a new secret doesn't help if the existing job definition was already modified to exfiltrate data on the next run.

---

## Containment steps

Once you have the blast radius map:

1. **Rotate the credential** — invalidate the compromised client secret or PAT immediately
2. **Revoke workspace access** — remove the identity from workspaces via the Account Console or API
3. **Revoke UC grants** — for direct grants, use REVOKE SQL; for group-inherited access, remove from the relevant group
4. **Pause affected jobs and pipelines** — anything this identity owns or can modify should be reviewed before the next run
5. **Cross-reference the audit log** — see exactly what it did (below)

---

## Cross-reference with the audit log

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
LIMIT 200;
```

Focus on `action_name` values like `createPermissions`, `updatePermissions`, `deletePermissions`, `create`, `delete`, `runCommand`. These are the actions with lasting side effects — data modifications, permission changes, code execution.

---

## After containment — verify scope with a clean audit

Once the credential is rotated and access revoked, run the audit one more time against the same identity to confirm the blast radius has been fully closed:

```bash
databricks-access-audit --principal "compromised@company.com" \
  --scan-workspace-objects \
  --escalation-check
```

The output should show no workspace access, no UC permissions, no object grants. If anything remains, you missed a revocation step.
