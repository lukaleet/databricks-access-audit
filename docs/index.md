# databricks-access-audit

**Databricks gives you no native way to answer "what can this identity access across all my workspaces?" — this tool does.**

The Account Console shows you one workspace at a time. `INFORMATION_SCHEMA` shows you one metastore at a time. Neither resolves nested group memberships. Neither tells you whether a personal grant duplicates what the group already provides. Neither helps you figure out what Bob can reach, why he can reach it, or how to replicate that access for a new hire.

`databricks-access-audit` answers all of it in one command, across every workspace in your account at once.

---

## Four modes

| Mode | Entry point | Question it answers |
|---|---|---|
| **Principal audit** | `--principal "alice@company.com"` | What can this user / SP / group access — every workspace, every catalog, every object? |
| **Group audit** | `--group "data-engineers"` | What does this group access? Who in it has personal grants that duplicate what the group already provides? |
| **Compare** | `--compare "alice@company.com" "bob@company.com"` | Which groups does Alice have that Bob doesn't? Which are shared? |
| **Access provisioning** | `--clone-from "alice@company.com" --to "bob@company.com"` | Exactly what do I need to do — in Databricks and in my IdP — to give Bob the same access as Alice? |

---

## What it does

- **Multi-workspace scanning** — auto-discovers every workspace in your account and scans them in parallel; one command covers your whole estate
- **Recursive group resolution** — traces nested group chains (users → groups → groups) with exact paths; shows you *why* someone has access, not just *that* they do
- **Permission inheritance tracking** — classifies every grant as `Direct`, `Upstream` (from a parent group), or `Member Direct` (personal bypass of the group)
- **IdP vs Databricks group classification** — tells you which groups are Entra/Okta-managed (can't be touched in Databricks) and which are Databricks-managed (can be provisioned immediately)
- **Schema and table drill-down** — optionally scans schema and table-level UC grants within accessible catalogs
- **Redundancy and overlap analysis** — compares personal grants against group coverage; generates copy-paste REVOKE SQL for cleanup
- **Workspace object ACLs** — jobs, clusters, pipelines, SQL warehouses, dashboards, and 8 more object types
- **Escalation detection** — flags `ALL_PRIVILEGES` and `MANAGE` grants across the full access chain
- **Compliance snapshots** — save a run to JSON, diff against a previous snapshot, export changes as CSV
- **Resilient API calls** — automatic retry with exponential backoff on 429 / 5xx responses

---

## When to use it

| Scenario | Mode | Key flags |
|---|---|---|
| **Onboarding** — replicate one person's access to a new hire | `--clone-from` / `--compare` | `--scan-uc --apply` |
| **Offboarding** — pull everything before deprovisioning | `--principal` | `--scan-workspace-objects --escalation-check --output csv` |
| **Access review** — export permissions, prove nothing drifted | either | `--output csv --baseline last_quarter.json` |
| **Incident response** — map blast radius of a compromised credential | `--principal` | `--escalation-check --scan-workspace-objects --output json` |
| **Permission hygiene** — find redundant grants, generate REVOKE SQL | `--group` | `--revoke-script` |
| **Stale access** — flag grants with no recorded activity | `--group` | `--stale-days 90 --sql-warehouse-id ...` |
| **Compliance snapshot** — prove permissions haven't changed since last quarter | either | `--save-snapshot` / `--baseline` |

---

## Install

```bash
pip install "databricks-access-audit[sdk]"
```

[Get started →](getting-started.md)
