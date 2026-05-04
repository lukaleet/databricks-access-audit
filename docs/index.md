# databricks-access-audit

**Databricks gives you no native way to answer *"what can this identity access across all my workspaces?"* — this tool does.**

The Account Console shows you one workspace at a time. `INFORMATION_SCHEMA` shows you one metastore at a time. Neither resolves nested group memberships. Neither tells you whether a personal grant duplicates what the group already provides.

`databricks-access-audit` is a CLI and Python library that answers cross-workspace access questions in one command.

## Two modes

| Mode | Entry point | Question it answers |
|---|---|---|
| **Principal audit** | `--principal "alice@company.com"` | What can this user / SP / group access across every workspace? |
| **Group audit** | `--group "data-engineers"` | What does this group access? Who in it has redundant personal grants? |

## When to use it

| Scenario | Mode | Key flags |
|---|---|---|
| **Offboarding** — pull everything before deprovisioning | `--principal` | `--scan-workspace-objects --output csv` |
| **Access review** — export permissions, compare to last quarter | either | `--output csv --baseline last_quarter.json` |
| **Incident response** — map what a compromised identity can reach | `--principal` | `--escalation-check --scan-workspace-objects` |
| **Permission hygiene** — find redundant grants, generate REVOKE SQL | `--group` | `--revoke-script` |
| **Stale access** — flag grants with no recorded activity | `--group` | `--stale-days 90 --sql-warehouse-id ...` |
| **Compliance snapshot** — prove permissions haven't drifted | either | `--save-snapshot` / `--baseline` |

## Install

```bash
pip install "databricks-access-audit[sdk]"
```

[Get started →](getting-started.md)
