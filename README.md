# databricks-access-audit

> Databricks gives you no native way to answer *"what can this identity access across all my workspaces?"* — this tool does.

[![CI](https://img.shields.io/github/actions/workflow/status/lukaleet/databricks-access-audit/ci.yml?branch=main&label=CI)](https://github.com/lukaleet/databricks-access-audit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/databricks-access-audit)](https://pypi.org/project/databricks-access-audit/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

The Account Console shows you one workspace at a time. `INFORMATION_SCHEMA` shows you one metastore at a time. Neither resolves nested group memberships. Neither tells you whether a personal grant duplicates what the group already provides.

`databricks-access-audit` answers cross-workspace access questions in one command, across every workspace in your account at once.

## Two modes

| Mode | Entry point | Question it answers |
|---|---|---|
| **Principal audit** | `--principal "alice@company.com"` | What can this user / SP / group access across every workspace? |
| **Group audit** | `--group "data-engineers"` | What does this group access? Who in it has redundant personal grants? |

## What it does

- **Multi-workspace scanning** — auto-discovers every workspace in your account, scans them in parallel
- **Recursive group resolution** — traces nested group membership chains with full hierarchy and path
- **Permission inheritance tracking** — classifies every grant as `Direct`, `Upstream`, or `Member Direct`
- **Schema and table drill-down** — optionally scans schema and table-level UC grants
- **Redundancy and overlap analysis** — compares personal grants against group coverage, generates REVOKE SQL
- **Workspace object ACLs** — jobs, clusters, pipelines, SQL warehouses, dashboards and 8 more types
- **Escalation detection** — flags `ALL_PRIVILEGES` and `MANAGE` grants across the principal's access chain
- **Compliance snapshots** — save a run to JSON, diff against a previous snapshot, export changes as CSV
- **Resilient API calls** — automatic retry with exponential backoff on 429 / 5xx responses

## Install

```bash
pip install "databricks-access-audit[sdk]"
```

Requires Python 3.9+. The `[sdk]` extra adds `databricks-sdk` for automatic auth and retries.

## Credentials

Add a section to `~/.databrickscfg` and run without any flags — cloud is auto-detected from the host:

```ini
[DEFAULT]
host          = https://accounts.azuredatabricks.net
account_id    = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
client_id     = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
client_secret = your-sp-secret
```

Or use environment variables (`DATABRICKS_CLIENT_ID`, `DATABRICKS_CLIENT_SECRET`, `DATABRICKS_ACCOUNT_ID`) or explicit `--client-id` / `--client-secret` / `--account-id` flags. Named profiles work too: `--profile prod`.

## Quick start

```bash
# What can alice access across all workspaces?
databricks-access-audit --principal "alice@company.com"

# Full picture — workspace objects, escalation risks, export to CSV
databricks-access-audit --principal "alice@company.com" \
  --scan-workspace-objects \
  --escalation-check \
  --output csv > alice_$(date +%F).csv

# What does data-engineers access? Who has redundant personal grants?
databricks-access-audit --group "data-engineers"

# Deep scan with schema grants + REVOKE SQL for cleanup
databricks-access-audit --group "data-engineers" \
  --scan-schemas \
  --revoke-script

# Compare against last quarter's snapshot
databricks-access-audit --group "data-engineers" \
  --baseline snapshots/data-engineers_2025-01-01.json \
  --save-snapshot snapshots/data-engineers_$(date +%F).json \
  --output csv
```

## Documentation

**[https://lukaleet.github.io/databricks-access-audit](https://lukaleet.github.io/databricks-access-audit)**

- [Getting Started](https://lukaleet.github.io/databricks-access-audit/getting-started/) — install, credentials, first audit
- [Capabilities](https://lukaleet.github.io/databricks-access-audit/capabilities/) — how each feature works with examples
- [Use Cases](https://lukaleet.github.io/databricks-access-audit/use-cases/offboarding/) — offboarding, access review, incident response, compliance
- [CLI Reference](https://lukaleet.github.io/databricks-access-audit/reference/cli/) — every flag documented
- [Python API](https://lukaleet.github.io/databricks-access-audit/reference/python-api/) — use as a library

## Development

```bash
pip install -e ".[sdk,dev]"
pytest          # 477 tests, no real Databricks connection required
ruff check .
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
