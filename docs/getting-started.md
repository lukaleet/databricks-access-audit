# Getting Started

## Install

```bash
# Recommended — includes the Databricks SDK for automatic auth and retries
pip install "databricks-access-audit[sdk]"

# Core install — raw HTTP client only, no extra dependencies beyond requests
pip install databricks-access-audit
```

Requires Python 3.9 or later.

## Configure credentials

The tool needs three values to talk to the Databricks Account API:

| Value | What it is |
|---|---|
| `client_id` | Service Principal application (client) ID |
| `client_secret` | Service Principal secret |
| `account_id` | Databricks account ID (visible in the Account Console URL) |

### Option 1 — `~/.databrickscfg` (recommended)

Add a section to your `~/.databrickscfg`. The `host` field determines the cloud automatically.

```ini
[DEFAULT]
host          = https://accounts.azuredatabricks.net
account_id    = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
client_id     = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
client_secret = your-sp-secret
```

Then run without any credential flags:

```bash
databricks-access-audit --principal "alice@company.com"
```

Use named profiles for multiple environments:

```ini
[prod]
host          = https://accounts.azuredatabricks.net
account_id    = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
client_id     = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
client_secret = your-prod-secret

[staging]
host          = https://accounts.azuredatabricks.net
account_id    = yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
client_id     = yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
client_secret = your-staging-secret
```

```bash
databricks-access-audit --principal "alice@company.com" --profile prod
databricks-access-audit --principal "alice@company.com" --profile staging
```

### Option 2 — environment variables

```bash
export DATABRICKS_CLIENT_ID="your-sp-client-id"
export DATABRICKS_CLIENT_SECRET="your-sp-secret"
export DATABRICKS_ACCOUNT_ID="your-account-id"

databricks-access-audit --principal "alice@company.com" --cloud azure
```

### Option 3 — CLI flags

```bash
databricks-access-audit --principal "alice@company.com" \
  --client-id "your-sp-client-id" \
  --client-secret "your-sp-secret" \
  --account-id "your-account-id" \
  --cloud azure
```

Credentials are resolved in priority order: **CLI flags → env vars → `~/.databrickscfg` profile**.

## Service Principal permissions

The SP running the audit requires:

| Level | Required |
|---|---|
| **Databricks account** | Account Admin |
| **Each workspace** | Workspace Admin (recommended) |
| **Unity Catalog** | Metastore Admin, or `MANAGE` on every catalog to audit |

!!! tip "Just-in-time elevation"
    Use `--auto-elevate` to temporarily grant Workspace Admin to the SP on workspaces where it lacks that role, then restore the prior state after the audit. See [CLI reference](reference/cli.md#permission-elevation).

## Your first audit

### Principal audit — what can alice access?

```bash
databricks-access-audit --principal "alice@company.com"
```

Example output:

```
============================================================
  Principal audit: alice@company.com (USER, external)
============================================================

  Group memberships (2):
    * data-engineers (direct, external)
    - all-data-team (transitive, external)

  Workspace access (1):
    * prod-workspace: USER (via data-engineers)

  UC permissions (3):
    [CATALOG] main: USE_CATALOG, SELECT via data-engineers (prod-workspace)
    [SCHEMA]  main.analytics: USE_SCHEMA via data-engineers (prod-workspace)
    [TABLE]   main.analytics.events: SELECT via data-engineers (prod-workspace)
============================================================
```

### Group audit — what does data-engineers access?

```bash
databricks-access-audit --group "data-engineers"
```

### Add workspace object scanning

Jobs, clusters, dashboards, pipelines and more — off by default, opt in with a flag:

```bash
databricks-access-audit --principal "alice@company.com" --scan-workspace-objects
```

### Export to CSV

```bash
databricks-access-audit --principal "alice@company.com" \
  --scan-workspace-objects \
  --output csv > alice_access_$(date +%F).csv
```

## Next steps

- [Offboarding walkthrough](use-cases/offboarding.md)
- [Access provisioning — onboarding a new hire](use-cases/access-provisioning.md)
- [Access review workflow](use-cases/access-review.md)
- [Incident response](use-cases/incident-response.md)
- [Full CLI reference](reference/cli.md)
