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

!!! tip "SDK vs raw HTTP auth"
    When `databricks-sdk` is installed (the `[sdk]` extra), it handles authentication using its own resolution chain. If you store a PAT token in `~/.databrickscfg` and experience auth errors, add `--no-sdk` to force the raw HTTP client, which reads your profile directly.

## Service Principal permissions

The SP running the audit requires:

| Level | Required |
|---|---|
| **Databricks account** | Account Admin |
| **Each workspace** | Workspace Admin (recommended) |
| **Unity Catalog** | Metastore Admin, or `MANAGE` on every catalog to audit |

!!! tip "Just-in-time elevation"
    Use `--auto-elevate` to temporarily grant Workspace Admin to the SP on workspaces where it lacks that role, then restore the prior state after the audit. See [CLI reference](reference/cli.md#permission-elevation).

## Pick your starting point

Not sure which command to run? Start here.

| Your question | Command |
|---|---|
| What can alice access — workspaces, catalogs, objects? | `--principal "alice@company.com"` |
| What does data-engineers have access to? Who in it has personal grants? | `--group "data-engineers"` |
| **Who can access the main catalog?** | `--resource "main"` |
| **Who has a role on prod-workspace?** | `--resource "prod-workspace" --resource-type workspace` |
| Does thomas have the same access as sarah? What's different? | `--compare "thomas@company.com" "sarah@company.com"` |
| Onboard thomas — give him exactly what sarah has | `--clone-from "sarah@company.com" --to "thomas@company.com"` |
| Show alice's access as a visual diagram for a manager | `--principal "alice@company.com" --output html` |
| Show it as a compact tree in the terminal | `--principal "alice@company.com" --tree` |
| Has data-engineers' access changed since last quarter? | `--group "data-engineers" --baseline snapshots/Q1.json` |
| Does alice have any dangerous ALL_PRIVILEGES or MANAGE grants? | `--principal "alice@company.com" --escalation-check` |
| Who in data-engineers has redundant personal grants? Generate REVOKE SQL | `--group "data-engineers" --revoke-script` |
| Does alice own any jobs, clusters, or dashboards? | `--principal "alice@company.com" --scan-workspace-objects` |
| Export everything to a spreadsheet | add `--output csv` to any command |

See the [full decision guide](reference/quick-reference.md) for output formats, depth flags, and compliance workflows.

---

## Your first audit

### Principal audit — what can alice access?

```bash
databricks-access-audit --principal "alice@company.com"
```

```
============================================================
  Principal audit: alice@company.com (USER, external)
============================================================

  Group memberships (3, 3 IdP-synced, 0 Databricks-managed):
    * data-engineers (direct, external)
      path: alice@company.com → data-engineers
    - all-data-team (transitive, external)
      path: alice@company.com → data-engineers → all-data-team
    - platform-users (transitive, external)
      path: alice@company.com → data-engineers → all-data-team → platform-users

  Workspace access (1):
    * prod-workspace: USER (via data-engineers)

  UC permissions (4):
    [CATALOG] main:            USE_CATALOG, SELECT  via data-engineers   (prod-workspace)
    [CATALOG] raw:             USE_CATALOG          via all-data-team     (prod-workspace)
    [SCHEMA]  main.analytics:  USE_SCHEMA           via data-engineers   (prod-workspace)
    [TABLE]   main.analytics.events: SELECT         via data-engineers   (prod-workspace)
============================================================
```

The `*` prefix means direct group membership. `-` means transitive (inherited). Every grant shows the exact group path that provides it — so you know which group to change and what that change will affect downstream.

!!! note "0 workspace roles is expected for most users"
    The `permissionassignments` API returns only explicit `ADMIN` grants. Users who reach workspaces through the implicit "account users" group show 0 workspace roles here — that's normal Databricks behaviour. Their Unity Catalog permissions are still discovered correctly. See [Troubleshooting](troubleshooting.md) for details.

---

### Group audit — what does data-engineers access?

```bash
databricks-access-audit --group "data-engineers"
```

```
============================================================
  Group audit: data-engineers [external · 12 members]
============================================================

  Direct members (4 users, 1 SP):
    alice@company.com          (USER, external)
    bob@company.com            (USER, external)
    carol@company.com          (USER, external)
    david@company.com          (USER, external)
    etl-pipeline               (SERVICE_PRINCIPAL, external)

  UC permissions — Direct (2):
    [CATALOG] raw:             USE_CATALOG          (prod-workspace)
    [CATALOG] analytics:       USE_CATALOG, SELECT  (analytics-workspace)

  UC permissions — Upstream via all-data-team (1):
    [CATALOG] main:            USE_CATALOG, SELECT  (prod-workspace)

  UC permissions — Member Direct (redundant personal grants) (1):
    alice@company.com → [CATALOG] main: USE_CATALOG, SELECT  ⚠ FULL redundancy

  ⚠  1 member has personal grants fully covered by the group.
     Run --revoke-script to generate REVOKE SQL.
============================================================
```

---

### Resource audit — who can access this catalog?

```bash
databricks-access-audit --resource "main"
```

```
============================================================
  Resource audit: main (CATALOG)
============================================================

  Direct grants (2):
    GROUP               data-engineers      [external]  USE_CATALOG, SELECT
    USER                alice@company.com               USE_CATALOG, SELECT

  Via group (5 individuals):
    data-engineers (4 members):
      USER              alice@company.com               USE_CATALOG, SELECT
      USER              bob@company.com                 USE_CATALOG, SELECT
      USER              carol@company.com               USE_CATALOG, SELECT
      SERVICE_PRINCIPAL etl-pipeline                    USE_CATALOG, SELECT
============================================================
```

---

### Add workspace object scanning

Jobs, clusters, dashboards, pipelines and more — off by default, opt in with a flag:

```bash
databricks-access-audit --principal "alice@company.com" --scan-workspace-objects
```

---

### Export to CSV

```bash
databricks-access-audit --principal "alice@company.com" \
  --scan-workspace-objects \
  --output csv > alice_access_$(date +%F).csv
```

---

## Next steps

- [Quick reference — full decision guide](reference/quick-reference.md)
- [Principal audit — full walkthrough](use-cases/principal-audit.md)
- [Offboarding walkthrough](use-cases/offboarding.md)
- [Access provisioning — onboarding a new hire](use-cases/access-provisioning.md)
- [Resource audit — who has access to this catalog?](use-cases/resource-audit.md)
- [Access review workflow](use-cases/access-review.md)
- [Troubleshooting](troubleshooting.md)
- [Full CLI reference](reference/cli.md)
