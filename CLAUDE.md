# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install for development
pip install -e ".[sdk,dev]"

# Run all tests
pytest

# Run a single test file
pytest tests/test_catalog_scanner.py

# Run a single test by name
pytest tests/test_redundancy.py::test_full_redundancy

# Lint
ruff check .

# Run the CLI (group audit)
databricks-group-audit --group "data-engineers" --cloud azure

# Run the CLI (principal audit)
databricks-group-audit --principal "alice@example.com" --cloud azure --escalation-check
```

## Architecture

The tool audits Databricks group membership and Unity Catalog permissions across all workspaces in an account. It has two modes: **group audit** (what does a group access, who has redundant personal grants?) and **principal audit** (what can a specific user/SP/group access across the account?).

### Client layer

`client.py` defines the `AuditClient` structural Protocol — both backends must satisfy it. `DatabricksAPIClient` (raw HTTP, zero extra deps beyond `requests`) handles OAuth client-credentials with per-host token caches, exponential-backoff retry on 429/5xx, and manual SCIM pagination. `sdk_client.py` wraps `databricks-sdk` for automatic auth/pagination/retries and is only imported when the package is installed. `create_client()` is the factory used everywhere — it returns the SDK client when available, raw HTTP otherwise. Pass `prefer_sdk=False` or `--no-sdk` to force raw HTTP.

### Data flow — group audit

1. `group_resolver.py` — walks SCIM to build a `GroupNode` tree (nested groups, users, SPs). Bulk pre-fetches all users and SPs to avoid N+1 calls. Reads `externalId` from SCIM to tag each member as IdP-synced or Databricks-managed.
2. `workspace.py` — discovers workspaces via the Account API (or explicit URLs).
3. `catalog_scanner.py` → `schema_scanner.py` → `table_scanner.py` — fetches UC grants at progressively deeper levels; all call `classify_grant()` from `_classification.py`.
4. `_classification.py` — `classify_grant()` and `build_member_lookups()` shared by all scanners. Classifies each grant as `GrantSource.DIRECT`, `UPSTREAM`, or `MEMBER_DIRECT`.
5. `redundancy.py` — compares member-direct grants against the group's effective privileges (with `ALL_PRIVILEGES` expansion) to produce `RedundancyLevel.FULL/PARTIAL/NONE`.
6. `revoke.py` — generates copy-paste REVOKE SQL from `RedundancyResult` objects.

### Data flow — principal audit

`principal_auditor.py` resolves a user/SP/group via SCIM (returning a 4-tuple including `external_id`), BFS-walks upward through all group memberships, queries `/permissionassignments` per workspace in parallel (`get_workspace_assignments`, `ThreadPoolExecutor`), then scans UC grants per unique workspace URL in parallel (`scan_permissions` → `_scan_one_workspace`; workspace-level dedup happens upfront, catalog-level dedup is local to each worker). Dead-end groups (no workspace assignment) are detected and reported. `audit()` accepts `max_workers` and threads it to both parallel steps. `_get_workspace_principal_alias()` queries workspace SCIM (`/api/2.0/preview/scim/v2/Users/{id}`) per workspace to resolve Azure AD B2B guest UPNs (e.g. `user_gmail.com#EXT#@tenant`) that differ from the account-level email; the alias is passed to `scan_workspace_for_principal` so ACL matches aren't missed.

### Security and compliance features

- `elevate.py` — `PermissionElevator` context manager: temporarily grants Workspace Admin to the audit SP on each workspace, then restores prior state on exit (success or failure). Used by `--auto-elevate`.
- `escalation.py` — `detect_escalations()` flags `ALL_PRIVILEGES` and `MANAGE` grants in a `PrincipalAuditResult`. Used by `--escalation-check`.
- `stale_checker.py` — `StaleGrantChecker` executes SQL against `system.access.audit` via the Statement Execution API to find principals with no recent activity. `_execute_statement` raises `RuntimeError` on failure (caller catches to avoid false positives). Used by `--stale-days`.
- `local_groups.py` — `LocalGroupChecker` compares workspace SCIM (`/api/2.0/preview/scim/v2/Groups`) against account SCIM to find legacy workspace-local groups. Used by `--check-local-groups`.

### Output features

- `csv_output.py` — `write_group_audit_csv()` and `write_principal_audit_csv()` render results as CSV (grants + redundancy + workspace objects / permissions + escalations + workspace objects). `write_diff_csv()` renders an `AuditDiff`. Used by `--output csv`.
- `snapshot.py` — `build_group_snapshot()` / `build_principal_snapshot()` serialise audit results to a plain-dict JSON format. `save_snapshot()` / `load_snapshot()` persist to disk. `diff_snapshots()` compares two snapshots by full-field fingerprint (grants) and identity key (members) to produce an `AuditDiff`. Used by `--save-snapshot` / `--baseline`.
- `workspace_object_scanner.py` — `WorkspaceObjectScanner` scans workspace-level ACLs (13 types: jobs, clusters, cluster policies, pipelines, SQL warehouses, SQL queries, SQL alerts, Lakeview dashboards, Genie spaces, MLflow experiments, registered models, serving endpoints, apps) via `/api/2.0/permissions/`. Fans out with `ThreadPoolExecutor` per object type; reuses `classify_grant` from `_classification.py`. Used by `--scan-workspace-objects`.

### Models

All dataclasses and enums live in `models.py`:

| Model | Purpose |
|---|---|
| `GroupMember`, `GroupNode` | SCIM group tree; both have `external_id` and `source: PrincipalSource` |
| `PrincipalSource` | Enum: `EXTERNAL` (has SCIM `externalId`) / `INTERNAL` (Databricks-managed) |
| `WorkspaceInfo` | Workspace metadata |
| `CatalogGrant`, `SchemaGrant`, `TableGrant` | UC permission grant at each level |
| `GrantSource` | `DIRECT`, `UPSTREAM`, `MEMBER_DIRECT` |
| `RedundancyResult`, `RedundancyLevel` | Redundancy analysis output |
| `GroupMembership`, `WorkspaceRole`, `EffectivePermission`, `PrincipalAuditResult` | Principal audit output |
| `EscalationFinding` | `ALL_PRIVILEGES` / `MANAGE` escalation risk |
| `StaleFinding` | Member-direct grant with no recent `system.access.audit` activity |
| `LocalGroupFinding` | Group present in workspace SCIM but absent from account SCIM |
| `WorkspaceObjectGrant` | Workspace-level ACL grant (job/cluster/warehouse/pipeline/policy); `object_type`, `object_id`, `object_name`, `permission_level`, `grant_source`, `principal_type`, `inherited_from` |
| `AuditDiff` | Delta between two snapshots; `has_changes` property |

### Tests

Tests use the `responses` library (HTTP mocking, no real Databricks connection). `tests/conftest.py` defines shared SCIM/UC mock data and three fixtures: `mock_client`, `mock_scim`, `mock_uc`. Each module has its own test file. 448 tests total.
