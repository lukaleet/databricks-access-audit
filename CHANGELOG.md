# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.11.0] - 2026-04-25

### Added
- **`--workers N` now also applies to principal audit** — `get_workspace_assignments` and `scan_permissions` in `PrincipalAuditor` now accept `max_workers` and fan out with `ThreadPoolExecutor`; workspace permission-assignment queries run in parallel and each unique workspace is UC-scanned independently in parallel; `audit()` accepts and threads `max_workers` through both calls; `_run_principal_audit` in `cli.py` passes `args.workers`

### Changed
- `scan_permissions` refactored: duplicate workspace URLs are now deduplicated upfront (replacing the inline `seen_ws` set); the per-workspace catalog scan is extracted into `_scan_one_workspace()` (all state local, safe for concurrent execution); `scanned_catalogs` is keyed only on catalog name within each workspace call rather than `(url, name)` globally

### Tests
- 317 tests (up from 313): `test_parallel_two_workspaces_roles_merged`, `test_empty_workspaces_returns_empty`, `test_parallel_two_workspaces_perms_merged`, `test_full_audit_max_workers_one` in `test_principal_auditor.py`

---

## [0.10.0] - 2026-04-25

### Fixed
- **TokenCache used naive local datetime** — `get_token()` and `set_token()` now use `datetime.now(timezone.utc)` so token expiry comparisons are correct across DST boundaries and are consistent with the UTC timestamps used elsewhere in the codebase
- **Statement execution polling loop** — timeout was tracked as `elapsed += poll_interval` (inaccurate if `time.sleep()` overshoots; non-terminating when `poll_interval=0`); replaced with a wall-clock deadline via `time.monotonic()`
- **Bulk-fetch fallback logged at WARNING** — some account configurations legitimately cannot bulk-list SCIM users or SPs; the per-member fallback is fully supported and was downgraded from `WARNING` to `INFO` to eliminate false alerts in log-monitoring systems
- **Silent `{}` returns in SDK client** — three sites in `DatabricksSDKClient` that coerced unexpected response types to `{}` now emit a `DEBUG` log before returning so unexpected SDK-version surprises are observable in verbose output

### Tests
- 313 tests (up from 304): new `tests/test_client.py` with 8 `TokenCache` tests (UTC-awareness, expiry, thread safety, minimum-expiry floor); new `test_execute_statement_timeout_raises` in `test_stale_checker.py`

---

## [0.9.0] - 2026-04-25

### Added
- **Parallel scanning** (`--workers N`, default 8) — workspace, schema, and table scans now fan out with `ThreadPoolExecutor`; each workspace is scanned from its own vantage point so workspace-catalog bindings are respected; duplicate workspace URLs are silently deduplicated before dispatch
- `scan_all_workspaces` now accepts a `max_workers` parameter for programmatic use

### Fixed
- **SCIM filter injection** — group names, user emails, and SP identifiers are now escaped (backslash and double-quote) before being interpolated into SCIM filter expressions; unescaped values could produce malformed filters or match unintended principals
- **UTC timestamps** — JSON output `timestamp` fields were naive local-time strings; they are now always UTC with `+00:00` offset
- **Elevation cleanup leak** — if `ensure_workspace_admin` raised mid-loop, already-elevated workspaces were never revoked; the loop is now wrapped so cleanup runs unconditionally on any exception
- **`StaleFinding.last_access`** — was always `None` because the SQL query only covered the `stale_days` window; an extended `max_lookback_days` window (default `max(stale_days × 3, 365)`) is now used for the query and active-vs-stale classification is done in Python, so stale-but-historically-seen principals get a real date
- **Snapshot version validation** — `load_snapshot()` now raises `ValueError` on version mismatch instead of silently loading an incompatible schema
- **CSV output gaps** — `write_group_audit_csv` was missing the `additional_privileges` column in the redundancy section; `write_principal_audit_csv` omitted the group-memberships and workspace-roles sections entirely; `write_diff_csv` labelled the `external_id` member column `"source"`
- **Workspace token cache race** — `_get_workspace_token` used a non-atomic check-then-insert on `_workspace_token_caches`; replaced with `dict.setdefault()` so concurrent threads always share the same `TokenCache` object per host

### Tests
- 304 tests (up from 275): new tests for UTC timestamps, elevation cleanup, stale `last_access`, snapshot version validation, CSV column counts and section headers, `--workers` flag, parallel deduplication, and local-group pagination

---

## [0.8.0] - 2026-04-24

### Added
- **CSV output** (`--output csv`) - flat grant table plus redundancy/escalation sections; Excel-ready for auditors who won't run a CLI
- **Snapshot / diff mode** - `--save-snapshot PATH` writes a timestamped JSON snapshot after any audit run; `--baseline PATH` compares the current run against a previous snapshot and reports new grants, removed grants, new/removed members - SOC 2 / ISO 27001 compliance evidence workflow
- `AuditDiff` model with `has_changes` property
- `csv_output.py` - `write_group_audit_csv()`, `write_principal_audit_csv()`, `write_diff_csv()`
- `snapshot.py` - `build_group_snapshot()`, `build_principal_snapshot()`, `save_snapshot()`, `load_snapshot()`, `diff_snapshots()`
- Databricks notebook fully rewritten: inline fallback classes removed, all new features wired to widgets, `AuditResultBuilder` updated with source tagging and new DataFrame builders

---

## [0.7.0] - 2026-04-24

### Added
- **Identity source tagging** - every user, SP, and group is tagged `external` (IdP-provisioned via SCIM `externalId`) or `internal` (Databricks-managed)
- `PrincipalSource` enum and `_source_from_external_id()` helper in `models.py`
- `source` property on `GroupMember`, `GroupNode`, `GroupMembership`; `principal_source` property on `PrincipalAuditResult`
- Group audit text/JSON output shows `(N IdP-synced, M Databricks-managed)` breakdowns for users, SPs, and groups
- Principal audit text/JSON output shows per-principal and per-group source tags

---

## [0.6.0] - 2026-04-24

### Added
- **Privilege escalation detection** (`--escalation-check`, principal audit only) - flags `ALL_PRIVILEGES` and `MANAGE` grants inherited through group membership; `EscalationFinding` model; `escalation.py`
- **Stale grant detection** (`--stale-days N`) - cross-references member-direct catalog grants against `system.access.audit` via the Statement Execution API; flags principals with no recorded activity in the last N days; `StaleFinding` model; `stale_checker.py`; requires `--sql-warehouse-id`
- **Workspace-local group detection** (`--check-local-groups`) - scans workspace SCIM and flags groups absent from account SCIM (legacy pre-UC groups); `LocalGroupFinding` model; `local_groups.py`

---

## [0.5.0] - 2026-04-24

### Added
- **Just-in-time Workspace Admin elevation** (`--auto-elevate`) - temporarily grants the audit SP Workspace Admin on each workspace that lacks it, then restores the prior state after the audit (success or failure); `PermissionElevator` context manager; `elevate.py`
- `--dry-run-elevation` - previews which workspaces would be elevated without writing any changes

---

## [0.3.0] - 2026-04-01

### Added
- Initial public release
- **Group audit mode** (`--group`) - recursive SCIM group resolution, multi-workspace catalog/schema/table permission scanning, grant classification (`Direct` / `Upstream` / `Member Direct`), redundancy detection, copy-paste REVOKE SQL generation
- **Principal audit mode** (`--principal`) - reverse BFS lookup from user/SP/group through all group memberships and workspace assignments to effective UC permissions; dead-end group detection
- Dual client backends: `DatabricksAPIClient` (raw HTTP, always available) and `DatabricksSDKClient` (optional, wraps `databricks-sdk`); auto-selected by `create_client()`
- Multi-cloud support: Azure, AWS, GCP
- `--output text` and `--output json`
- `--scan-schemas` and `--scan-tables` depth flags
- Databricks notebook with Spark DataFrame output and optional Delta export
