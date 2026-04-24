# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
