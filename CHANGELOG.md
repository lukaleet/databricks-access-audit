# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.18.0] - 2026-04-30

### Added
- **8 new workspace object types** — `WorkspaceObjectScanner` now covers 13 object types (up from 5):
  - *SQL / Analytics*: `sql_queries` (`/api/2.0/sql/queries`), `sql_alerts` (`/api/2.0/sql/alerts`), `lakeview_dashboards` (`/api/2.0/lakeview/dashboards`), `genie_spaces` (`/api/2.0/genie/spaces`)
  - *AI / ML*: `mlflow_experiments` (`/api/2.0/mlflow/experiments/list`), `registered_models` (`/api/2.0/mlflow/registered-models/list`), `serving_endpoints` (`/api/2.0/serving-endpoints`), `apps` (`/api/2.0/apps`)
  - All use the same `classify_grant` path and are available via `--workspace-object-types` filtering.
  - Agent Bricks coverage comes from the three AI/ML types (experiments, registered models, serving endpoints) that underpin the platform.
- **Bare-array response handling in `_list_objects`** — some DBSQL endpoints return a raw JSON array instead of a wrapped dict; `_list_objects` now detects `isinstance(resp, list)` and handles both shapes without error.

### Tests
- 448 tests (up from 427): 8 parametrized group-audit smoke tests, 8 parametrized principal-audit smoke tests, bare-array resilience test, pagination test for `mlflow_experiments`, name-as-ID test for `registered_models`, non-standard perm-prefix test for `genie_spaces`, non-pagination test for `serving_endpoints`.

---

## [0.17.0] - 2026-04-28

### Added
- **Workspace object permission scanning** — new `--scan-workspace-objects` flag scans workspace-level ACLs for jobs, clusters, SQL warehouses, pipelines, and cluster policies.  Off by default (adds significant API calls per workspace).  Use `--workspace-object-types jobs,clusters` to restrict to a subset.  Works in both `--group` and `--principal` modes.
- **`WorkspaceObjectGrant` model** — mirrors `CatalogGrant` / `SchemaGrant` / `TableGrant`; carries `object_type`, `object_id`, `object_name`, `permission_level`, `grant_source` (`DIRECT` / `UPSTREAM` / `MEMBER_DIRECT`), `principal_type`, and `inherited_from`.
- **`WorkspaceObjectScanner`** — new `workspace_object_scanner.py`; fans out with `ThreadPoolExecutor` per object type, reuses `classify_grant` from `_classification.py`, handles pagination for jobs and pipelines, skips objects on ACL errors.  Deduplicates workspace URLs before dispatch.
- **CLI output** — group audit gets a new `Workspace Object Permissions` section in text output; principal audit gets the same.  JSON output gains `workspace_object_grants` (group) and `workspace_object_permissions` (principal) arrays.  CSV output gains a third section after the redundancy table.  All outputs include a note that remediation requires the Databricks permissions REST API, not SQL.
- **Snapshot / diff** — `build_group_snapshot` and `build_principal_snapshot` include workspace object grants; `diff_snapshots` diffs them by full-field fingerprint alongside UC grants.
- **SDK client routes** — `DatabricksSDKClient.workspace_api` now handles all five object-list endpoints via SDK typed iterators (auto-pagination) and all `/api/2.0/permissions/…` paths via raw REST (`ws.api_client.do`) to avoid gRPC shim issues.
- **`PrincipalAuditor.audit()`** — two new parameters: `scan_workspace_objects: bool = False` and `workspace_object_types: Optional[List[str]] = None`.

### Fixed
- **Infinite loop in `_list_objects` pagination test** — `test_list_objects_pagination` in `test_workspace_object_scanner.py` used `if not calls[0]` to branch between the first and subsequent page responses; `calls[0]` is always `{}` (the first call's empty params dict), so the mock always returned `next_page_token`, sending `_list_objects` into an infinite loop that exhausted RAM and crashed the process.  Fixed by checking `if not params` (the current call's params) instead.
- **Retry-backoff hang in `test_principal_source.py`** — the local `mock_client` fixture used default `max_retries=5, base_delay=1.0`; any URL not registered in the `responses` mock raised `requests.exceptions.ConnectionError`, which is a `RequestException` and triggered five retries with 1+2+4+8+16 = 31 s of backoff per unmatched request.  Fixed by adding `max_retries=0, base_delay=0` to the fixture.

- **Azure AD B2B guest UPN mismatch in workspace object scan** — when `--scan-workspace-objects` is used for an Azure AD B2B guest user, the principal's account SCIM identity (e.g. `user@gmail.com`) does not match the workspace ACL identity (e.g. `user_gmail.com#EXT#@tenant.onmicrosoft.com`), causing 0 workspace object grants to be returned.  `PrincipalAuditor` now calls `_get_workspace_principal_alias()` per workspace before scanning: it queries `GET /api/2.0/preview/scim/v2/Users/{id}` on the workspace SCIM endpoint, and if the workspace `userName` differs from the account email, adds it as an alias passed to `scan_workspace_for_principal`.  Non-users (SPs, groups) and workspaces where the SCIM call fails are silently skipped (alias = `None`), preserving the existing behaviour.

### Tests
- 427 tests (up from 389): 31 new tests in `test_workspace_object_scanner.py`; new coverage in `test_sdk_client.py`, `test_cli.py`, `test_csv_output.py`, and `test_snapshot.py` for the workspace object scanning feature; 2 bug-fix tests (infinite-loop and retry hang); 5 new tests in `TestGetWorkspacePrincipalAlias` covering alias extraction, identity match, SP skip, API failure, and case-insensitive match.

---

## [0.16.0] - 2026-04-27

### Added
- **Parallel group membership map with session cache** — `GroupMembershipResolver.get_group_membership_map()` replaces the serial O(N) individual-GET loops in `catalog_scanner` and `principal_auditor`.  The Databricks SCIM list endpoint never returns the `members` field, so individual GETs are unavoidable; they now fire concurrently via `ThreadPoolExecutor` (default 16 workers) and the result is cached on the resolver instance for the lifetime of the session.  On a 300-group account with 8+ workers this reduces the membership-map build step by roughly an order of magnitude.
- **`PrincipalAuditor` accepts a shared `group_resolver`** — new optional constructor parameter `group_resolver: Optional[GroupMembershipResolver] = None`.  When passed, the auditor uses the provided instance (and its cache) instead of creating its own, eliminating duplicate O(N) fetches when group audit and principal audit run in the same session.  Backwards compatible: omitting the parameter behaves identically to before.
- **Notebook resolver sharing** — `pa_auditor` in cell 4 is now instantiated with the shared `group_resolver`, so running group audit followed by principal audit in the same notebook session reuses the cached membership map.

### Tests
- 352 tests (up from 342): 10 new tests in `test_group_resolver.py` covering map correctness, `child_to_parents` structure, cache hit behaviour, `_group_cache` warming, `clear_caches()` invalidation, empty-account edge case, failed-GET skipping, and three `PrincipalAuditor` integration tests.

---

## [0.15.1] - 2026-04-26

### Fixed
- **SCIM group membership resolution** — the Databricks SCIM group list endpoint (`GET /scim/v2/Groups`) never returns the `members` field regardless of client (SDK typed call, raw HTTP, `attributes=members` param); only individual `GET /scim/v2/Groups/{id}` includes members; `get_groups_containing_target` in `catalog_scanner` and `resolve_group_memberships` in `principal_auditor` both now fetch the ID/name list first and then do one GET per group to build the child-to-parent adjacency map; this caused upstream group detection and group membership tracing to silently return empty results on all runs against real Databricks accounts
- **SDK client group listing** — `DatabricksSDKClient.account_api` for `/scim/v2/Groups` and `scim_list_all("Groups")` now route through raw HTTP (`api_client.do`) rather than the SDK's `groups.list()` iterator, which also omits members; test suite updated accordingly

### Tests
- 342 tests: updated `test_sdk_client.py` group-listing tests to assert `api_client.do` call path and payload instead of `groups.list`

---

## [0.15.0] - 2026-04-26

### Fixed
- **Account OIDC token URL** — the raw HTTP client was calling `{account_host}/oidc/v1/token` (the workspace path); corrected to `{account_host}/oidc/accounts/{account_id}/v1/token` (the account-scoped path required by Databricks); this caused `invalid_request` 400 errors on every run using the raw HTTP client
- **Workspace OIDC fallback handles 401** — the `invalid_client` fallback to the account-level token previously only caught HTTP 400; Databricks also returns HTTP 401 with the same `invalid_client` body in some workspace configurations; the guard now checks `status_code in (400, 401)` so the fallback fires in both cases
- **SDK client grant queries** — `ws.grants.get(securable_type=SecurableType.CATALOG, …)` routes through a gRPC shim that returns `SECURABLETYPE.CATALOG is not a valid securable type` on some workspace versions; replaced all three grant endpoints (catalog, schema, table) with `ws.api_client.do("GET", endpoint)` to hit the REST path directly, matching the raw HTTP client and working on all workspace versions; this caused 0 grants returned for all catalogs when using the default SDK backend
- **Principal auditor UC grant matching** — `find_principal()` now returns a 5th value (`uc_name`): the SCIM `userName`, which is what Unity Catalog stores grants against; previously only `displayName` was matched, causing UC grants to be missed when `displayName ≠ userName` (most visibly for Azure AD guest users whose UC grants use their `#ext#` UPN); `scan_permissions` accepts a `principal_aliases` set and includes `uc_name` in the relevant-principal check
- **Notebook elevation safety** — the `ensure_workspace_admin` loop in both group-audit and principal-audit cells was called after `_elevator.__enter__()` but outside a try/except; if an exception was raised mid-loop, temporary Workspace Admin grants on already-processed workspaces were never revoked; both cells now wrap the loop in `try/except` that calls `__exit__(*sys.exc_info())` on failure, matching the CLI's cleanup guarantee
- **Notebook install cell** — added `dbutils.library.restartPython()` after `%pip install` so the newly installed package is picked up by the cluster driver without a manual restart
- **Notebook JSON format** — cell sources were accidentally serialised as a single string instead of the per-line list-of-strings format required by the `.ipynb` spec; corrected so the notebook opens correctly in Jupyter, VS Code, and Databricks
- **Workspace URL parsing for explicit `--workspace-urls`** — `parse_workspace_urls` failed to extract a numeric workspace ID from Azure (`adb-<id>.<region>.azuredatabricks.net`) and AWS URL formats; a regex now extracts the ID from the hostname so explicit workspace URLs work without requiring the Account API workspace list

### Tests
- 342 tests (up from 332): new tests in `test_client.py` for account/workspace OIDC URL construction and 401 `invalid_client` fallback; new tests in `test_principal_auditor.py` for `uc_name` return value; updated `test_sdk_client.py` grant tests to mock `ws.api_client.do` instead of `ws.grants.get`

---

## [0.14.0] - 2026-04-26

### Added
- **Top-members ranking in group audit** — after redundancy detection, members are ranked by personal (member-direct) catalog grant count; each entry includes the principal name, grant count, and redundancy level (`Full` / `Partial` / `None`), giving admins an instant cleanup shortlist; available in `--output text` (top 5 printed in the summary block), `--output json` (`top_members` array), and the Databricks notebook (`df_top_members` DataFrame)

### Fixed
- **Python 3.9 incompatible union type hint** — `str | None` in a function signature in `tests/test_cli.py` requires Python 3.10+; added `from __future__ import annotations` to restore 3.9 compatibility (same fix applied previously to `tests/test_workspace.py`)
- **Ruff lint violations** — `E501` (line too long) in `client.py:104` wrapped; `F401` unused imports (`time`, `pytest`) and `I001` import block formatting in `tests/test_client.py` cleaned up

### Tests
- 332 tests (up from 331): `test_group_audit_json_top_members_ranked` asserts `top_members` is present in JSON output and contains the expected principals and fields

---

## [0.13.0] - 2026-04-26

### Fixed
- **Schema / table grants had empty `workspace_name`** — the stub `WorkspaceInfo` objects constructed for parallel schema and table scans in `_run_group_audit` used a hardcoded `""` for `workspace_name`; the CLI now builds a `workspace_url → workspace_name` mapping from the discovered workspaces list and passes the correct name into each stub, so schema/table grants carry the right name in CSV and snapshot output
- **`log` undefined in `cli.py`** — `log.warning(...)` calls in the parallel schema/table scan error handlers referenced a name that was never imported/defined; added `import logging` and `log = logging.getLogger(__name__)` at module level
- **BFS queue in `get_groups_containing_target`** used `list.pop(0)` (O(n) per call); replaced with `collections.deque` + `popleft()` (O(1)) for better performance on deep group hierarchies
- **CLI JSON indentation** — `"principal_source"` key in the principal audit JSON dict was at the wrong indent level (valid Python but confusing); aligned with the other keys

### Tests
- 331 tests (up from 330): `test_scan_schemas_workspace_name_propagated` asserts the workspace_name flows through the scanner; `test_principal_audit_json_output` extended with `principal_source` key assertion

---

## [0.12.0] - 2026-04-26

### Fixed
- **REVOKE SQL quoting incomplete** — principals were only backtick-quoted when they contained `@` or a space, leaving group names with hyphens (e.g. `data-engineers`) and other non-alphanumeric characters unquoted; embedded backtick characters in any identifier (principal name, catalog name) were not escaped; the new `_bt()` helper unconditionally backtick-quotes every identifier and escapes embedded backticks by doubling them (`` ` `` → ` `` ``), matching the Spark SQL standard

### Tests
- 330 tests (up from 317): `_bt` unit tests (wrap, single/multiple escapes); parametrized `test_principal_always_backtick_quoted` across email / group / SP / space variants; `test_principal_with_embedded_backtick_escaped`; `test_catalog_with_embedded_backtick_escaped`; `test_principal_with_hyphen_is_quoted`; `test_principal_without_special_chars_still_quoted`

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
