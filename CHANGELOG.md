# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.19.0] - 2026-05-07

### Added
- **Resource audit (`--resource`)** — new audit mode that inverts the principal/group perspective: given a Unity Catalog resource (catalog, schema, or table) or a workspace, discover every identity that has access to it. Auto-detects resource type from the name format: 0 dots = catalog, 1 dot = schema, 2+ dots = table, `https://` or "databricks" in the name = workspace.
- **`--no-expand-groups`** — for `--resource` mode, show only the direct grants on the resource without expanding group members to individual users and service principals. Default is to expand groups.
- **`ResourceAuditor`** (`resource_auditor.py`) — parallel workspace scanner, SCIM-based principal classification with cache, group membership expansion via `GroupMembershipResolver`, deduplication by `(principal_name, via_group, frozenset(privileges))`.
- **`ResourceGrant` / `ResourceAuditResult`** models in `models.py`.
- **`_resource_html_renderer.py`** — self-contained HTML page with teal gradient header, stat cards, Mermaid LR flowchart (resource → direct principals, group nodes → member nodes with dashed edges), direct grants table, and via-group grants table.
- **`write_resource_audit_csv()`** in `csv_output.py` — CSV with 8 columns: `resource_type`, `resource_name`, `principal_name`, `principal_type`, `principal_source`, `privileges`, `via_group`, `workspace_name`.
- `detect_resource_type()` module-level utility function exported from `resource_auditor.py`.

### Tests
- 567 tests (up from 527 before this release cycle): 37 new tests covering `detect_resource_type`, `_classify_principal` (email / group / SP / default / cache), `_scan_uc_resource` (catalog, 404 silence, group expansion, no-expand), `_scan_workspace_resource` (basic, expand), `audit()` catalog/workspace modes (result type, dedup, not-found error), model field checks, HTML renderer (resource name, Mermaid, no-grants, HTML escaping, via-group section), CSV column header/data/via-group, and full CLI integration (text/csv/json/html output, workspace-not-found → exit 1, mutual-exclusion with `--group`).

---

## [0.18.7] - 2026-05-07

### Fixed
- **Principal `--tree` and `--output html`**: direct workspace assignments (`ADMIN` set explicitly on the principal, not via a group) were rendering as a fake `via  (direct)` group section instead of the "Direct" block.  Root cause: `principal_auditor.py` sets `via_group="(direct)"` on direct `WorkspaceRole` objects; the renderers bucketed by `r.via_group or "__direct__"` but `"(direct)"` is truthy so it never reached the `__direct__` sentinel.  Fixed in both `_tree_renderer.py` and `_html_renderer.py` to treat `via_group == "(direct)"` identically to `None`.
- **Group `--tree`**: Unity Catalog rows were showing the group/principal name in the workspace column instead of the workspace name.  Root cause: `_print_uc` used `*_, ws` to unpack the grant tuple, grabbing `principal` (last element) instead of `workspace_name` (second-to-last).  Fixed with explicit unpacking.

---

## [0.18.6] - 2026-05-07

### Added
- **Group audit `--tree`** — ASCII tree view for `--group` mode, organised by grant source rather than securable type.  Upstream (parent-group-inherited) grants are shown per parent group; direct grants the group holds itself form their own branch; member-direct personal grants appear in a compact summary with redundancy warnings.  Workspace objects included when `--scan-workspace-objects` is set.  Redundancy callout line printed before the footer when full or partial overlaps are found.

### Tests
- 527 tests (up from 525): 2 new tests for group audit `--tree` output structure and member-count presence.

---

## [0.18.5] - 2026-05-07

### Added
- **Group audit `--output html`** — self-contained HTML page for `--group` mode.  Green-themed header with IdP vs Databricks classification, member counts, and timestamp.  Mermaid LR flowchart showing the group's access footprint: parent groups (dashed edges), workspaces, and UC catalogs.  Summary stats grid highlights redundant grant count in amber when non-zero.  Redundancy findings are surfaced in a prominent banner and dedicated table before the full grant list.  Combined Unity Catalog grants table (catalog + schema + table) with grant-source tags.  Progress messages routed to stderr.
- **Snapshot diff `--output html`** — self-contained HTML diff page for `--baseline` mode.  Works for both group and principal audits.  Slate-themed header with a baseline → current timeline.  Summary cards show +/− counts for grants and members in green/red.  Color-coded rows: green background for additions, red for removals.  Renders a clean "No changes detected" state when there are no differences — suitable for committing to a repo as a compliance artifact.  `--output html` now supported in `_print_diff` which is shared by both audit modes.

### Fixed
- `_log` in `_run_group_audit` now routes progress messages to stderr for all non-`text` output modes (was only routing for json).

### Tests
- 525 tests (up from 519): 6 new tests covering group audit HTML output structure, section headings, progress-to-stderr isolation, diff HTML no-changes state, diff HTML with additions and removals, and diff HTML principal-mode member label.

---

## [0.18.4] - 2026-05-06

### Added
- **`--output html`** — self-contained HTML access map for principal audit.  Embeds a Mermaid LR flowchart (principal → groups → workspaces + UC securables) with solid edges for direct group memberships and dashed edges for transitive ones.  Includes a summary stats grid and four data tables (group memberships, workspace access, UC permissions, workspace objects).  No server required — one file, renders in any browser.  Progress messages are routed to stderr so the HTML on stdout is clean.
- **`--tree`** — ASCII tree view for principal audit, reorganising output by granting entity rather than securable type.  Each section shows "via <group>" with the workspace roles and UC grants beneath it; direct grants and workspace objects have their own nodes; escalation findings appear when `--escalation-check` is set.
- **Visualizing Access use-case page** — `docs/use-cases/access-map.md` covering when to use `--tree` vs `--output html` vs CSV, how to compose with `--scan-workspace-objects` and `--escalation-check`, and the "show this to a manager" scenario.
- **CLI reference updated** — `docs/reference/cli.md` now documents `--output html` and `--tree` with examples.

### Fixed
- Progress messages (`Auditing principal: …`) were leaking onto stdout in `--output html` mode.  `_log` in `_run_principal_audit` now routes to stderr for all non-text output modes (json, csv, html).

### Tests
- 519 tests (up from 513): 6 new tests in `tests/test_cli.py` covering `--tree` output structure, `--output html` content, HTML progress-to-stderr isolation, and `--tree` with `--output json`.

---

## [0.18.3] - 2026-05-05

### Added
- **`--compare A B`** — pure-read membership diff between two principals.  Shows which groups are unique to each principal and which are shared.  Each group is annotated with source (`external` = IdP-managed, `internal` = Databricks-managed), directness (`is_direct`), and the full membership chain.  Available in `text`, `json`, and `csv` output formats.
- **`--clone-from SOURCE --to TARGET`** — provisioning report that classifies each of the source's direct group memberships into one of four actions:
  - `Databricks` — the group is Databricks-managed and has a workspace assignment or UC grants; the tool can perform the SCIM PATCH when `--apply` is passed.
  - `IdP required` — the group is synced from an external IdP (Entra / Okta); the target must be added in the identity provider — Databricks has no write access to IdP-managed group membership.
  - `Unverified` — the group is Databricks-managed but has no detected workspace assignment; UC grants are not checked by default (pass `--scan-uc` to resolve these into `Databricks` or `Skipped`).
  - `Skipped` — verified dead-end: no workspace assignment and no UC grants (requires `--scan-uc`).
- **`--apply`** — when passed alongside `--clone-from / --to`, executes the SCIM PATCH for every `Databricks`-classified group, adding the target to each group.
- **`--scan-uc`** — optional flag for `--clone-from`; scans Unity Catalog catalog grants in parallel to resolve `Unverified` groups into `Databricks` (has grants) or `Skipped` (dead-end).  Adds catalog-scan API calls per workspace, so it is off by default.
- **`PrincipalComparer`** — Python API class wrapping the compare logic.  Takes two principal identifiers, BFS-walks group memberships for both, and returns a `CompareResult`.
- **`AccessCloner`** — Python API class with `build_report()` (dry-run analysis) and `apply()` (SCIM writes).  `apply()` mutates the `CloneReport` in place, setting `applied=True` or `error=...` per action.
- **New models** — `GroupComparison`, `CompareResult`, `CloneActionType`, `CloneAction`, `CloneReport` in `models.py`.
- **CSV output functions** — `write_compare_csv()` and `write_clone_report_csv()` in `csv_output.py`.
- **Access Provisioning use-case page** — `docs/use-cases/access-provisioning.md` covering the "match one user's access to another" scenario with CLI and Python API examples, IdP vs Databricks group classification explanation, and `--scan-uc` guidance.

### Tests
- 513 tests (up from 477): 12 new tests in `tests/test_principal_comparer.py`, 10 new tests in `tests/test_access_cloner.py`, 22 new tests in `tests/test_cli.py` (compare and clone modes across all output formats, `--apply` success/error paths, missing `--to` guard, mutually-exclusive mode validation).

---

## [0.18.2] - 2026-05-04

### Added
- **`uc_only_groups` in principal audit** — groups with no workspace permission assignment but that still grant Unity Catalog access are now separated from true dead-end groups.  `PrincipalAuditResult` gains a new `uc_only_groups: List[str]` field.  Text output shows two labelled buckets: *UC-only groups* (intentional pattern — access via UC grants only) and *Unused groups* (no workspace or UC grants — safe to review for removal).  JSON and CSV output include both fields.
- **`via_path` inheritance chain on workspace roles and UC permissions** — `WorkspaceRole` and `EffectivePermission` now carry `via_path: List[str]` (the full membership chain from the principal to the grant-holding group, e.g. `["alice@company.com", "team-A", "data-engineers"]`).  Built from the BFS walk at zero extra API cost.  Text output shows the chain in brackets; CSV adds a `via_path` column; JSON and snapshots include the field.  Parallel paths (same securable reachable via multiple groups) each appear as separate entries with distinct chains.
- **Permission Hygiene and Stale Access use-case pages** — `docs/use-cases/permission-hygiene.md` and `docs/use-cases/stale-access.md` added to the docs site, covering redundancy analysis, REVOKE SQL generation, `--stale-days` usage, SQL warehouse prerequisites, threshold tuning, and Python API examples.

### Tests
- 3 CSV tests updated to account for the new `via_path` column in workspace-roles and permissions headers.
- `test_dead_end_groups_detected` renamed to `test_workspace_unassigned_groups_split_into_uc_only_and_dead_end`; updated assertions verify groups with UC grants land in `uc_only_groups` and groups with no grants land in `dead_end_groups`.
- `test_cli.py` asserts `uc_only_groups` key present in principal JSON output.

---

## [0.18.1] - 2026-05-05

### Added
- **MkDocs documentation site** — full docs published to GitHub Pages at `https://lukaleet.github.io/databricks-access-audit`. Sections: Getting Started, Capabilities, Use Cases (offboarding, access review, incident response, compliance snapshots), Reference (CLI flags, Python API, output formats), How It Works (architecture, grant classification, Azure B2B guests).
- **Capabilities page** — each core feature (multi-workspace scanning, recursive group resolution, permission inheritance tracking, schema drill-down, redundancy analysis, resilient API calls) documented with example commands and sample output.
- **GitHub Actions docs workflow** (`.github/workflows/docs.yml`) — automatically redeploys the site on every push to `main` that touches `docs/` or `mkdocs.yml`.
- **`[docs]` optional dependency** — `pip install "databricks-access-audit[docs]"` installs `mkdocs-material` for local doc builds.
- **README slimmed to ~100 lines** — hook, two modes, capabilities list, quick-start examples, and links to the full docs site. Detailed reference content moved to GitHub Pages.
- **`~/.databrickscfg` profile-based authentication** — credentials are now resolved in priority order: CLI flags → environment variables → `~/.databrickscfg` profile → default `azure` cloud.  New `--profile NAME` flag (env: `DATABRICKS_CONFIG_PROFILE`, default: `DEFAULT`) selects a named profile.  `DATABRICKS_CONFIG_FILE` points to a non-default config file path.
- **Cloud auto-detection from profile host** — when `--cloud` is not explicitly passed, the cloud provider is inferred from the `host` field in the profile (`accounts.azuredatabricks.net` → `azure`, `accounts.cloud.databricks.com` → `aws`, `accounts.gcp.databricks.com` → `gcp`).  No need to pass `--cloud` on every invocation when using a profile.
- **New module `config.py`** — `load_profile()` reads named sections from `~/.databrickscfg` (merging `DEFAULT` fallbacks via `configparser`); `cloud_from_host()` maps account host URLs to cloud identifiers.
- **Improved credential error message** — when credentials are missing, the error now mentions `--profile` and `~/.databrickscfg` as the resolution path.
- **Package renamed** — `databricks-group-audit` → `databricks-access-audit`; module renamed `databricks_group_audit` → `databricks_access_audit`; CLI command renamed to `databricks-access-audit`.

### Tests
- 477 tests (up from 451): 14 new tests in `tests/test_config.py` covering `load_profile` and `cloud_from_host`; 12 new integration tests in `tests/test_cli.py` covering `_resolve_credentials`.

---

## [0.18.0] - 2026-04-30

### Added
- **8 new workspace object types** — `WorkspaceObjectScanner` now covers 13 object types (up from 5):
  - *SQL / Analytics*: `sql_queries` (`/api/2.0/sql/queries`), `sql_alerts` (`/api/2.0/sql/alerts`), `lakeview_dashboards` (`/api/2.0/lakeview/dashboards`), `genie_spaces` (`/api/2.0/genie/spaces`)
  - *AI / ML*: `mlflow_experiments` (`/api/2.0/mlflow/experiments/list`), `registered_models` (`/api/2.0/mlflow/registered-models/list`), `serving_endpoints` (`/api/2.0/serving-endpoints`), `apps` (`/api/2.0/apps`)
  - All use the same `classify_grant` path and are available via `--workspace-object-types` filtering.
  - Agent Bricks coverage comes from the three AI/ML types (experiments, registered models, serving endpoints) that underpin the platform.
- **Bare-array response handling in `_list_objects`** — some DBSQL endpoints return a raw JSON array instead of a wrapped dict; `_list_objects` now detects `isinstance(resp, list)` and handles both shapes without error.

### Fixed
- **Azure AD B2B guest UPN mismatch (improved)** — `_get_workspace_principal_aliases()` now searches workspace SCIM by `externalId eq "{id}"` instead of looking up the account-synced record by principal ID.  Azure AD B2B guest users have *two* workspace SCIM records: the account-synced record (userName = account email) and the Azure AD guest record (userName = guest UPN, e.g. `user_gmail.com#EXT#@tenant`).  The previous ID-lookup only returned the account email (already known), so the guest UPN was never discovered and workspace ACL entries stored under that UPN were silently missed.  The externalId search returns both records; only userNames not already in known identities are returned as new aliases.
- **Workspace object scan misses implicit-group workspaces** — when a principal's workspace access comes exclusively through a built-in group like "account users" (which doesn't appear in `permissionassignments`), `ws_roles` was empty and the workspace object scan loop never ran, producing 0 grants.  `audit()` now also supplements `ws_roles` with all discovered workspaces when `scan_workspace_objects=True`, matching the behaviour of the group audit scanner.

### Tests
- 451 tests (up from 427): 8 parametrized group-audit smoke tests, 8 parametrized principal-audit smoke tests, bare-array resilience test, pagination test for `mlflow_experiments`, name-as-ID test for `registered_models`, non-standard perm-prefix test for `genie_spaces`, non-pagination test for `serving_endpoints`; 2 new tests for `_get_workspace_principal_aliases` externalId search (B2B guest discovery); 1 new test for workspace object scan fallback to all discovered workspaces when `ws_roles` is empty.

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

- **Azure AD B2B guest UPN mismatch in workspace object scan (initial fix)** — added `_get_workspace_principal_aliases()` to `PrincipalAuditor`; superseded and extended in v0.18.0 with externalId-based search.

### Tests
- 427 tests (up from 389): 31 new tests in `test_workspace_object_scanner.py`; new coverage in `test_sdk_client.py`, `test_cli.py`, `test_csv_output.py`, and `test_snapshot.py` for the workspace object scanning feature; 2 bug-fix tests (infinite-loop and retry hang); 5 new tests in `TestGetWorkspacePrincipalAliases` covering alias extraction, identity match, SP skip, API failure, and case-insensitive match.

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
