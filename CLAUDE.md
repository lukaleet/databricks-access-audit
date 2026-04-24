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

# Run the CLI
databricks-group-audit --group "data-engineers" --cloud azure
```

## Architecture

The tool audits Databricks group membership and Unity Catalog permissions across all workspaces in an account. It has two modes: **group audit** (what does a group access, who has redundant personal grants?) and **principal audit** (what can a specific user/SP/group access across the account?).

### Client layer

`client.py` defines the `AuditClient` structural Protocol — both backends must satisfy it. `DatabricksAPIClient` (raw HTTP, zero extra deps beyond `requests`) handles OAuth client-credentials with per-host token caches, exponential-backoff retry on 429/5xx, and manual SCIM pagination. `sdk_client.py` wraps `databricks-sdk` for automatic auth/pagination/retries and is only imported when the package is installed. `create_client()` is the factory used everywhere — it returns the SDK client when available, raw HTTP otherwise. Pass `prefer_sdk=False` or `--no-sdk` to force raw HTTP.

### Data flow — group audit

1. `group_resolver.py` — walks SCIM to build a `GroupNode` tree with all nested groups, users, and SPs. Uses bulk pre-fetch of all groups then resolves members by ID.
2. `workspace.py` — discovers workspaces via the Account API (or explicit URLs).
3. `catalog_scanner.py` → `schema_scanner.py` → `table_scanner.py` — each fetches UC grants at progressively deeper levels; all call `classify_grant()` from `_classification.py`.
4. `_classification.py` — shared `classify_grant()` and `build_member_lookups()` used by all three scanners. Classifies each grant as `GrantSource.DIRECT` (group itself), `UPSTREAM` (parent group), or `MEMBER_DIRECT` (individual user/SP personal grant).
5. `redundancy.py` — compares member-direct grants against the group's effective privileges (with `ALL_PRIVILEGES` expansion) to produce `RedundancyLevel.FULL/PARTIAL/NONE`.
6. `revoke.py` — generates copy-paste REVOKE SQL from `RedundancyResult` objects.

### Data flow — principal audit

`principal_auditor.py` resolves a user/SP/group via SCIM, BFS-walks upward through all group memberships, queries `/permissionassignments` per workspace, then scans UC grants for each accessible workspace. Dead-end groups (member of group with no workspace assignment) are detected and reported.

### Models

All dataclasses and enums live in `models.py`: `GroupNode`, `GroupMember`, `WorkspaceInfo`, `CatalogGrant`/`SchemaGrant`/`TableGrant`, `RedundancyResult`, and the principal-audit models `GroupMembership`, `WorkspaceRole`, `EffectivePermission`, `PrincipalAuditResult`.

### Tests

Tests use the `responses` library (HTTP mocking, no real Databricks connection needed). `tests/conftest.py` defines shared SCIM/UC mock data and three fixtures: `mock_client` (bare client), `mock_scim` (SCIM endpoints mocked), `mock_uc` (SCIM + Unity Catalog endpoints mocked). Tests for each scanner/module are in their own file.
