# Architecture

The tool has two audit modes that share a common client layer and model layer but follow separate data flows.

---

## Client layer

`create_client()` is the factory used everywhere. It returns a `DatabricksSDKClient` when `databricks-sdk` is installed, or a `DatabricksAPIClient` (raw HTTP) otherwise.

Both backends implement the `AuditClient` structural Protocol — swap them freely with `--no-sdk` or `prefer_sdk=False`.

**`DatabricksAPIClient`** — zero extra dependencies beyond `requests`:

- OAuth2 client-credentials flow with per-host token caches
- Exponential backoff retry on 429/5xx (configurable)
- Manual SCIM pagination

**`DatabricksSDKClient`** — wraps `databricks-sdk`:

- Automatic auth (picks up `~/.databrickscfg`, env vars, or explicit credentials)
- SDK-managed pagination and retries
- More reliable in enterprise environments with custom auth providers

---

## Group audit data flow

```
GroupMembershipResolver
  └─ walks account SCIM → GroupNode tree
       (bulk pre-fetches users + SPs to avoid N+1 calls)
       (reads externalId to classify IdP-synced vs Databricks-managed)

WorkspaceDiscovery
  └─ lists all workspaces via Account API
       (or uses explicit --workspace-urls)

CatalogPermissionScanner
  └─ per workspace (parallel, ThreadPoolExecutor):
       • list catalogs
       • fetch UC grants per catalog
       • classify_grant() → DIRECT / UPSTREAM / MEMBER_DIRECT

SchemaPermissionScanner   (--scan-schemas)
  └─ per accessible (catalog, workspace) pair (parallel):
       • list schemas
       • fetch UC grants per schema
       • classify_grant()

TablePermissionScanner    (--scan-tables)
  └─ per (catalog, workspace, schema) triple (parallel):
       • list tables
       • fetch UC grants per table
       • classify_grant()

WorkspaceObjectScanner    (--scan-workspace-objects)
  └─ per workspace (parallel):
       • per object type (parallel, 13 types):
           – list objects
           – fetch /api/2.0/permissions/{type}/{id}
           – classify_grant()

RedundancyDetector
  └─ compares MEMBER_DIRECT grants against group's effective privileges
       (ALL_PRIVILEGES expansion aware)
       → RedundancyLevel: FULL / PARTIAL / NONE

RevokeScriptGenerator     (--revoke-script)
  └─ REVOKE SQL for each redundant grant
```

---

## Principal audit data flow

```
PrincipalAuditor.audit()
  ├─ resolve_principal() via account SCIM
  │    → 5-tuple: (id, name, type, external_id, uc_name)
  │
  ├─ BFS upward through all group memberships
  │    → List[GroupMembership] (direct + transitive)
  │
  ├─ get_workspace_assignments() — parallel, per workspace
  │    → /permissionassignments per workspace
  │    → List[WorkspaceRole]
  │
  ├─ _get_workspace_principal_aliases() — Azure AD B2B guest UPN resolution
  │    → workspace SCIM lookup by externalId
  │    → discovers guest UPN stored under a separate workspace record
  │
  └─ scan_permissions() — parallel, per unique workspace URL
       └─ _scan_one_workspace()
            ├─ catalog grants (+ schema/table when --scan-schemas/--scan-tables)
            └─ workspace object ACLs (--scan-workspace-objects)
                 → WorkspaceObjectScanner per workspace
```

When `ws_roles` is empty (principal accesses a workspace through an implicit built-in group like "account users"), the workspace object scan falls back to scanning all discovered workspaces.

!!! note "Workspace roles show explicit assignments only"
    The `/permissionassignments` API only returns **explicit** workspace role grants — ADMIN assignments made directly on the workspace. A user who reaches a workspace solely through the implicit built-in "account users" group will show **0 workspace roles** in the output, even though they can log in. This is a Databricks platform constraint, not a tool limitation. Their UC grants are still found via the separate catalog scan path.

---

## Parallelism

Both modes use `ThreadPoolExecutor` for the expensive I/O phases:

- Group audit: workspaces scanned in parallel; schemas and tables in parallel per catalog
- Principal audit: `permissionassignments` fetched in parallel per workspace; UC scans in parallel per workspace URL

The `--workers N` flag (default: 8) threads through to both parallel steps.

---

## Credential resolution

`_resolve_credentials()` in `cli.py` runs before the audit and mutates the parsed args:

1. If all three credentials are already set (flags or env vars), skip profile lookup.
2. Otherwise load `~/.databrickscfg` (or `DATABRICKS_CONFIG_FILE`) for the named profile.
3. Fill only the missing values — explicit flags take priority.
4. If `--cloud` was not set and the profile has a `host`, auto-detect cloud from the host.
5. Default `--cloud` to `azure` if still unset.
