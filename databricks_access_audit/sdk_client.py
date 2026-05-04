"""Databricks SDK-based client — optional drop-in replacement for DatabricksAPIClient.

Requires ``databricks-sdk``.  Install via::

    pip install databricks-access-audit[sdk]

The SDK handles OAuth token management, pagination, and retries automatically,
eliminating the manual token refresh, SCIM page walking, and exponential-backoff
logic that the raw HTTP client must implement.

Usage::

    from databricks_access_audit.sdk_client import DatabricksSDKClient

    client = DatabricksSDKClient.for_cloud(
        cloud="azure",
        client_id="...",
        client_secret="...",
        account_id="...",
    )

All existing scanner, resolver, and auditor modules accept either client
because they depend only on the ``account_api``, ``workspace_api``, and
``scim_list_all`` methods.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from databricks_access_audit.client import ACCOUNT_HOST_MAP

log = logging.getLogger(__name__)

try:
    from databricks.sdk import AccountClient, WorkspaceClient

    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False


class DatabricksSDKClient:
    """Databricks client backed by the official ``databricks-sdk``.

    Implements the same public interface as
    :class:`~databricks_access_audit.client.DatabricksAPIClient` so all
    existing scanner, resolver, and auditor modules work unchanged.

    Key advantages over the raw HTTP client:

    * **No manual OAuth** — the SDK refreshes tokens automatically.
    * **Built-in pagination** — ``list()`` methods return complete results.
    * **Automatic retries** — transient errors are retried with backoff.
    * **Typed responses** — SDK objects are converted to dicts for compatibility.
    """

    SCIM_PAGE_SIZE = 100  # Not actively used; SDK paginates internally.

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        account_id: str,
        account_host: str = "https://accounts.azuredatabricks.net",
        # Accept (and ignore) retry kwargs for interface compat.
        max_retries: int = 5,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
    ):
        if not SDK_AVAILABLE:
            raise ImportError(
                "databricks-sdk is required for DatabricksSDKClient. "
                "Install with:  pip install databricks-access-audit[sdk]"
            )

        self.account_id = account_id
        self.account_host = account_host
        self._client_id = client_id
        self._client_secret = client_secret

        self._account = AccountClient(
            host=account_host,
            account_id=account_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        self._workspace_clients: Dict[str, WorkspaceClient] = {}

    # -- Factory -----------------------------------------------------------

    @classmethod
    def for_cloud(
        cls,
        cloud: str,
        client_id: str,
        client_secret: str,
        account_id: str,
        **kwargs: Any,
    ) -> "DatabricksSDKClient":
        """Create a client for the given cloud provider."""
        host = ACCOUNT_HOST_MAP.get(cloud.lower(), ACCOUNT_HOST_MAP["azure"])
        return cls(
            client_id=client_id,
            client_secret=client_secret,
            account_id=account_id,
            account_host=host,
            **kwargs,
        )

    # -- Workspace client cache --------------------------------------------

    @staticmethod
    def _pat_for_host(host: str) -> str:
        """Return a PAT from ~/.databrickscfg whose host matches, or ''."""
        import configparser
        import os
        cfg_path = os.path.expanduser("~/.databrickscfg")
        if not os.path.exists(cfg_path):
            return ""
        cfg = configparser.ConfigParser()
        cfg.read(cfg_path)
        host_norm = host.rstrip("/")
        for section in cfg.sections():
            h = cfg.get(section, "host", fallback="").rstrip("/")
            t = cfg.get(section, "token", fallback="")
            if h == host_norm and t:
                return t
        # Also check [DEFAULT]
        h = cfg.defaults().get("host", "").rstrip("/")
        t = cfg.defaults().get("token", "")
        return t if h == host_norm and t else ""

    def _get_ws_client(self, workspace_host: str) -> "WorkspaceClient":
        if not workspace_host.startswith("https://"):
            workspace_host = f"https://{workspace_host}"
        if workspace_host not in self._workspace_clients:
            # Prefer oauth-m2m with explicit SP credentials.  Some workspaces
            # reject workspace-level OIDC for service principals (e.g. when
            # identity federation is enabled and the SP is only registered at
            # account level).  In that case fall back to a PAT from
            # ~/.databrickscfg (dev), DATABRICKS_TOKEN env var, or azure-cli.
            ws = WorkspaceClient(
                host=workspace_host,
                client_id=self._client_id,
                client_secret=self._client_secret,
            )
            try:
                next(ws.catalogs.list(), None)
            except Exception:
                pat = self._pat_for_host(workspace_host)
                log.debug(
                    "Workspace oauth-m2m failed for %s — retrying with %s.",
                    workspace_host,
                    "~/.databrickscfg PAT" if pat else "env-var/azure-cli auth",
                )
                ws = WorkspaceClient(host=workspace_host, token=pat) if pat \
                    else WorkspaceClient(host=workspace_host)
            self._workspace_clients[workspace_host] = ws
        return self._workspace_clients[workspace_host]

    # =====================================================================
    # account_api  — compatibility layer
    # =====================================================================

    # Patterns for endpoint routing
    _RE_GROUP_BY_ID = re.compile(r"^/scim/v2/Groups/(.+)$")
    _RE_USER_BY_ID = re.compile(r"^/scim/v2/Users/(.+)$")
    _RE_SP_BY_ID = re.compile(r"^/scim/v2/ServicePrincipals/(.+)$")
    _RE_WS_PERMS = re.compile(r"^/workspaces/(\d+)/permissionassignments$")

    def account_api(
        self, method: str, endpoint: str, **kwargs: Any
    ) -> Any:
        """Dispatch account-level API calls to typed SDK methods.

        Known SCIM and workspace endpoints are routed to the SDK's typed
        APIs; anything else falls through to the SDK's raw HTTP client.
        """
        params = kwargs.get("params", {})

        # --- SCIM Groups -------------------------------------------------
        # Use raw HTTP for group *listing* — the SDK's groups.list() omits
        # the `members` field, which is required for upstream-group traversal
        # in get_group_membership_map().  Individual group GETs (by ID)
        # via groups.get() do include members and are kept as typed calls.
        # Non-GET methods (POST/PATCH/PUT/DELETE) fall through to the raw
        # fallback so create/update/delete operations are handled correctly.
        if method == "GET" and endpoint == "/scim/v2/Groups":
            query: Dict[str, Any] = {"count": self.SCIM_PAGE_SIZE}
            if params.get("filter"):
                query["filter"] = params["filter"]
            if params.get("startIndex"):
                query["startIndex"] = params["startIndex"]
            resp = self._account.api_client.do(
                "GET",
                f"/api/2.0/accounts/{self.account_id}/scim/v2/Groups",
                query=query,
            )
            return resp if isinstance(resp, dict) else {}

        m = self._RE_GROUP_BY_ID.match(endpoint)
        if m and method == "GET":
            return self._to_dict(self._account.groups.get(m.group(1)))

        # --- SCIM Users --------------------------------------------------
        if method == "GET" and endpoint == "/scim/v2/Users":
            filt = params.get("filter")
            items = list(self._account.users.list(filter=filt))
            return {
                "Resources": [self._to_dict(u) for u in items],
                "totalResults": len(items),
            }

        m = self._RE_USER_BY_ID.match(endpoint)
        if m and method == "GET":
            return self._to_dict(self._account.users.get(m.group(1)))

        # --- SCIM ServicePrincipals --------------------------------------
        if method == "GET" and endpoint == "/scim/v2/ServicePrincipals":
            filt = params.get("filter")
            items = list(self._account.service_principals.list(filter=filt))
            return {
                "Resources": [self._to_dict(sp) for sp in items],
                "totalResults": len(items),
            }

        m = self._RE_SP_BY_ID.match(endpoint)
        if m and method == "GET":
            return self._to_dict(
                self._account.service_principals.get(m.group(1))
            )

        # --- Workspaces --------------------------------------------------
        if method == "GET" and endpoint == "/workspaces":
            items = list(self._account.workspaces.list())
            return [self._to_dict(w) for w in items]

        # --- Workspace Permission Assignments ----------------------------
        m = self._RE_WS_PERMS.match(endpoint)
        if m and method == "GET":
            ws_id = int(m.group(1))
            items = list(self._account.workspace_assignment.list(ws_id))
            return {
                "permission_assignments": [self._to_dict(pa) for pa in items],
            }

        # --- Fallback: raw API via SDK's internal HTTP client ------------
        # The SDK's api_client.do() uses body= for request payload, while the
        # rest of the codebase passes json= (requests-style).  Convert here.
        log.debug("SDK fallback to raw API: %s %s", method, endpoint)
        url = f"/api/2.0/accounts/{self.account_id}{endpoint}"
        fallback_kwargs = dict(kwargs)
        body = fallback_kwargs.pop("json", None)
        resp = self._account.api_client.do(method, url, body=body, **fallback_kwargs)
        if not isinstance(resp, dict):
            log.debug("account_api fallback: expected dict, got %s — returning {}",
                      type(resp).__name__)
            return {}
        return resp

    # =====================================================================
    # workspace_api  — compatibility layer
    # =====================================================================

    _RE_WS_SCIM_GROUPS = re.compile(r"^/api/2\.0/preview/scim/v2/Groups$")

    _RE_CATALOGS = re.compile(r"^/api/2\.1/unity-catalog/catalogs$")
    _RE_CAT_GRANTS = re.compile(
        r"^/api/2\.1/unity-catalog/permissions/catalog/(.+)$"
    )
    _RE_SCHEMAS = re.compile(r"^/api/2\.1/unity-catalog/schemas$")
    _RE_SCHEMA_GRANTS = re.compile(
        r"^/api/2\.1/unity-catalog/permissions/schema/(.+)$"
    )
    _RE_TABLES = re.compile(r"^/api/2\.1/unity-catalog/tables$")
    _RE_TABLE_GRANTS = re.compile(
        r"^/api/2\.1/unity-catalog/permissions/table/(.+)$"
    )

    # Workspace object list endpoints
    _RE_JOBS_LIST = re.compile(r"^/api/2\.1/jobs/list$")
    _RE_CLUSTERS_LIST = re.compile(r"^/api/2\.0/clusters/list$")
    _RE_WAREHOUSES_LIST = re.compile(r"^/api/2\.0/sql/warehouses$")
    _RE_PIPELINES_LIST = re.compile(r"^/api/2\.0/pipelines$")
    _RE_POLICIES_LIST = re.compile(r"^/api/2\.0/policies/clusters/list$")
    # Workspace object permission endpoints (raw REST — avoid gRPC shims)
    _RE_WS_PERMISSIONS = re.compile(r"^/api/2\.0/permissions/.+$")

    def workspace_api(
        self,
        workspace_host: str,
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Dispatch workspace-level API calls to typed SDK methods."""
        ws = self._get_ws_client(workspace_host)
        params = kwargs.get("params", {})

        # --- Workspace SCIM groups ---------------------------------------
        if method == "GET" and self._RE_WS_SCIM_GROUPS.match(endpoint):
            filt = params.get("filter")
            items = list(ws.groups.list(filter=filt))
            return {
                "Resources": [self._to_dict(g) for g in items],
                "totalResults": len(items),
            }

        # --- Catalogs ----------------------------------------------------
        if method == "GET" and self._RE_CATALOGS.match(endpoint):
            items = list(ws.catalogs.list())
            return {"catalogs": [self._to_dict(c) for c in items]}

        # --- Catalog grants ----------------------------------------------
        # Use raw REST (not ws.grants.get) — the SDK's grants API goes through
        # a gRPC shim that rejects SECURABLETYPE.CATALOG on some workspace
        # versions, while the REST endpoint works on all versions.
        # Non-GET methods (PATCH to add/remove grants) fall through to the
        # raw fallback below so they are sent with the correct method.
        m = self._RE_CAT_GRANTS.match(endpoint)
        if m and method == "GET":
            resp = ws.api_client.do("GET", endpoint)
            return resp if isinstance(resp, dict) else {}

        # --- Schemas -----------------------------------------------------
        if method == "GET" and self._RE_SCHEMAS.match(endpoint):
            cat_name = params.get("catalog_name", "")
            items = list(ws.schemas.list(catalog_name=cat_name))
            return {"schemas": [self._to_dict(s) for s in items]}

        # --- Schema grants -----------------------------------------------
        m = self._RE_SCHEMA_GRANTS.match(endpoint)
        if m and method == "GET":
            resp = ws.api_client.do("GET", endpoint)
            return resp if isinstance(resp, dict) else {}

        # --- Tables ------------------------------------------------------
        if method == "GET" and self._RE_TABLES.match(endpoint):
            cat_name = params.get("catalog_name", "")
            schema_name = params.get("schema_name", "")
            items = list(
                ws.tables.list(
                    catalog_name=cat_name, schema_name=schema_name,
                )
            )
            return {"tables": [self._to_dict(t) for t in items]}

        # --- Table grants ------------------------------------------------
        m = self._RE_TABLE_GRANTS.match(endpoint)
        if m and method == "GET":
            resp = ws.api_client.do("GET", endpoint)
            return resp if isinstance(resp, dict) else {}

        # --- Workspace object lists (SDK typed iterators for auto-pagination) ---
        if method == "GET" and self._RE_JOBS_LIST.match(endpoint):
            items = list(ws.jobs.list())
            return {"jobs": [self._to_dict(j) for j in items]}

        if method == "GET" and self._RE_CLUSTERS_LIST.match(endpoint):
            items = list(ws.clusters.list())
            return {"clusters": [self._to_dict(c) for c in items]}

        if method == "GET" and self._RE_WAREHOUSES_LIST.match(endpoint):
            items = list(ws.warehouses.list())
            return {"warehouses": [self._to_dict(w) for w in items]}

        if method == "GET" and self._RE_PIPELINES_LIST.match(endpoint):
            items = list(ws.pipelines.list_pipelines())
            return {"statuses": [self._to_dict(p) for p in items]}

        if method == "GET" and self._RE_POLICIES_LIST.match(endpoint):
            items = list(ws.cluster_policies.list())
            return {"policies": [self._to_dict(p) for p in items]}

        # --- Workspace object permissions (raw REST — no gRPC shim) -----
        if method == "GET" and self._RE_WS_PERMISSIONS.match(endpoint):
            resp = ws.api_client.do("GET", endpoint)
            return resp if isinstance(resp, dict) else {}

        # --- Fallback: raw API via SDK's workspace HTTP client -----------
        if not workspace_host.startswith("https://"):
            workspace_host = f"https://{workspace_host}"
        log.debug("SDK fallback to raw workspace API: %s %s", method, endpoint)
        fallback_kwargs = dict(kwargs)
        body = fallback_kwargs.pop("json", None)
        # Convert requests-style ``params`` to SDK-style ``query``.
        query = fallback_kwargs.pop("params", None)
        resp = ws.api_client.do(method, endpoint, body=body, query=query or None,
                                **fallback_kwargs)
        if not isinstance(resp, dict):
            log.debug("workspace_api fallback: expected dict, got %s — returning {}",
                      type(resp).__name__)
            return {}
        return resp

    # =====================================================================
    # scim_list_all  — compatibility layer
    # =====================================================================

    def scim_list_all(
        self, resource: str, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """List all SCIM resources with automatic SDK pagination.

        Groups are fetched via raw HTTP so that the ``members`` field is
        included — the SDK's ``groups.list()`` iterator omits members.
        Users and SPs do not need members so the typed SDK iterators are used.
        """
        filt = (params or {}).get("filter")

        if resource == "Groups":
            # Route through account_api which now uses raw HTTP for groups
            return self.account_api(
                "GET", "/scim/v2/Groups", params=params or {}
            ).get("Resources", [])
        elif resource == "Users":
            items = self._account.users.list(filter=filt)
        elif resource == "ServicePrincipals":
            items = self._account.service_principals.list(filter=filt)
        else:
            return self.account_api(
                "GET", f"/scim/v2/{resource}", params=params or {}
            ).get("Resources", [])

        return [self._to_dict(item) for item in items]

    # -- Helpers -----------------------------------------------------------

    @staticmethod
    def _to_dict(obj: Any) -> Dict[str, Any]:
        """Convert an SDK dataclass or plain dict to a plain dict.

        SDK response objects expose ``as_dict()``.  Plain dicts (e.g. from
        the raw HTTP fallback path) are returned as-is.  Any other type
        produces an empty dict and a DEBUG log so callers never see None
        but SDK-version surprises are still observable in verbose logs.
        """
        if hasattr(obj, "as_dict"):
            return obj.as_dict()
        if isinstance(obj, dict):
            return obj
        log.debug("_to_dict: unexpected type %s, returning {}", type(obj).__name__)
        return {}
