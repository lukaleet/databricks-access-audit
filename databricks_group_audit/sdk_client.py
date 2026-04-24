"""Databricks SDK-based client — optional drop-in replacement for DatabricksAPIClient.

Requires ``databricks-sdk``.  Install via::

    pip install databricks-group-audit[sdk]

The SDK handles OAuth token management, pagination, and retries automatically,
eliminating the manual token refresh, SCIM page walking, and exponential-backoff
logic that the raw HTTP client must implement.

Usage::

    from databricks_group_audit.sdk_client import DatabricksSDKClient

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

from databricks_group_audit.client import ACCOUNT_HOST_MAP

log = logging.getLogger(__name__)

try:
    from databricks.sdk import AccountClient, WorkspaceClient
    from databricks.sdk.service.catalog import SecurableType

    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False


class DatabricksSDKClient:
    """Databricks client backed by the official ``databricks-sdk``.

    Implements the same public interface as
    :class:`~databricks_group_audit.client.DatabricksAPIClient` so all
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
                "Install with:  pip install databricks-group-audit[sdk]"
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

    def _get_ws_client(self, workspace_host: str) -> "WorkspaceClient":
        if not workspace_host.startswith("https://"):
            workspace_host = f"https://{workspace_host}"
        if workspace_host not in self._workspace_clients:
            self._workspace_clients[workspace_host] = WorkspaceClient(
                host=workspace_host,
                client_id=self._client_id,
                client_secret=self._client_secret,
            )
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
        if endpoint == "/scim/v2/Groups":
            filt = params.get("filter")
            items = list(self._account.groups.list(filter=filt))
            return {
                "Resources": [self._to_dict(g) for g in items],
                "totalResults": len(items),
            }

        m = self._RE_GROUP_BY_ID.match(endpoint)
        if m:
            return self._to_dict(self._account.groups.get(m.group(1)))

        # --- SCIM Users --------------------------------------------------
        if endpoint == "/scim/v2/Users":
            filt = params.get("filter")
            items = list(self._account.users.list(filter=filt))
            return {
                "Resources": [self._to_dict(u) for u in items],
                "totalResults": len(items),
            }

        m = self._RE_USER_BY_ID.match(endpoint)
        if m:
            return self._to_dict(self._account.users.get(m.group(1)))

        # --- SCIM ServicePrincipals --------------------------------------
        if endpoint == "/scim/v2/ServicePrincipals":
            filt = params.get("filter")
            items = list(self._account.service_principals.list(filter=filt))
            return {
                "Resources": [self._to_dict(sp) for sp in items],
                "totalResults": len(items),
            }

        m = self._RE_SP_BY_ID.match(endpoint)
        if m:
            return self._to_dict(
                self._account.service_principals.get(m.group(1))
            )

        # --- Workspaces --------------------------------------------------
        if endpoint == "/workspaces":
            items = list(self._account.workspaces.list())
            return [self._to_dict(w) for w in items]

        # --- Workspace Permission Assignments ----------------------------
        m = self._RE_WS_PERMS.match(endpoint)
        if m:
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
        return resp if isinstance(resp, dict) else {}

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
        if self._RE_WS_SCIM_GROUPS.match(endpoint):
            filt = params.get("filter")
            items = list(ws.groups.list(filter=filt))
            return {
                "Resources": [self._to_dict(g) for g in items],
                "totalResults": len(items),
            }

        # --- Catalogs ----------------------------------------------------
        if self._RE_CATALOGS.match(endpoint):
            items = list(ws.catalogs.list())
            return {"catalogs": [self._to_dict(c) for c in items]}

        # --- Catalog grants ----------------------------------------------
        m = self._RE_CAT_GRANTS.match(endpoint)
        if m:
            grants = ws.grants.get(
                securable_type=SecurableType.CATALOG, full_name=m.group(1),
            )
            return {
                "privilege_assignments": [
                    self._to_dict(pa)
                    for pa in (grants.privilege_assignments or [])
                ],
            }

        # --- Schemas -----------------------------------------------------
        if self._RE_SCHEMAS.match(endpoint):
            cat_name = params.get("catalog_name", "")
            items = list(ws.schemas.list(catalog_name=cat_name))
            return {"schemas": [self._to_dict(s) for s in items]}

        # --- Schema grants -----------------------------------------------
        m = self._RE_SCHEMA_GRANTS.match(endpoint)
        if m:
            grants = ws.grants.get(
                securable_type=SecurableType.SCHEMA, full_name=m.group(1),
            )
            return {
                "privilege_assignments": [
                    self._to_dict(pa)
                    for pa in (grants.privilege_assignments or [])
                ],
            }

        # --- Tables ------------------------------------------------------
        if self._RE_TABLES.match(endpoint):
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
        if m:
            grants = ws.grants.get(
                securable_type=SecurableType.TABLE, full_name=m.group(1),
            )
            return {
                "privilege_assignments": [
                    self._to_dict(pa)
                    for pa in (grants.privilege_assignments or [])
                ],
            }

        # --- Fallback: raw API via SDK's workspace HTTP client -----------
        if not workspace_host.startswith("https://"):
            workspace_host = f"https://{workspace_host}"
        log.debug("SDK fallback to raw workspace API: %s %s", method, endpoint)
        fallback_kwargs = dict(kwargs)
        body = fallback_kwargs.pop("json", None)
        resp = ws.api_client.do(method, endpoint, body=body, **fallback_kwargs)
        return resp if isinstance(resp, dict) else {}

    # =====================================================================
    # scim_list_all  — compatibility layer
    # =====================================================================

    def scim_list_all(
        self, resource: str, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """List all SCIM resources with automatic SDK pagination."""
        filt = (params or {}).get("filter")

        if resource == "Groups":
            items = self._account.groups.list(filter=filt)
        elif resource == "Users":
            items = self._account.users.list(filter=filt)
        elif resource == "ServicePrincipals":
            items = self._account.service_principals.list(filter=filt)
        else:
            # Unknown resource — fall back to account_api
            return self.account_api(
                "GET", f"/scim/v2/{resource}", params=params or {}
            ).get("Resources", [])

        return [self._to_dict(item) for item in items]

    # -- Helpers -----------------------------------------------------------

    @staticmethod
    def _to_dict(obj: Any) -> Dict[str, Any]:
        """Convert an SDK dataclass to a plain dict."""
        if hasattr(obj, "as_dict"):
            return obj.as_dict()
        if isinstance(obj, dict):
            return obj
        return {}
