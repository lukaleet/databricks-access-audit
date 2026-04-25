"""HTTP client with OAuth authentication and retry logic.

This module provides:

* :class:`DatabricksAPIClient` — raw HTTP client with manual OAuth, pagination,
  and exponential-backoff retry.  Zero external dependencies beyond ``requests``.
* :func:`create_client` — factory that returns a
  :class:`~databricks_group_audit.sdk_client.DatabricksSDKClient` when
  ``databricks-sdk`` is installed, falling back to the raw HTTP client otherwise.

Typical usage::

    from databricks_group_audit.client import create_client

    client = create_client(
        cloud="azure",
        client_id="...",
        client_secret="...",
        account_id="...",
    )
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

import requests

log = logging.getLogger(__name__)

ACCOUNT_HOST_MAP = {
    "azure": "https://accounts.azuredatabricks.net",
    "aws": "https://accounts.cloud.databricks.com",
    "gcp": "https://accounts.gcp.databricks.com",
}


def _scim_filter_escape(value: str) -> str:
    """Escape a string value for use inside a SCIM filter expression.

    Per RFC 7644 §3.4.2.2, only backslashes and double-quotes need escaping
    inside a filter string literal.  Without this, a group or principal name
    that contains a double-quote character would produce a malformed filter and
    could allow unexpected SCIM query results.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


# ---------------------------------------------------------------------------
# Structural protocol shared by both client implementations
# ---------------------------------------------------------------------------

@runtime_checkable
class AuditClient(Protocol):
    """Structural type satisfied by both :class:`DatabricksAPIClient`
    and :class:`~databricks_group_audit.sdk_client.DatabricksSDKClient`.

    Modules should type-hint their ``api_client`` parameter as
    ``AuditClient`` for maximum flexibility.
    """

    account_id: str
    account_host: str

    def account_api(
        self, method: str, endpoint: str, **kwargs: Any
    ) -> Any: ...

    def workspace_api(
        self, workspace_host: str, method: str, endpoint: str, **kwargs: Any
    ) -> Dict[str, Any]: ...

    def scim_list_all(
        self, resource: str, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]: ...


# ---------------------------------------------------------------------------
# Token cache
# ---------------------------------------------------------------------------

@dataclass
class TokenCache:
    """Thread-safe OAuth token cache with expiry."""

    token: Optional[str] = None
    expires_at: Optional[datetime] = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def get_token(self) -> Optional[str]:
        with self.lock:
            if self.token and self.expires_at and datetime.now() < self.expires_at:
                return self.token
            return None

    def set_token(self, token: str, expires_in: int) -> None:
        with self.lock:
            self.token = token
            self.expires_at = datetime.now() + timedelta(seconds=max(expires_in - 60, 10))


# ---------------------------------------------------------------------------
# Raw HTTP client
# ---------------------------------------------------------------------------

class DatabricksAPIClient:
    """Databricks API client with SP OAuth and exponential-backoff retry.

    Supports Azure, AWS, and GCP account console endpoints.
    """

    SCIM_PAGE_SIZE = 100

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        account_id: str,
        account_host: str = "https://accounts.azuredatabricks.net",
        max_retries: int = 5,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.account_id = account_id
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay

        self._account_token_cache = TokenCache()
        self._workspace_token_caches: Dict[str, TokenCache] = {}

        self.account_host = account_host
        self.session = requests.Session()

    @classmethod
    def for_cloud(
        cls,
        cloud: str,
        client_id: str,
        client_secret: str,
        account_id: str,
        **kwargs: Any,
    ) -> "DatabricksAPIClient":
        """Factory that selects the correct account host for the cloud."""
        host = ACCOUNT_HOST_MAP.get(cloud.lower(), ACCOUNT_HOST_MAP["azure"])
        return cls(
            client_id=client_id,
            client_secret=client_secret,
            account_id=account_id,
            account_host=host,
            **kwargs,
        )

    # -- OAuth token helpers ------------------------------------------------

    def _get_oauth_token(self, host: str, scope: Optional[str] = None) -> tuple:
        data: Dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if scope:
            data["scope"] = scope
        resp = self.session.post(f"{host}/oidc/v1/token", data=data)
        resp.raise_for_status()
        body = resp.json()
        return body["access_token"], body.get("expires_in", 3600)

    def _get_account_token(self) -> str:
        cached = self._account_token_cache.get_token()
        if cached:
            return cached
        token, expires_in = self._get_oauth_token(self.account_host, scope="all-apis")
        self._account_token_cache.set_token(token, expires_in)
        return token

    def _get_workspace_token(self, workspace_host: str) -> str:
        cache = self._workspace_token_caches.setdefault(workspace_host, TokenCache())
        cached = cache.get_token()
        if cached:
            return cached
        token, expires_in = self._get_oauth_token(workspace_host, scope="all-apis")
        cache.set_token(token, expires_in)
        return token

    # -- Retry engine ------------------------------------------------------

    def _request_with_retry(
        self, method: str, url: str, token: str, **kwargs: Any
    ) -> requests.Response:
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        headers["Content-Type"] = "application/json"

        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.request(method, url, headers=headers, **kwargs)
                if resp.status_code < 400 or (
                    400 <= resp.status_code < 500 and resp.status_code != 429
                ):
                    return resp
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < self.max_retries:
                        retry_after = resp.headers.get("Retry-After")
                        delay = (
                            float(retry_after)
                            if retry_after
                            else min(self.base_delay * (2**attempt), self.max_delay)
                        )
                        time.sleep(delay)
                        continue
                return resp
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    delay = min(self.base_delay * (2**attempt), self.max_delay)
                    time.sleep(delay)
                    continue
                raise
        if last_exc:
            raise last_exc
        return resp  # type: ignore[possibly-undefined]

    # -- High-level API methods --------------------------------------------

    def account_api(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        token = self._get_account_token()
        url = f"{self.account_host}/api/2.0/accounts/{self.account_id}{endpoint}"
        resp = self._request_with_retry(method, url, token, **kwargs)
        resp.raise_for_status()
        return resp.json() if resp.text else {}

    def workspace_api(
        self, workspace_host: str, method: str, endpoint: str, **kwargs: Any
    ) -> Dict[str, Any]:
        if not workspace_host.startswith("https://"):
            workspace_host = f"https://{workspace_host}"
        token = self._get_workspace_token(workspace_host)
        url = f"{workspace_host}{endpoint}"
        resp = self._request_with_retry(method, url, token, **kwargs)
        resp.raise_for_status()
        return resp.json() if resp.text else {}

    # -- Paginated SCIM helpers --------------------------------------------

    def scim_list_all(
        self, resource: str, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Paginate through a SCIM list endpoint."""
        all_resources: List[Dict[str, Any]] = []
        start_index = 1

        while True:
            page_params: Dict[str, Any] = {
                "startIndex": start_index,
                "count": self.SCIM_PAGE_SIZE,
            }
            if params:
                page_params.update(params)

            body = self.account_api("GET", f"/scim/v2/{resource}", params=page_params)
            resources = body.get("Resources", [])
            all_resources.extend(resources)

            total = body.get("totalResults", len(all_resources))
            per_page = body.get("itemsPerPage", len(resources))

            if not resources or len(all_resources) >= total:
                break
            start_index += per_page

        return all_resources


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------

def create_client(
    cloud: str,
    client_id: str,
    client_secret: str,
    account_id: str,
    prefer_sdk: bool = True,
    **kwargs: Any,
) -> AuditClient:
    """Create the best available API client.

    When *prefer_sdk* is ``True`` (default) and ``databricks-sdk`` is
    installed, returns a
    :class:`~databricks_group_audit.sdk_client.DatabricksSDKClient` which
    benefits from automatic auth, pagination, and retries.  Falls back to
    :class:`DatabricksAPIClient` (raw HTTP) when the SDK is unavailable.

    Parameters
    ----------
    cloud : str
        ``"azure"``, ``"aws"``, or ``"gcp"``.
    client_id, client_secret, account_id : str
        Service-principal credentials and Databricks account ID.
    prefer_sdk : bool
        Set to ``False`` to force the raw HTTP client even when the SDK
        is available.
    **kwargs
        Forwarded to the chosen client's constructor (e.g. ``max_retries``).
    """
    if prefer_sdk:
        try:
            from databricks_group_audit.sdk_client import (
                SDK_AVAILABLE,
                DatabricksSDKClient,
            )

            if SDK_AVAILABLE:
                log.info("Using Databricks SDK client")
                return DatabricksSDKClient.for_cloud(
                    cloud=cloud,
                    client_id=client_id,
                    client_secret=client_secret,
                    account_id=account_id,
                    **kwargs,
                )
        except Exception as exc:
            log.debug("SDK client unavailable, falling back to raw HTTP: %s", exc)

    log.info("Using raw HTTP client")
    return DatabricksAPIClient.for_cloud(
        cloud=cloud,
        client_id=client_id,
        client_secret=client_secret,
        account_id=account_id,
        **kwargs,
    )
