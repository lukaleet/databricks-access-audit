"""Credential resolution from ~/.databrickscfg profiles."""
from __future__ import annotations

import configparser
import os
from typing import Dict, Optional

_ACCOUNT_HOST_CLOUD: Dict[str, str] = {
    "accounts.azuredatabricks.net": "azure",
    "accounts.cloud.databricks.com": "aws",
    "accounts.gcp.databricks.com": "gcp",
}


def cloud_from_host(host: str) -> Optional[str]:
    """Detect cloud provider from an account host URL, or None if unrecognised."""
    h = host.lower().rstrip("/")
    for prefix in ("https://", "http://"):
        if h.startswith(prefix):
            h = h[len(prefix):]
    return _ACCOUNT_HOST_CLOUD.get(h)


def load_profile(
    profile: str = "DEFAULT",
    config_file: Optional[str] = None,
) -> Dict[str, str]:
    """Load a named profile from ~/.databrickscfg (or a custom path).

    Resolution order for the config file path:
    1. ``config_file`` argument
    2. ``DATABRICKS_CONFIG_FILE`` environment variable
    3. ``~/.databrickscfg``

    Returns a dict containing any of: host, account_id, client_id,
    client_secret, token.  Returns an empty dict when the file is missing
    or the requested profile does not exist.
    """
    path_str = config_file or os.getenv("DATABRICKS_CONFIG_FILE", "~/.databrickscfg")
    path = os.path.expanduser(path_str)
    if not os.path.exists(path):
        return {}

    cfg = configparser.ConfigParser()
    cfg.read(path)

    # configparser merges DEFAULT into every named section automatically.
    # For profile="DEFAULT" read cfg.defaults() directly to avoid duplicates.
    if profile.upper() == "DEFAULT":
        raw: Dict[str, str] = dict(cfg.defaults())
    elif cfg.has_section(profile):
        raw = dict(cfg[profile])  # includes DEFAULT fallbacks
    else:
        return {}

    result: Dict[str, str] = {}
    for key in ("host", "account_id", "client_id", "client_secret", "token"):
        val = raw.get(key, "").strip()
        if val:
            result[key] = val
    return result
