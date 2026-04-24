"""Databricks Group Audit Tool.

Audit group membership and Unity Catalog permissions across workspaces.
"""

__version__ = "0.1.0"

from databricks_group_audit.models import (
    MemberType,
    GroupMember,
    GroupNode,
    WorkspaceInfo,
    GrantSource,
    CatalogGrant,
    SchemaGrant,
    TableGrant,
    RedundancyLevel,
    RedundancyResult,
)
from databricks_group_audit.client import DatabricksAPIClient
from databricks_group_audit.group_resolver import GroupMembershipResolver
from databricks_group_audit.workspace import WorkspaceDiscovery, WORKSPACE_DOMAIN_MAP
from databricks_group_audit.catalog_scanner import CatalogPermissionScanner, classify_catalog_grant
from databricks_group_audit.schema_scanner import SchemaPermissionScanner
from databricks_group_audit.table_scanner import TablePermissionScanner
from databricks_group_audit.redundancy import RedundancyDetector
from databricks_group_audit.revoke import RevokeScriptGenerator
from databricks_group_audit._classification import classify_grant, build_member_lookups

__all__ = [
    "DatabricksAPIClient",
    "GroupMembershipResolver",
    "WorkspaceDiscovery",
    "CatalogPermissionScanner",
    "SchemaPermissionScanner",
    "TablePermissionScanner",
    "RedundancyDetector",
    "RevokeScriptGenerator",
    "MemberType",
    "GroupMember",
    "GroupNode",
    "WorkspaceInfo",
    "GrantSource",
    "CatalogGrant",
    "SchemaGrant",
    "TableGrant",
    "RedundancyLevel",
    "RedundancyResult",
    "WORKSPACE_DOMAIN_MAP",
    "classify_catalog_grant",
    "classify_grant",
    "build_member_lookups",
]
