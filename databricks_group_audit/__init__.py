"""Databricks Group Audit Tool.

Audit group membership and Unity Catalog permissions across workspaces.

Quick start::

    from databricks_group_audit import create_client, GroupMembershipResolver

    client = create_client(cloud="azure", client_id="...",
                           client_secret="...", account_id="...")
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
"""

__version__ = "0.3.0"

from databricks_group_audit.models import (
    MemberType,
    PrincipalSource,
    GroupMember,
    GroupNode,
    WorkspaceInfo,
    GrantSource,
    CatalogGrant,
    SchemaGrant,
    TableGrant,
    RedundancyLevel,
    RedundancyResult,
    # Principal audit models
    GroupMembership,
    WorkspaceRole,
    EffectivePermission,
    PrincipalAuditResult,
    # New feature models
    EscalationFinding,
    StaleFinding,
    LocalGroupFinding,
)
from databricks_group_audit.client import (
    AuditClient,
    DatabricksAPIClient,
    create_client,
)
from databricks_group_audit.group_resolver import GroupMembershipResolver
from databricks_group_audit.workspace import WorkspaceDiscovery, WORKSPACE_DOMAIN_MAP
from databricks_group_audit.catalog_scanner import CatalogPermissionScanner, classify_catalog_grant
from databricks_group_audit.schema_scanner import SchemaPermissionScanner
from databricks_group_audit.table_scanner import TablePermissionScanner
from databricks_group_audit.redundancy import RedundancyDetector
from databricks_group_audit.revoke import RevokeScriptGenerator
from databricks_group_audit._classification import classify_grant, build_member_lookups
from databricks_group_audit.principal_auditor import PrincipalAuditor
from databricks_group_audit.elevate import PermissionElevator
from databricks_group_audit.escalation import detect_escalations, ESCALATION_PRIVILEGES
from databricks_group_audit.stale_checker import StaleGrantChecker
from databricks_group_audit.local_groups import LocalGroupChecker

# Optional SDK client — only available when databricks-sdk is installed
try:
    from databricks_group_audit.sdk_client import DatabricksSDKClient, SDK_AVAILABLE
except ImportError:
    DatabricksSDKClient = None  # type: ignore[assignment,misc]
    SDK_AVAILABLE = False

__all__ = [
    "PrincipalSource",
    # Clients
    "AuditClient",
    "DatabricksAPIClient",
    "DatabricksSDKClient",
    "create_client",
    "SDK_AVAILABLE",
    # Core modules
    "GroupMembershipResolver",
    "WorkspaceDiscovery",
    "CatalogPermissionScanner",
    "SchemaPermissionScanner",
    "TablePermissionScanner",
    "RedundancyDetector",
    "RevokeScriptGenerator",
    "PrincipalAuditor",
    "PermissionElevator",
    "detect_escalations",
    "ESCALATION_PRIVILEGES",
    "StaleGrantChecker",
    "LocalGroupChecker",
    # Models
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
    "GroupMembership",
    "WorkspaceRole",
    "EffectivePermission",
    "PrincipalAuditResult",
    "EscalationFinding",
    "StaleFinding",
    "LocalGroupFinding",
    # Helpers
    "WORKSPACE_DOMAIN_MAP",
    "classify_catalog_grant",
    "classify_grant",
    "build_member_lookups",
]
