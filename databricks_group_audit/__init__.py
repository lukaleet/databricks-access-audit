"""Databricks Group Audit Tool.

Audit group membership and Unity Catalog permissions across workspaces.

Quick start::

    from databricks_group_audit import create_client, GroupMembershipResolver

    client = create_client(cloud="azure", client_id="...",
                           client_secret="...", account_id="...")
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
"""

__version__ = "0.15.0"

from databricks_group_audit._classification import build_member_lookups, classify_grant
from databricks_group_audit.catalog_scanner import CatalogPermissionScanner, classify_catalog_grant
from databricks_group_audit.client import (
    AuditClient,
    DatabricksAPIClient,
    create_client,
)
from databricks_group_audit.csv_output import write_group_audit_csv, write_principal_audit_csv
from databricks_group_audit.elevate import PermissionElevator
from databricks_group_audit.escalation import ESCALATION_PRIVILEGES, detect_escalations
from databricks_group_audit.group_resolver import GroupMembershipResolver
from databricks_group_audit.local_groups import LocalGroupChecker
from databricks_group_audit.models import (
    AuditDiff,
    CatalogGrant,
    EffectivePermission,
    # Feature models
    EscalationFinding,
    GrantSource,
    GroupMember,
    # Principal audit models
    GroupMembership,
    GroupNode,
    LocalGroupFinding,
    MemberType,
    PrincipalAuditResult,
    PrincipalSource,
    RedundancyLevel,
    RedundancyResult,
    SchemaGrant,
    StaleFinding,
    TableGrant,
    WorkspaceInfo,
    WorkspaceRole,
)
from databricks_group_audit.principal_auditor import PrincipalAuditor
from databricks_group_audit.redundancy import RedundancyDetector
from databricks_group_audit.revoke import RevokeScriptGenerator
from databricks_group_audit.schema_scanner import SchemaPermissionScanner
from databricks_group_audit.snapshot import (
    build_group_snapshot,
    build_principal_snapshot,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
)
from databricks_group_audit.stale_checker import StaleGrantChecker
from databricks_group_audit.table_scanner import TablePermissionScanner
from databricks_group_audit.workspace import WORKSPACE_DOMAIN_MAP, WorkspaceDiscovery

# Optional SDK client — only available when databricks-sdk is installed
try:
    from databricks_group_audit.sdk_client import SDK_AVAILABLE, DatabricksSDKClient
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
    "AuditDiff",
    # CSV / snapshot
    "write_group_audit_csv",
    "write_principal_audit_csv",
    "build_group_snapshot",
    "build_principal_snapshot",
    "save_snapshot",
    "load_snapshot",
    "diff_snapshots",
    # Helpers
    "WORKSPACE_DOMAIN_MAP",
    "classify_catalog_grant",
    "classify_grant",
    "build_member_lookups",
]
