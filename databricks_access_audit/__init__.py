"""Databricks Access Audit.

Audit Databricks access across all workspaces — Unity Catalog permissions and workspace object ACLs.

Quick start::

    from databricks_access_audit import create_client, GroupMembershipResolver

    client = create_client(cloud="azure", client_id="...",
                           client_secret="...", account_id="...")
    resolver = GroupMembershipResolver(client)
    node = resolver.resolve_group("data-engineers")
"""

__version__ = "0.18.3"

from databricks_access_audit._classification import build_member_lookups, classify_grant
from databricks_access_audit.access_cloner import AccessCloner
from databricks_access_audit.catalog_scanner import CatalogPermissionScanner, classify_catalog_grant
from databricks_access_audit.client import (
    AuditClient,
    DatabricksAPIClient,
    create_client,
)
from databricks_access_audit.csv_output import (
    write_clone_report_csv,
    write_compare_csv,
    write_group_audit_csv,
    write_principal_audit_csv,
)
from databricks_access_audit.elevate import PermissionElevator
from databricks_access_audit.escalation import ESCALATION_PRIVILEGES, detect_escalations
from databricks_access_audit.group_resolver import GroupMembershipResolver
from databricks_access_audit.local_groups import LocalGroupChecker
from databricks_access_audit.models import (
    AuditDiff,
    CatalogGrant,
    # Clone / provisioning models
    CloneAction,
    CloneActionType,
    CloneReport,
    # Compare models
    CompareResult,
    EffectivePermission,
    # Feature models
    EscalationFinding,
    GrantSource,
    GroupComparison,
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
    WorkspaceObjectGrant,
    WorkspaceRole,
)
from databricks_access_audit.principal_auditor import PrincipalAuditor
from databricks_access_audit.principal_comparer import PrincipalComparer
from databricks_access_audit.redundancy import RedundancyDetector
from databricks_access_audit.revoke import RevokeScriptGenerator
from databricks_access_audit.schema_scanner import SchemaPermissionScanner
from databricks_access_audit.snapshot import (
    build_group_snapshot,
    build_principal_snapshot,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
)
from databricks_access_audit.stale_checker import StaleGrantChecker
from databricks_access_audit.table_scanner import TablePermissionScanner
from databricks_access_audit.workspace import WORKSPACE_DOMAIN_MAP, WorkspaceDiscovery
from databricks_access_audit.workspace_object_scanner import (
    ALL_OBJECT_TYPES,
    WorkspaceObjectScanner,
)

# Optional SDK client — only available when databricks-sdk is installed
try:
    from databricks_access_audit.sdk_client import SDK_AVAILABLE, DatabricksSDKClient
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
    "WorkspaceObjectScanner",
    "ALL_OBJECT_TYPES",
    "RedundancyDetector",
    "RevokeScriptGenerator",
    "PrincipalAuditor",
    "PrincipalComparer",
    "AccessCloner",
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
    "WorkspaceObjectGrant",
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
    # Compare / clone models
    "GroupComparison",
    "CompareResult",
    "CloneActionType",
    "CloneAction",
    "CloneReport",
    # CSV / snapshot
    "write_group_audit_csv",
    "write_principal_audit_csv",
    "write_compare_csv",
    "write_clone_report_csv",
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
