"""Shared data models used across the audit tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Group membership models
# ---------------------------------------------------------------------------

class MemberType(Enum):
    USER = "User"
    SERVICE_PRINCIPAL = "ServicePrincipal"
    GROUP = "Group"


class PrincipalSource(Enum):
    """Origin of a Databricks principal (user, SP, or group).

    ``EXTERNAL`` means the principal was provisioned by an external identity
    provider (Azure Entra ID, Okta, AWS SSO, etc.) via SCIM — indicated by a
    non-empty ``externalId`` field in the SCIM response.

    ``INTERNAL`` means the principal was created directly inside Databricks
    (the SCIM ``externalId`` field is absent or empty).  This includes
    Databricks OAuth service principals and manually created accounts.
    """
    EXTERNAL = "external"   # has SCIM externalId → provisioned by an IdP
    INTERNAL = "internal"   # no externalId       → Databricks-managed


def _source_from_external_id(external_id: Optional[str]) -> PrincipalSource:
    """Return :class:`PrincipalSource` based on whether ``externalId`` is set."""
    return PrincipalSource.EXTERNAL if external_id else PrincipalSource.INTERNAL


@dataclass
class GroupMember:
    """A single member (user or service principal) of a group."""
    id: str
    display_name: str
    member_type: MemberType
    email: Optional[str] = None
    application_id: Optional[str] = None
    parent_groups: List[str] = field(default_factory=list)
    # SCIM externalId — non-empty when provisioned by an external IdP.
    external_id: Optional[str] = None

    @property
    def source(self) -> PrincipalSource:
        """Whether this member is IdP-synced or Databricks-managed."""
        return _source_from_external_id(self.external_id)


@dataclass
class GroupNode:
    """A group in the hierarchy tree."""
    id: str
    display_name: str
    direct_users: List[GroupMember] = field(default_factory=list)
    direct_service_principals: List[GroupMember] = field(default_factory=list)
    nested_groups: Dict[str, GroupNode] = field(default_factory=dict)
    parent_path: List[str] = field(default_factory=list)
    # SCIM externalId — non-empty when provisioned by an external IdP.
    external_id: Optional[str] = None

    @property
    def source(self) -> PrincipalSource:
        """Whether this group is IdP-synced or Databricks-managed."""
        return _source_from_external_id(self.external_id)


# ---------------------------------------------------------------------------
# Workspace model
# ---------------------------------------------------------------------------

@dataclass
class WorkspaceInfo:
    """Information about a Databricks workspace."""
    workspace_id: str
    deployment_name: str
    workspace_name: str
    workspace_url: str
    cloud: str
    region: str


# ---------------------------------------------------------------------------
# Permission / grant models
# ---------------------------------------------------------------------------

class GrantSource(Enum):
    """How a permission was acquired."""
    DIRECT = "Direct"
    UPSTREAM = "Upstream"
    MEMBER_DIRECT = "Member Direct"


@dataclass
class CatalogGrant:
    """Permission grant on a catalog."""
    catalog_name: str
    workspace_name: str
    workspace_url: str
    principal: str
    principal_type: str
    privileges: List[str]
    grant_source: GrantSource
    inherited_from: Optional[str] = None
    member_of_target: bool = False


@dataclass
class SchemaGrant:
    """Permission grant on a schema."""
    catalog_name: str
    schema_name: str
    workspace_name: str
    workspace_url: str
    principal: str
    principal_type: str
    privileges: List[str]
    grant_source: GrantSource
    inherited_from: Optional[str] = None
    member_of_target: bool = False


@dataclass
class TableGrant:
    """Permission grant on a table or view."""
    catalog_name: str
    schema_name: str
    table_name: str
    full_name: str
    table_type: str
    workspace_name: str
    workspace_url: str
    principal: str
    principal_type: str
    privileges: List[str]
    grant_source: GrantSource
    inherited_from: Optional[str] = None
    member_of_target: bool = False


@dataclass
class WorkspaceObjectGrant:
    """Permission grant on a workspace-level object (job, cluster, SQL warehouse, etc.).

    Unlike Unity Catalog grants (which use privilege lists), workspace object
    permissions use a single ``permission_level`` (e.g. CAN_MANAGE, CAN_RUN).
    """
    object_type: str       # "JOB" | "CLUSTER" | "SQL_WAREHOUSE" | "PIPELINE" | "CLUSTER_POLICY"
    object_id: str
    object_name: str
    workspace_name: str
    workspace_url: str
    principal: str
    principal_type: str    # "GROUP" | "USER" | "SERVICE_PRINCIPAL"
    permission_level: str  # e.g. "CAN_VIEW" | "CAN_RUN" | "CAN_MANAGE"
    grant_source: GrantSource
    inherited_from: Optional[str] = None  # upstream group name for UPSTREAM grants
    member_of_target: bool = False


# ---------------------------------------------------------------------------
# Redundancy models
# ---------------------------------------------------------------------------

class RedundancyLevel(Enum):
    NONE = "None"
    PARTIAL = "Partial"
    FULL = "Full"


@dataclass
class RedundancyResult:
    """Redundancy analysis for a single member grant."""
    catalog_name: str
    principal: str
    principal_type: str
    member_privileges: List[str]
    group_effective_privileges: List[str]
    redundant_privileges: List[str]
    additional_privileges: List[str]
    redundancy_level: RedundancyLevel
    recommendation: str


# ---------------------------------------------------------------------------
# Principal audit models (reverse / "who can access what" perspective)
# ---------------------------------------------------------------------------

@dataclass
class GroupMembership:
    """A group that a principal belongs to."""
    group_id: str
    group_name: str
    path: List[str] = field(default_factory=list)
    is_direct: bool = True
    # SCIM externalId of the group — non-empty when provisioned by an IdP.
    external_id: Optional[str] = None

    @property
    def source(self) -> "PrincipalSource":
        return _source_from_external_id(self.external_id)


@dataclass
class WorkspaceRole:
    """A workspace assignment granted through a group (or directly)."""
    workspace_id: str
    workspace_name: str
    workspace_url: str
    permission_level: str  # USER, ADMIN
    via_group: str  # group name that provides this access
    via_group_id: str = ""
    via_path: List[str] = field(default_factory=list)  # full chain: principal → ... → group


@dataclass
class EffectivePermission:
    """A Unity Catalog permission traced to the group that grants it."""
    securable_type: str  # CATALOG, SCHEMA, TABLE
    securable_name: str  # e.g. "main", "main.default", "main.default.orders"
    privileges: List[str] = field(default_factory=list)
    via_group: str = ""  # group name holding the grant
    workspace_name: str = ""
    workspace_url: str = ""
    via_path: List[str] = field(default_factory=list)  # full chain: principal → ... → group


@dataclass
class PrincipalAuditResult:
    """Complete audit for a single principal (user, SP, or group)."""
    principal_type: str  # USER, SERVICE_PRINCIPAL, GROUP
    principal_id: str
    principal_name: str  # email or display name
    groups: List[GroupMembership] = field(default_factory=list)
    workspace_roles: List[WorkspaceRole] = field(default_factory=list)
    permissions: List[EffectivePermission] = field(default_factory=list)
    dead_end_groups: List[str] = field(default_factory=list)
    uc_only_groups: List[str] = field(default_factory=list)
    escalation_findings: List["EscalationFinding"] = field(default_factory=list)
    workspace_object_grants: List["WorkspaceObjectGrant"] = field(default_factory=list)
    # SCIM externalId of the principal — non-empty when provisioned by an IdP.
    principal_external_id: Optional[str] = None

    @property
    def principal_source(self) -> "PrincipalSource":
        return _source_from_external_id(self.principal_external_id)


# ---------------------------------------------------------------------------
# Privilege escalation models
# ---------------------------------------------------------------------------

@dataclass
class EscalationFinding:
    """A high-privilege UC grant that represents a potential escalation risk.

    ALL_PRIVILEGES and MANAGE are the two privileges that allow a principal
    to either access everything (ALL_PRIVILEGES) or grant access to others
    (MANAGE), making them the primary escalation vectors in Unity Catalog.
    """
    principal_name: str
    privilege: str          # e.g. "ALL_PRIVILEGES" or "MANAGE"
    securable_type: str     # "CATALOG", "SCHEMA", or "TABLE"
    securable_name: str     # e.g. "main" or "main.default"
    via_group: str          # the group holding the grant
    is_transitive: bool     # True when the grant is via a group, not direct
    workspace_name: str
    workspace_url: str


# ---------------------------------------------------------------------------
# Stale grant models
# ---------------------------------------------------------------------------

@dataclass
class StaleFinding:
    """A member-direct catalog grant with no recent activity in system.access.audit.

    ``last_access`` is None when the principal has not appeared in the audit
    log at all within the configured ``stale_days`` window.
    """
    principal: str
    principal_type: str     # "USER", "SERVICE_PRINCIPAL", or "GROUP"
    catalog_name: str
    privileges: List[str]
    workspace_name: str
    workspace_url: str
    last_access: Optional[str]  # ISO date string or None ("no activity in window")
    stale_days: int             # the configured inactivity threshold


# ---------------------------------------------------------------------------
# Workspace-local group models
# ---------------------------------------------------------------------------

@dataclass
class LocalGroupFinding:
    """A group found in workspace SCIM but absent from account SCIM.

    Workspace-local groups are a legacy artefact from before Unity Catalog
    account-level group migration (Databricks recommends migrating all groups
    to account SCIM as workspace-local groups are being deprecated).
    """
    group_name: str
    group_id: str           # workspace-local SCIM ID
    workspace_name: str
    workspace_url: str
    member_count: int


# ---------------------------------------------------------------------------
# Audit snapshot diff models
# ---------------------------------------------------------------------------

@dataclass
class AuditDiff:
    """Delta between two audit snapshots produced by diff_snapshots().

    ``grants_added`` / ``grants_removed`` are plain dicts matching the
    snapshot grant schema.  ``members_added`` / ``members_removed`` are
    plain dicts matching the snapshot member schema (group mode: user/SP
    dicts; principal mode: group-membership dicts).
    """
    baseline_timestamp: str
    current_timestamp: str
    mode: str    # "group" or "principal"
    target: str  # group name or principal identifier
    grants_added: List[Dict[str, Any]] = field(default_factory=list)
    grants_removed: List[Dict[str, Any]] = field(default_factory=list)
    members_added: List[Dict[str, Any]] = field(default_factory=list)
    members_removed: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.grants_added or self.grants_removed
            or self.members_added or self.members_removed
        )


# ---------------------------------------------------------------------------
# Principal comparison models
# ---------------------------------------------------------------------------

@dataclass
class GroupComparison:
    """A group appearing in a principal comparison, with membership info for each side."""
    group_id: str
    group_name: str
    external_id: Optional[str]
    in_a: bool
    in_b: bool
    is_direct_in_a: bool = False
    is_direct_in_b: bool = False
    path_in_a: List[str] = field(default_factory=list)
    path_in_b: List[str] = field(default_factory=list)

    @property
    def source(self) -> PrincipalSource:
        return _source_from_external_id(self.external_id)


@dataclass
class CompareResult:
    """Membership diff between two principals."""
    principal_a: str          # identifier used (email / display name)
    principal_b: str
    display_name_a: str       # resolved display name
    display_name_b: str
    only_in_a: List[GroupComparison] = field(default_factory=list)
    only_in_b: List[GroupComparison] = field(default_factory=list)
    in_both: List[GroupComparison] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Access clone / provisioning models
# ---------------------------------------------------------------------------

class CloneActionType(str, Enum):
    """How an access-clone action should be handled."""
    DATABRICKS = "Databricks"    # Databricks-managed group — tool can SCIM PATCH
    IDP_REQUIRED = "IdP required"  # IdP-synced group — must be done in Entra/Okta/etc.
    UNVERIFIED = "Unverified"    # No workspace assignment; UC not scanned — verify before cloning
    SKIPPED = "Skipped"          # Dead-end verified (no workspace, no UC grants)


@dataclass
class CloneAction:
    """One recommended action in a clone provisioning report."""
    action_type: CloneActionType
    group_id: str
    group_name: str
    external_id: Optional[str]          # non-empty for IdP-synced groups
    path: List[str]                     # source principal's path to this group
    workspace_accesses: List[str] = field(default_factory=list)  # workspace names
    uc_grants_summary: str = ""         # e.g. "SELECT on pii_catalog.schema" (when --scan-uc)
    applied: bool = False               # True after successful SCIM PATCH
    error: Optional[str] = None         # set when apply fails

    @property
    def source(self) -> PrincipalSource:
        return _source_from_external_id(self.external_id)


@dataclass
class CloneReport:
    """Provisioning report: make target's access mirror source's access."""
    source_principal: str
    target_principal: str
    source_display_name: str
    target_display_name: str
    actions: List[CloneAction] = field(default_factory=list)

    @property
    def idp_actions(self) -> List[CloneAction]:
        return [a for a in self.actions if a.action_type == CloneActionType.IDP_REQUIRED]

    @property
    def databricks_actions(self) -> List[CloneAction]:
        return [a for a in self.actions if a.action_type == CloneActionType.DATABRICKS]

    @property
    def unverified_actions(self) -> List[CloneAction]:
        return [a for a in self.actions if a.action_type == CloneActionType.UNVERIFIED]

    @property
    def skipped(self) -> List[CloneAction]:
        return [a for a in self.actions if a.action_type == CloneActionType.SKIPPED]


# ---------------------------------------------------------------------------
# Resource audit models (resource-centric: 'who has access to X?')
# ---------------------------------------------------------------------------

@dataclass
class ResourceGrant:
    """One identity's direct or inherited access to a specific resource."""
    resource_type: str       # "CATALOG", "SCHEMA", "TABLE", "WORKSPACE"
    resource_name: str
    principal_name: str
    principal_type: str      # "USER", "SERVICE_PRINCIPAL", "GROUP"
    principal_source: PrincipalSource
    privileges: List[str]
    via_group: Optional[str]  # None = direct grant; group name = inherited
    workspace_name: str


@dataclass
class ResourceAuditResult:
    """Complete result of a resource-centric audit."""
    resource_type: str
    resource_name: str
    grants: List[ResourceGrant] = field(default_factory=list)
