"""Shared data models used across the audit tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Group membership models
# ---------------------------------------------------------------------------

class MemberType(Enum):
    USER = "User"
    SERVICE_PRINCIPAL = "ServicePrincipal"
    GROUP = "Group"


@dataclass
class GroupMember:
    """A single member (user or service principal) of a group."""
    id: str
    display_name: str
    member_type: MemberType
    email: Optional[str] = None
    application_id: Optional[str] = None
    parent_groups: List[str] = field(default_factory=list)


@dataclass
class GroupNode:
    """A group in the hierarchy tree."""
    id: str
    display_name: str
    direct_users: List[GroupMember] = field(default_factory=list)
    direct_service_principals: List[GroupMember] = field(default_factory=list)
    nested_groups: Dict[str, GroupNode] = field(default_factory=dict)
    parent_path: List[str] = field(default_factory=list)


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


@dataclass
class WorkspaceRole:
    """A workspace assignment granted through a group (or directly)."""
    workspace_id: str
    workspace_name: str
    workspace_url: str
    permission_level: str  # USER, ADMIN
    via_group: str  # group name that provides this access
    via_group_id: str = ""


@dataclass
class EffectivePermission:
    """A Unity Catalog permission traced to the group that grants it."""
    securable_type: str  # CATALOG, SCHEMA, TABLE
    securable_name: str  # e.g. "main", "main.default", "main.default.orders"
    privileges: List[str] = field(default_factory=list)
    via_group: str = ""  # group name holding the grant
    workspace_name: str = ""
    workspace_url: str = ""


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
