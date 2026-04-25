"""CSV serialisation for audit results."""

from __future__ import annotations

import csv
import sys
from typing import Any, List, Optional, TextIO


def write_group_audit_csv(
    catalog_grants: List,
    schema_grants: List,
    table_grants: List,
    redundancy: List,
    output: Optional[TextIO] = None,
) -> None:
    """Write group audit results as CSV.  Grants first, then redundancy findings."""
    out = output or sys.stdout
    w = csv.writer(out)

    # Grants table
    w.writerow(["securable_type", "workspace", "securable_name",
                "principal", "principal_type", "privileges",
                "grant_source", "inherited_from"])
    for g in catalog_grants:
        w.writerow(["CATALOG", g.workspace_name, g.catalog_name, g.principal,
                    g.principal_type, "|".join(g.privileges),
                    g.grant_source.value, g.inherited_from or ""])
    for g in schema_grants:
        w.writerow(["SCHEMA", g.workspace_name, f"{g.catalog_name}.{g.schema_name}",
                    g.principal, g.principal_type, "|".join(g.privileges),
                    g.grant_source.value, g.inherited_from or ""])
    for g in table_grants:
        w.writerow(["TABLE", g.workspace_name, g.full_name, g.principal,
                    g.principal_type, "|".join(g.privileges),
                    g.grant_source.value, g.inherited_from or ""])

    if redundancy:
        w.writerow([])
        w.writerow(["catalog", "principal", "principal_type",
                    "member_privileges", "group_effective_privileges",
                    "redundant_privileges", "additional_privileges",
                    "redundancy_level", "recommendation"])
        for r in redundancy:
            w.writerow([r.catalog_name, r.principal, r.principal_type,
                        "|".join(r.member_privileges),
                        "|".join(r.group_effective_privileges),
                        "|".join(r.redundant_privileges),
                        "|".join(r.additional_privileges),
                        r.redundancy_level.value, r.recommendation])


def write_principal_audit_csv(
    result: Any,
    escalation_findings: List,
    output: Optional[TextIO] = None,
) -> None:
    """Write principal audit results as CSV.

    Sections (separated by blank rows):
    1. Group memberships
    2. Workspace roles
    3. UC permissions
    4. Escalation findings (only when present)
    """
    out = output or sys.stdout
    w = csv.writer(out)

    # Group memberships
    w.writerow(["group_id", "group_name", "is_direct", "path", "source"])
    for g in result.groups:
        w.writerow([g.group_id, g.group_name, g.is_direct,
                    " -> ".join(g.path), g.source.value])

    # Workspace roles
    w.writerow([])
    w.writerow(["workspace_id", "workspace_name", "permission_level", "via_group"])
    for r in result.workspace_roles:
        w.writerow([r.workspace_id, r.workspace_name, r.permission_level, r.via_group])

    # Permissions table
    w.writerow([])
    w.writerow(["securable_type", "securable_name", "privileges", "via_group", "workspace"])
    for p in result.permissions:
        w.writerow([p.securable_type, p.securable_name,
                    "|".join(p.privileges), p.via_group, p.workspace_name])

    if escalation_findings:
        w.writerow([])
        w.writerow(["privilege", "securable_type", "securable_name",
                    "via_group", "is_transitive", "workspace"])
        for f in escalation_findings:
            w.writerow([f.privilege, f.securable_type, f.securable_name,
                        f.via_group, f.is_transitive, f.workspace_name])


def write_diff_csv(diff: Any, output: Optional[TextIO] = None) -> None:
    """Write an AuditDiff as CSV."""
    out = output or sys.stdout
    w = csv.writer(out)

    w.writerow(["change_type", "securable_type", "workspace", "securable_name",
                "principal", "principal_type", "privileges", "grant_source"])
    for g in diff.grants_added:
        w.writerow(["GRANT_ADDED", g.get("securable_type", ""), g.get("workspace_name", ""),
                    g.get("securable_name", ""), g.get("principal", g.get("via_group", "")),
                    g.get("principal_type", ""), "|".join(g.get("privileges", [])),
                    g.get("grant_source", "")])
    for g in diff.grants_removed:
        w.writerow(["GRANT_REMOVED", g.get("securable_type", ""), g.get("workspace_name", ""),
                    g.get("securable_name", ""), g.get("principal", g.get("via_group", "")),
                    g.get("principal_type", ""), "|".join(g.get("privileges", [])),
                    g.get("grant_source", "")])

    if diff.members_added or diff.members_removed:
        w.writerow([])
        w.writerow(["change_type", "id_or_group_id", "name", "type", "external_id", "", "", ""])
        for m in diff.members_added:
            w.writerow(["MEMBER_ADDED",
                        m.get("id", m.get("group_id", "")),
                        m.get("display_name", m.get("group_name", "")),
                        m.get("type", "GROUP"), m.get("external_id", ""), "", "", ""])
        for m in diff.members_removed:
            w.writerow(["MEMBER_REMOVED",
                        m.get("id", m.get("group_id", "")),
                        m.get("display_name", m.get("group_name", "")),
                        m.get("type", "GROUP"), m.get("external_id", ""), "", "", ""])
