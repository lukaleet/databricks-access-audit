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
    workspace_object_grants: Optional[List] = None,
    output: Optional[TextIO] = None,
) -> None:
    """Write group audit results as CSV.  Grants, then redundancy, then workspace objects."""
    out = output or sys.stdout
    w = csv.writer(out)

    # UC grants table
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

    if workspace_object_grants:
        w.writerow([])
        w.writerow(["object_type", "object_id", "object_name", "workspace",
                    "principal", "principal_type", "permission_level",
                    "grant_source", "inherited_from"])
        for g in workspace_object_grants:
            w.writerow([g.object_type, g.object_id, g.object_name,
                        g.workspace_name, g.principal, g.principal_type,
                        g.permission_level, g.grant_source.value,
                        g.inherited_from or ""])


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
    w.writerow(["workspace_id", "workspace_name", "permission_level", "via_group", "via_path"])
    for r in result.workspace_roles:
        w.writerow([r.workspace_id, r.workspace_name, r.permission_level, r.via_group,
                    " → ".join(r.via_path) if r.via_path else ""])

    # Permissions table
    w.writerow([])
    w.writerow(["securable_type", "securable_name", "privileges", "via_group", "via_path",
                "workspace"])
    for p in result.permissions:
        w.writerow([p.securable_type, p.securable_name,
                    "|".join(p.privileges), p.via_group,
                    " → ".join(p.via_path) if p.via_path else "",
                    p.workspace_name])

    if escalation_findings:
        w.writerow([])
        w.writerow(["privilege", "securable_type", "securable_name",
                    "via_group", "is_transitive", "workspace"])
        for f in escalation_findings:
            w.writerow([f.privilege, f.securable_type, f.securable_name,
                        f.via_group, f.is_transitive, f.workspace_name])

    if getattr(result, "workspace_object_grants", None):
        w.writerow([])
        w.writerow(["object_type", "object_id", "object_name", "workspace",
                    "principal", "principal_type", "permission_level",
                    "grant_source", "inherited_from"])
        for g in result.workspace_object_grants:
            w.writerow([g.object_type, g.object_id, g.object_name,
                        g.workspace_name, g.principal, g.principal_type,
                        g.permission_level, g.grant_source.value,
                        g.inherited_from or ""])


def write_compare_csv(result: Any, output: Optional[TextIO] = None) -> None:
    """Write a CompareResult as CSV."""
    out = output or sys.stdout
    w = csv.writer(out)

    w.writerow(["group_id", "group_name", "source",
                "in_a", "in_b", "is_direct_in_a", "is_direct_in_b",
                "path_in_a", "path_in_b"])
    for section in (result.only_in_a, result.only_in_b, result.in_both):
        for gc in section:
            w.writerow([
                gc.group_id, gc.group_name, gc.source.value,
                gc.in_a, gc.in_b, gc.is_direct_in_a, gc.is_direct_in_b,
                " → ".join(gc.path_in_a), " → ".join(gc.path_in_b),
            ])


def write_clone_report_csv(report: Any, output: Optional[TextIO] = None) -> None:
    """Write a CloneReport as CSV."""
    out = output or sys.stdout
    w = csv.writer(out)

    w.writerow(["action_type", "group_name", "group_id", "source",
                "path", "workspace_accesses", "uc_grants_summary",
                "applied", "error"])
    for a in report.actions:
        w.writerow([
            a.action_type.value, a.group_name, a.group_id, a.source.value,
            " → ".join(a.path), ", ".join(a.workspace_accesses),
            a.uc_grants_summary, a.applied, a.error or "",
        ])


def write_resource_audit_csv(result: Any, output: Optional[TextIO] = None) -> None:
    """Write resource audit results as CSV.

    Columns: resource_type, resource_name, principal_name, principal_type,
             principal_source, privileges, via_group, workspace_name
    """
    out = output or sys.stdout
    w = csv.writer(out)

    w.writerow([
        "resource_type", "resource_name", "principal_name", "principal_type",
        "principal_source", "privileges", "via_group", "workspace_name",
    ])
    for g in result.grants:
        w.writerow([
            g.resource_type,
            g.resource_name,
            g.principal_name,
            g.principal_type,
            g.principal_source.value,
            "|".join(g.privileges),
            g.via_group or "",
            g.workspace_name,
        ])


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
