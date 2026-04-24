"""CLI entry point for databricks-group-audit.

Usage (group audit)::

    databricks-group-audit --group "data-engineers" --cloud azure

Usage (principal audit)::

    databricks-group-audit --principal "alice@example.com" --cloud azure

Usage (force raw HTTP instead of SDK)::

    databricks-group-audit --group "data-engineers" --no-sdk
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List


def _parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="databricks-group-audit",
        description="Audit Databricks group membership and Unity Catalog permissions.",
    )
    # Credentials
    p.add_argument("--client-id", default=os.getenv("DATABRICKS_CLIENT_ID", ""),
                   help="Service principal client ID (env: DATABRICKS_CLIENT_ID)")
    p.add_argument("--client-secret", default=os.getenv("DATABRICKS_CLIENT_SECRET", ""),
                   help="Service principal secret (env: DATABRICKS_CLIENT_SECRET)")
    p.add_argument("--account-id", default=os.getenv("DATABRICKS_ACCOUNT_ID", ""),
                   help="Databricks account ID (env: DATABRICKS_ACCOUNT_ID)")
    p.add_argument("--cloud", choices=["azure", "aws", "gcp"], default="azure",
                   help="Cloud provider (default: azure)")

    # Target (mutually exclusive: --group OR --principal)
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--group", help="Display name of the group to audit")
    target.add_argument("--principal",
                        help="User email, SP app-ID/name, or group name for principal audit")

    p.add_argument("--workspace-urls", default="",
                   help="Comma-separated workspace URLs (omit to scan all)")

    # Scan depth
    p.add_argument("--scan-schemas", action="store_true", help="Scan schema-level grants")
    p.add_argument("--scan-tables", action="store_true", help="Scan table/view-level grants")

    # Output
    p.add_argument("--output", choices=["json", "text"], default="text",
                   help="Output format (default: text)")
    p.add_argument("--revoke-script", action="store_true",
                   help="Print REVOKE SQL for redundant grants (group audit only)")

    # Client selection
    p.add_argument("--no-sdk", action="store_true",
                   help="Force the raw HTTP client even when databricks-sdk is installed")

    # Retry tuning (applies to raw HTTP client; SDK manages its own retries)
    p.add_argument("--max-retries", type=int, default=5)
    p.add_argument("--retry-base-delay", type=float, default=1.0)
    p.add_argument("--retry-max-delay", type=float, default=60.0)

    # Permission elevation
    p.add_argument(
        "--auto-elevate",
        action="store_true",
        help=(
            "Temporarily grant the audit SP Workspace Admin on any workspace "
            "where it lacks that role, then restore the prior state after the "
            "audit completes (success or failure).  Requires Account Admin. "
            "Metastore Admin must still be granted manually."
        ),
    )
    p.add_argument(
        "--dry-run-elevation",
        action="store_true",
        help=(
            "Preview which workspaces would be elevated (--auto-elevate) without "
            "writing any permission changes.  Implies --auto-elevate."
        ),
    )

    # Privilege escalation detection (principal audit only)
    p.add_argument(
        "--escalation-check",
        action="store_true",
        help=(
            "Flag ALL_PRIVILEGES and MANAGE grants inherited by the principal "
            "through group membership.  Applies to --principal mode only."
        ),
    )

    # Stale grant detection (both modes)
    p.add_argument(
        "--stale-days",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Flag member-direct catalog grants whose holders have had no recorded "
            "activity in system.access.audit for the last N days.  Requires "
            "--sql-warehouse-id and --sql-workspace-url."
        ),
    )
    p.add_argument(
        "--sql-warehouse-id",
        default="",
        help="SQL warehouse ID used to query system.access.audit (required for --stale-days).",
    )
    p.add_argument(
        "--sql-workspace-url",
        default="",
        help=(
            "Workspace URL whose system.access.audit will be queried.  "
            "Defaults to the first discovered workspace when omitted."
        ),
    )

    # Workspace-local group detection (both modes)
    p.add_argument(
        "--check-local-groups",
        action="store_true",
        help=(
            "Scan each workspace's SCIM directory and flag groups that exist "
            "only at the workspace level (not in account SCIM).  These are "
            "legacy workspace-local groups pending Unity Catalog migration."
        ),
    )

    return p.parse_args(argv)


def _build_client(args: argparse.Namespace) -> Any:
    """Create the API client using the factory."""
    from databricks_group_audit.client import create_client

    return create_client(
        cloud=args.cloud,
        client_id=args.client_id,
        client_secret=args.client_secret,
        account_id=args.account_id,
        prefer_sdk=not args.no_sdk,
        max_retries=args.max_retries,
        base_delay=args.retry_base_delay,
        max_delay=args.retry_max_delay,
    )


def _elevation_context(args: argparse.Namespace, client: Any, workspaces: List):
    """Return a configured PermissionElevator, or a no-op context when not needed."""
    import contextlib
    from databricks_group_audit.elevate import PermissionElevator

    use_elevation = args.auto_elevate or args.dry_run_elevation
    if not use_elevation:
        return contextlib.nullcontext(None)

    dry_run = args.dry_run_elevation
    if dry_run:
        print("Permission elevation: DRY RUN — no changes will be written.")
    else:
        print("Permission elevation enabled — temporary Workspace Admin grants will be applied.")

    elevator = PermissionElevator(client, args.client_id, dry_run=dry_run)
    elevator.__enter__()

    for ws in workspaces:
        elevator.ensure_workspace_admin(ws.workspace_id, ws.workspace_name)

    # Return a context that only runs __exit__ (entry already done above).
    return _AlreadyEnteredContext(elevator)


class _AlreadyEnteredContext:
    """Wrap an already-entered context manager so `with` only calls __exit__."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __enter__(self) -> Any:
        return self._inner

    def __exit__(self, *args: Any) -> bool:
        return self._inner.__exit__(*args)


def _run_stale_check(
    args: argparse.Namespace,
    client: Any,
    catalog_grants: List,
    workspaces: List,
    workspace_name: str,
) -> List:
    """Run stale grant detection if --stale-days is set; return findings."""
    if not args.stale_days:
        return []
    if not args.sql_warehouse_id:
        print("WARNING: --stale-days requires --sql-warehouse-id; skipping stale check.",
              file=sys.stderr)
        return []

    from databricks_group_audit.stale_checker import StaleGrantChecker

    ws_url = args.sql_workspace_url
    if not ws_url:
        ws_url = workspaces[0].workspace_url if workspaces else ""
    if not ws_url:
        print("WARNING: No workspace available for --stale-days query; skipping.",
              file=sys.stderr)
        return []

    print(f"  Checking for stale grants (>{args.stale_days} days inactive) ...")
    checker = StaleGrantChecker(client, ws_url, args.sql_warehouse_id,
                                stale_days=args.stale_days)
    return checker.check_catalog_grants(catalog_grants, workspace_name, ws_url)


def _run_local_group_check(
    args: argparse.Namespace,
    client: Any,
    workspaces: List,
) -> List:
    """Run workspace-local group detection if --check-local-groups is set."""
    if not args.check_local_groups:
        return []

    from databricks_group_audit.local_groups import LocalGroupChecker

    print("  Checking for workspace-local groups ...")
    checker = LocalGroupChecker(client)
    return checker.check_all_workspaces(workspaces)


def _run_principal_audit(args: argparse.Namespace) -> int:
    """Run the principal-centric audit."""
    from databricks_group_audit.workspace import WorkspaceDiscovery
    from databricks_group_audit.principal_auditor import PrincipalAuditor
    from databricks_group_audit.escalation import detect_escalations

    client = _build_client(args)
    ws_disc = WorkspaceDiscovery(client, cloud_provider=args.cloud)
    auditor = PrincipalAuditor(client, workspace_discovery=ws_disc, cloud_provider=args.cloud)

    # Discover workspaces up-front so we can elevate before scanning.
    workspaces = ws_disc.discover(args.workspace_urls)

    print(f"Auditing principal: {args.principal} ...")
    try:
        with _elevation_context(args, client, workspaces):
            result = auditor.audit(
                identifier=args.principal,
                explicit_workspace_urls=args.workspace_urls,
                scan_schemas=args.scan_schemas,
                scan_tables=args.scan_tables,
            )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Optional: privilege escalation check
    if args.escalation_check:
        result.escalation_findings = detect_escalations(result)
        print(f"  Escalation check: {len(result.escalation_findings)} finding(s)")

    # Optional: workspace-local group check
    local_findings = _run_local_group_check(args, client, workspaces)

    if args.output == "json":
        out: Dict[str, Any] = {
            "principal": result.principal_name,
            "principal_type": result.principal_type,
            "timestamp": datetime.now().isoformat(),
            "groups": [{
                "name": g.group_name, "direct": g.is_direct, "path": g.path,
            } for g in result.groups],
            "workspace_roles": [{
                "workspace": r.workspace_name, "permission": r.permission_level,
                "via_group": r.via_group,
            } for r in result.workspace_roles],
            "permissions": [{
                "type": p.securable_type, "name": p.securable_name,
                "privileges": p.privileges, "via_group": p.via_group,
                "workspace": p.workspace_name,
            } for p in result.permissions],
            "dead_end_groups": result.dead_end_groups,
        }
        if args.escalation_check:
            out["escalation_findings"] = [{
                "privilege": f.privilege,
                "securable_type": f.securable_type,
                "securable_name": f.securable_name,
                "via_group": f.via_group,
                "is_transitive": f.is_transitive,
                "workspace": f.workspace_name,
            } for f in result.escalation_findings]
        if args.check_local_groups:
            out["local_group_findings"] = [{
                "group_name": f.group_name,
                "workspace": f.workspace_name,
                "member_count": f.member_count,
            } for f in local_findings]
        print(json.dumps(out, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  Principal: {result.principal_name} ({result.principal_type})")
        print(f"{'='*60}")

        print(f"\n  Group memberships ({len(result.groups)}):")
        for g in result.groups:
            tag = "direct" if g.is_direct else "transitive"
            print(f"    {'*' if g.is_direct else '-'} {g.group_name} ({tag})")
            print(f"      path: {' -> '.join(g.path)}")

        print(f"\n  Workspace access ({len(result.workspace_roles)}):")
        for r in result.workspace_roles:
            print(f"    * {r.workspace_name}: {r.permission_level} (via {r.via_group})")

        if result.dead_end_groups:
            print(f"\n  Dead-end groups (no workspace access): {len(result.dead_end_groups)}")
            for dg in result.dead_end_groups:
                print(f"    - {dg}")

        print(f"\n  UC permissions ({len(result.permissions)}):")
        for p in result.permissions:
            print(f"    * [{p.securable_type}] {p.securable_name}")
            print(f"      privileges: {', '.join(p.privileges)}")
            print(f"      via: {p.via_group} @ {p.workspace_name}")

        if args.escalation_check:
            findings = result.escalation_findings
            print(f"\n  Escalation risks ({len(findings)}):")
            if findings:
                for f in findings:
                    kind = "transitive" if f.is_transitive else "direct"
                    print(f"    ! RISK [{f.securable_type}] {f.securable_name}: "
                          f"{f.privilege} via {f.via_group} ({kind})")
            else:
                print("    No escalation risks found.")

        if args.check_local_groups:
            print(f"\n  Workspace-local groups ({len(local_findings)}):")
            for f in local_findings:
                print(f"    ! {f.group_name} in '{f.workspace_name}' "
                      f"({f.member_count} member(s)) — not in account SCIM")

        print(f"\n{'='*60}")

    return 0


def _run_group_audit(args: argparse.Namespace) -> int:
    """Run the group-centric audit (original behavior)."""
    from databricks_group_audit.group_resolver import GroupMembershipResolver
    from databricks_group_audit.workspace import WorkspaceDiscovery
    from databricks_group_audit.catalog_scanner import CatalogPermissionScanner
    from databricks_group_audit.schema_scanner import SchemaPermissionScanner
    from databricks_group_audit.table_scanner import TablePermissionScanner
    from databricks_group_audit.redundancy import RedundancyDetector
    from databricks_group_audit.revoke import RevokeScriptGenerator
    from databricks_group_audit.models import GrantSource, WorkspaceInfo

    client = _build_client(args)

    resolver = GroupMembershipResolver(client)
    print(f"Resolving group: {args.group} ...")
    group_node = resolver.resolve_group(args.group)
    if not group_node:
        print(f"ERROR: Group '{args.group}' not found.", file=sys.stderr)
        return 1
    members = resolver.get_all_members_flat(group_node)
    print(f"  Found {len(members['users'])} users, {len(members['service_principals'])} SPs")

    ws_disc = WorkspaceDiscovery(client, cloud_provider=args.cloud)
    workspaces = ws_disc.discover(args.workspace_urls)
    print(f"  Scanning {len(workspaces)} workspace(s)")

    cat_scanner = CatalogPermissionScanner(client, resolver)

    schema_grants: List = []
    table_grants: List = []

    with _elevation_context(args, client, workspaces):
        catalog_grants = cat_scanner.scan_all_workspaces(workspaces, args.group, group_node, members)
        print(f"  Found {len(catalog_grants)} catalog grant(s)")

        if args.scan_schemas or args.scan_tables:
            sch_scanner = SchemaPermissionScanner(client)
            upstream = cat_scanner.get_groups_containing_target(args.group)
            accessible = {(g.catalog_name, g.workspace_url) for g in catalog_grants
                          if g.grant_source in (GrantSource.DIRECT, GrantSource.UPSTREAM)}
            for cat_name, ws_url in accessible:
                ws = WorkspaceInfo("scan", "", "", ws_url, args.cloud.upper(), "")
                schema_grants.extend(sch_scanner.scan_schemas(ws, cat_name, args.group, members, upstream))
            print(f"  Found {len(schema_grants)} schema grant(s)")

        if args.scan_tables:
            tbl_scanner = TablePermissionScanner(client)
            for cat_name, ws_url in accessible:
                ws = WorkspaceInfo("scan", "", "", ws_url, args.cloud.upper(), "")
                for sch in sch_scanner.get_schemas(ws, cat_name):
                    sname = sch.get("name", "")
                    table_grants.extend(tbl_scanner.scan_tables(ws, cat_name, sname, args.group, members, upstream))
            print(f"  Found {len(table_grants)} table grant(s)")

    detector = RedundancyDetector()
    redundancy = detector.detect_redundancy(catalog_grants, args.group)

    # Optional: stale grant detection
    stale_findings = _run_stale_check(
        args, client, catalog_grants, workspaces,
        workspace_name=workspaces[0].workspace_name if workspaces else "",
    )

    # Optional: workspace-local group check
    local_findings = _run_local_group_check(args, client, workspaces)

    if args.output == "json":
        result: Dict[str, Any] = {
            "group": args.group,
            "timestamp": datetime.now().isoformat(),
            "users": len(members["users"]),
            "service_principals": len(members["service_principals"]),
            "catalog_grants": len(catalog_grants),
            "schema_grants": len(schema_grants),
            "table_grants": len(table_grants),
            "full_redundancy": sum(1 for r in redundancy if r.redundancy_level.value == "Full"),
            "partial_redundancy": sum(1 for r in redundancy if r.redundancy_level.value == "Partial"),
        }
        if args.stale_days:
            result["stale_findings"] = [{
                "principal": f.principal,
                "catalog": f.catalog_name,
                "privileges": f.privileges,
                "stale_days": f.stale_days,
                "workspace": f.workspace_name,
            } for f in stale_findings]
        if args.check_local_groups:
            result["local_group_findings"] = [{
                "group_name": f.group_name,
                "workspace": f.workspace_name,
                "member_count": f.member_count,
            } for f in local_findings]
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  Audit complete for group: {args.group}")
        print(f"  Users: {len(members['users'])}  |  SPs: {len(members['service_principals'])}")
        print(f"  Catalog grants: {len(catalog_grants)}  |  Schema: {len(schema_grants)}  |  Table: {len(table_grants)}")
        full = sum(1 for r in redundancy if r.redundancy_level.value == "Full")
        partial = sum(1 for r in redundancy if r.redundancy_level.value == "Partial")
        print(f"  Redundancy: {full} full, {partial} partial")

        if stale_findings:
            print(f"\n  Stale grants ({len(stale_findings)}, no activity in {args.stale_days} days):")
            for f in stale_findings:
                print(f"    ! {f.principal}: {', '.join(f.privileges)} on {f.catalog_name}")

        if args.check_local_groups:
            print(f"\n  Workspace-local groups ({len(local_findings)}):")
            for f in local_findings:
                print(f"    ! {f.group_name} in '{f.workspace_name}' "
                      f"({f.member_count} member(s)) — not in account SCIM")

        print(f"{'='*60}")

    if args.revoke_script:
        print("\n" + RevokeScriptGenerator.generate(redundancy, include_partial=True))

    return 0


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(argv)

    if not args.client_id or not args.client_secret or not args.account_id:
        print("ERROR: --client-id, --client-secret, and --account-id are required.", file=sys.stderr)
        return 1

    if args.principal:
        return _run_principal_audit(args)
    else:
        return _run_group_audit(args)
