"""CLI entry point for databricks-group-audit.

Usage (group audit):
    databricks-group-audit --group "data-engineers" --cloud azure

Usage (principal audit):
    databricks-group-audit --principal "alice@example.com" --cloud azure
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

    # Retry tuning
    p.add_argument("--max-retries", type=int, default=5)
    p.add_argument("--retry-base-delay", type=float, default=1.0)
    p.add_argument("--retry-max-delay", type=float, default=60.0)

    return p.parse_args(argv)


def _run_principal_audit(args: argparse.Namespace) -> int:
    """Run the principal-centric audit."""
    from databricks_group_audit.client import DatabricksAPIClient
    from databricks_group_audit.workspace import WorkspaceDiscovery
    from databricks_group_audit.principal_auditor import PrincipalAuditor

    client = DatabricksAPIClient.for_cloud(
        cloud=args.cloud,
        client_id=args.client_id,
        client_secret=args.client_secret,
        account_id=args.account_id,
        max_retries=args.max_retries,
        base_delay=args.retry_base_delay,
        max_delay=args.retry_max_delay,
    )

    ws_disc = WorkspaceDiscovery(client, cloud_provider=args.cloud)
    auditor = PrincipalAuditor(client, workspace_discovery=ws_disc, cloud_provider=args.cloud)

    print(f"Auditing principal: {args.principal} ...")
    try:
        result = auditor.audit(
            identifier=args.principal,
            explicit_workspace_urls=args.workspace_urls,
            scan_schemas=args.scan_schemas,
            scan_tables=args.scan_tables,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

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

        print(f"\n{'='*60}")

    return 0


def _run_group_audit(args: argparse.Namespace) -> int:
    """Run the group-centric audit (original behavior)."""
    from databricks_group_audit.client import DatabricksAPIClient
    from databricks_group_audit.group_resolver import GroupMembershipResolver
    from databricks_group_audit.workspace import WorkspaceDiscovery
    from databricks_group_audit.catalog_scanner import CatalogPermissionScanner
    from databricks_group_audit.schema_scanner import SchemaPermissionScanner
    from databricks_group_audit.table_scanner import TablePermissionScanner
    from databricks_group_audit.redundancy import RedundancyDetector
    from databricks_group_audit.revoke import RevokeScriptGenerator
    from databricks_group_audit.models import GrantSource, WorkspaceInfo

    client = DatabricksAPIClient.for_cloud(
        cloud=args.cloud,
        client_id=args.client_id,
        client_secret=args.client_secret,
        account_id=args.account_id,
        max_retries=args.max_retries,
        base_delay=args.retry_base_delay,
        max_delay=args.retry_max_delay,
    )

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
    catalog_grants = cat_scanner.scan_all_workspaces(workspaces, args.group, group_node, members)
    print(f"  Found {len(catalog_grants)} catalog grant(s)")

    schema_grants: List = []
    if args.scan_schemas or args.scan_tables:
        sch_scanner = SchemaPermissionScanner(client)
        upstream = cat_scanner.get_groups_containing_target(args.group)
        accessible = {(g.catalog_name, g.workspace_url) for g in catalog_grants
                      if g.grant_source in (GrantSource.DIRECT, GrantSource.UPSTREAM)}
        for cat_name, ws_url in accessible:
            ws = WorkspaceInfo("scan", "", "", ws_url, args.cloud.upper(), "")
            schema_grants.extend(sch_scanner.scan_schemas(ws, cat_name, args.group, members, upstream))
        print(f"  Found {len(schema_grants)} schema grant(s)")

    table_grants: List = []
    if args.scan_tables:
        tbl_scanner = TablePermissionScanner(client)
        for cat_name, ws_url in accessible:
            ws = WorkspaceInfo("scan", "", "", ws_url, args.cloud.upper(), "")
            for sch in sch_scanner._get_schemas(ws, cat_name):
                sname = sch.get("name", "")
                table_grants.extend(tbl_scanner.scan_tables(ws, cat_name, sname, args.group, members, upstream))
        print(f"  Found {len(table_grants)} table grant(s)")

    detector = RedundancyDetector()
    redundancy = detector.detect_redundancy(catalog_grants, args.group)

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
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  Audit complete for group: {args.group}")
        print(f"  Users: {len(members['users'])}  |  SPs: {len(members['service_principals'])}")
        print(f"  Catalog grants: {len(catalog_grants)}  |  Schema: {len(schema_grants)}  |  Table: {len(table_grants)}")
        full = sum(1 for r in redundancy if r.redundancy_level.value == "Full")
        partial = sum(1 for r in redundancy if r.redundancy_level.value == "Partial")
        print(f"  Redundancy: {full} full, {partial} partial")
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
