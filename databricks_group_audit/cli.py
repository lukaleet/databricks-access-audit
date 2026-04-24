"""CLI entry point for databricks-group-audit.

Usage:
    python -m databricks_group_audit \
        --client-id $SP_CLIENT_ID \
        --client-secret $SP_CLIENT_SECRET \
        --account-id $DATABRICKS_ACCOUNT_ID \
        --group "data-engineers" \
        --cloud azure
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

    # Target
    p.add_argument("--group", required=True, help="Display name of the group to audit")
    p.add_argument("--workspace-urls", default="",
                   help="Comma-separated workspace URLs (omit to scan all)")

    # Scan depth
    p.add_argument("--scan-schemas", action="store_true", help="Scan schema-level grants")
    p.add_argument("--scan-tables", action="store_true", help="Scan table/view-level grants")

    # Output
    p.add_argument("--output", choices=["json", "text"], default="text",
                   help="Output format (default: text)")
    p.add_argument("--revoke-script", action="store_true",
                   help="Print REVOKE SQL for redundant grants")

    # Retry tuning
    p.add_argument("--max-retries", type=int, default=5)
    p.add_argument("--retry-base-delay", type=float, default=1.0)
    p.add_argument("--retry-max-delay", type=float, default=60.0)

    return p.parse_args(argv)


def main(argv: List[str] | None = None) -> int:  # noqa: C901
    args = _parse_args(argv)

    if not args.client_id or not args.client_secret or not args.account_id:
        print("ERROR: --client-id, --client-secret, and --account-id are required.", file=sys.stderr)
        return 1

    # Lazy imports so --help is fast
    from databricks_group_audit.client import DatabricksAPIClient
    from databricks_group_audit.group_resolver import GroupMembershipResolver
    from databricks_group_audit.workspace import WorkspaceDiscovery
    from databricks_group_audit.catalog_scanner import CatalogPermissionScanner
    from databricks_group_audit.schema_scanner import SchemaPermissionScanner
    from databricks_group_audit.table_scanner import TablePermissionScanner
    from databricks_group_audit.redundancy import RedundancyDetector
    from databricks_group_audit.revoke import RevokeScriptGenerator
    from databricks_group_audit.models import GrantSource

    client = DatabricksAPIClient.for_cloud(
        cloud=args.cloud,
        client_id=args.client_id,
        client_secret=args.client_secret,
        account_id=args.account_id,
        max_retries=args.max_retries,
        base_delay=args.retry_base_delay,
        max_delay=args.retry_max_delay,
    )

    # Step 1: Resolve group
    resolver = GroupMembershipResolver(client)
    print(f"Resolving group: {args.group} ...")
    group_node = resolver.resolve_group(args.group)
    if not group_node:
        print(f"ERROR: Group '{args.group}' not found.", file=sys.stderr)
        return 1
    members = resolver.get_all_members_flat(group_node)
    print(f"  Found {len(members['users'])} users, {len(members['service_principals'])} SPs")

    # Step 2: Discover workspaces
    ws_disc = WorkspaceDiscovery(client, cloud_provider=args.cloud)
    workspaces = ws_disc.discover(args.workspace_urls)
    print(f"  Scanning {len(workspaces)} workspace(s)")

    # Step 3: Catalog scan
    cat_scanner = CatalogPermissionScanner(client, resolver)
    catalog_grants = cat_scanner.scan_all_workspaces(workspaces, args.group, group_node, members)
    print(f"  Found {len(catalog_grants)} catalog grant(s)")

    # Step 4: Schema scan
    schema_grants = []
    if args.scan_schemas or args.scan_tables:
        sch_scanner = SchemaPermissionScanner(client)
        upstream = cat_scanner.get_groups_containing_target(args.group)
        accessible = {(g.catalog_name, g.workspace_url) for g in catalog_grants
                      if g.grant_source in (GrantSource.DIRECT, GrantSource.UPSTREAM)}
        from databricks_group_audit.models import WorkspaceInfo
        for cat_name, ws_url in accessible:
            ws = WorkspaceInfo("scan", "", "", ws_url, args.cloud.upper(), "")
            schema_grants.extend(sch_scanner.scan_schemas(ws, cat_name, args.group, members, upstream))
        print(f"  Found {len(schema_grants)} schema grant(s)")

    # Step 4b: Table scan
    table_grants = []
    if args.scan_tables:
        tbl_scanner = TablePermissionScanner(client)
        for cat_name, ws_url in accessible:
            ws = WorkspaceInfo("scan", "", "", ws_url, args.cloud.upper(), "")
            for sch in sch_scanner._get_schemas(ws, cat_name):
                sname = sch.get("name", "")
                table_grants.extend(tbl_scanner.scan_tables(ws, cat_name, sname, args.group, members, upstream))
        print(f"  Found {len(table_grants)} table grant(s)")

    # Step 5: Redundancy
    detector = RedundancyDetector()
    redundancy = detector.detect_redundancy(catalog_grants, args.group)

    # Output
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
