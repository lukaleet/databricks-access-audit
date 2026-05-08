"""CLI entry point for databricks-access-audit.

Usage (group audit)::

    databricks-access-audit --group "data-engineers" --cloud azure

Usage (principal audit)::

    databricks-access-audit --principal "alice@example.com" --cloud azure

Usage (force raw HTTP instead of SDK)::

    databricks-access-audit --group "data-engineers" --no-sdk
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List

log = logging.getLogger(__name__)


def _parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="databricks-access-audit",
        description="Audit Databricks group membership and Unity Catalog permissions.",
    )
    # Credentials
    p.add_argument("--client-id", default=os.getenv("DATABRICKS_CLIENT_ID", ""),
                   help="Service principal client ID (env: DATABRICKS_CLIENT_ID)")
    p.add_argument("--client-secret", default=os.getenv("DATABRICKS_CLIENT_SECRET", ""),
                   help="Service principal secret (env: DATABRICKS_CLIENT_SECRET)")
    p.add_argument("--account-id", default=os.getenv("DATABRICKS_ACCOUNT_ID", ""),
                   help="Databricks account ID (env: DATABRICKS_ACCOUNT_ID)")
    p.add_argument("--cloud", choices=["azure", "aws", "gcp"], default=None,
                   help="Cloud provider (default: azure, or auto-detected from --profile host)")
    p.add_argument(
        "--profile",
        default=os.getenv("DATABRICKS_CONFIG_PROFILE", "DEFAULT"),
        metavar="NAME",
        help=(
            "~/.databrickscfg profile to use when credentials are not supplied "
            "via flags or env vars (env: DATABRICKS_CONFIG_PROFILE, default: DEFAULT)"
        ),
    )

    # Target (mutually exclusive: --group OR --principal OR --compare OR --clone-from)
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--group", help="Display name of the group to audit")
    target.add_argument("--principal",
                        help="User email, SP app-ID/name, or group name for principal audit")
    target.add_argument(
        "--compare",
        nargs=2,
        metavar=("PRINCIPAL_A", "PRINCIPAL_B"),
        help="Compare group memberships of two principals side-by-side",
    )
    target.add_argument(
        "--clone-from",
        metavar="SOURCE",
        help="Build a provisioning report to replicate SOURCE's group access",
    )
    target.add_argument(
        "--resource",
        metavar="NAME",
        help=(
            "Show who has access to a resource: catalog, schema (cat.schema), "
            "table (cat.schema.tbl), or workspace (by name or URL). "
            "Type is auto-detected from the name format."
        ),
    )

    p.add_argument("--workspace-urls", default="",
                   help="Comma-separated workspace URLs (omit to scan all)")

    # Scan depth
    p.add_argument("--scan-schemas", action="store_true", help="Scan schema-level grants")
    p.add_argument("--scan-tables", action="store_true", help="Scan table/view-level grants")

    # Output
    p.add_argument("--output", choices=["json", "text", "csv", "html"], default="text",
                   help="Output format (default: text). 'html' generates a self-contained "
                        "Mermaid access-graph page (principal audit only).")
    p.add_argument("--tree", action="store_true",
                   help="Render --principal text output as a tree grouped by granting group "
                        "instead of by securable type. Ignored for --output json/csv/html.")
    p.add_argument("--revoke-script", action="store_true",
                   help="Print REVOKE SQL for redundant grants (group audit only)")

    # Snapshot / diff
    p.add_argument(
        "--save-snapshot",
        metavar="PATH",
        default="",
        help=(
            "Save a timestamped JSON snapshot of this audit run to PATH.  "
            "Use with --baseline to track permission drift over time."
        ),
    )
    p.add_argument(
        "--baseline",
        metavar="PATH",
        default="",
        help=(
            "Compare this run against a previous snapshot at PATH and print "
            "what changed: new grants, removed grants, new/removed members.  "
            "Compatible with all --output formats."
        ),
    )

    # Client selection
    p.add_argument("--no-sdk", action="store_true",
                   help="Force the raw HTTP client even when databricks-sdk is installed")

    p.add_argument(
        "--workers",
        type=int,
        default=8,
        metavar="N",
        help=(
            "Number of parallel threads used to scan workspaces, schemas, and tables "
            "(default: 8).  Set to 1 to scan sequentially."
        ),
    )

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

    # Workspace object ACL scanning (both modes)
    p.add_argument(
        "--scan-workspace-objects",
        action="store_true",
        help=(
            "Scan workspace-level object permissions: jobs, clusters, SQL warehouses, "
            "pipelines, and cluster policies.  Off by default — adds significant API "
            "calls per workspace."
        ),
    )
    p.add_argument(
        "--workspace-object-types",
        default="",
        metavar="LIST",
        help=(
            "Comma-separated object types to scan when --scan-workspace-objects is set.  "
            "Valid values: jobs, clusters, cluster_policies, pipelines, sql_warehouses, "
            "sql_queries, sql_alerts, lakeview_dashboards, genie_spaces, "
            "mlflow_experiments, registered_models, serving_endpoints, apps.  "
            "Default: all 13 types."
        ),
    )

    p.add_argument(
        "--resource-type",
        choices=["catalog", "schema", "table", "workspace"],
        default=None,
        help=(
            "Override auto-detected resource type for --resource. "
            "Use when the name is ambiguous (e.g. a workspace whose name "
            "doesn't contain 'databricks')."
        ),
    )
    p.add_argument(
        "--no-expand-groups",
        action="store_true",
        help="For --resource: show only direct grants without expanding group members.",
    )

    p.add_argument(
        "--to",
        metavar="TARGET",
        default="",
        help="Target principal for --clone-from (required when using --clone-from)",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Apply Databricks-managed group changes from --clone-from.  "
            "Without this flag the report is a dry run.  IdP-managed groups "
            "are never touched — those must be handled in your identity provider."
        ),
    )
    p.add_argument(
        "--scan-uc",
        action="store_true",
        help=(
            "For --clone-from: scan Unity Catalog grants to classify groups with "
            "no workspace assignment as UC-only (clone-able) or dead-end (skip).  "
            "Adds catalog-scan API calls — may be slow with many workspaces."
        ),
    )

    return p.parse_args(argv)


def _resolve_credentials(args: argparse.Namespace) -> None:
    """Fill missing credentials from ~/.databrickscfg profile. Mutates args in place.

    Priority: explicit flags / env vars → named profile → cloud auto-detection.
    """
    from databricks_access_audit.config import cloud_from_host, load_profile

    if not (args.client_id and args.client_secret and args.account_id):
        profile = load_profile(args.profile)
        args.client_id = args.client_id or profile.get("client_id", "")
        args.client_secret = args.client_secret or profile.get("client_secret", "")
        args.account_id = args.account_id or profile.get("account_id", "")

        if args.cloud is None and "host" in profile:
            args.cloud = cloud_from_host(profile["host"])

    if args.cloud is None:
        args.cloud = "azure"


def _build_client(args: argparse.Namespace) -> Any:
    """Create the API client using the factory."""
    from databricks_access_audit.client import create_client

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

    from databricks_access_audit.elevate import PermissionElevator

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

    try:
        for ws in workspaces:
            elevator.ensure_workspace_admin(ws.workspace_id, ws.workspace_name)
    except Exception:
        # Ensure already-elevated workspaces are revoked even if the loop
        # fails mid-way (e.g. a network error on the second workspace).
        elevator.__exit__(*sys.exc_info())
        raise

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

    from databricks_access_audit.stale_checker import StaleGrantChecker

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

    from databricks_access_audit.local_groups import LocalGroupChecker

    print("  Checking for workspace-local groups ...")
    checker = LocalGroupChecker(client)
    return checker.check_all_workspaces(workspaces)


def _print_diff(diff: Any, output_format: str) -> None:
    """Print an AuditDiff in the requested format."""
    if output_format == "html":
        from databricks_access_audit._diff_html_renderer import render_diff_html
        print(render_diff_html(diff))
        return

    if output_format == "csv":
        from databricks_access_audit.csv_output import write_diff_csv
        write_diff_csv(diff)
        return

    if output_format == "json":
        out: Dict[str, Any] = {
            "mode": diff.mode,
            "target": diff.target,
            "baseline_timestamp": diff.baseline_timestamp,
            "current_timestamp": diff.current_timestamp,
            "has_changes": diff.has_changes,
            "grants_added": diff.grants_added,
            "grants_removed": diff.grants_removed,
            "members_added": diff.members_added,
            "members_removed": diff.members_removed,
        }
        print(json.dumps(out, indent=2))
        return

    # Text
    member_label = "Members" if diff.mode == "group" else "Group memberships"
    print(f"\n{'='*60}")
    print(f"  Diff: {diff.target} ({diff.mode})")
    print(f"  Baseline:  {diff.baseline_timestamp}")
    print(f"  Current:   {diff.current_timestamp}")
    print(f"{'='*60}")

    if not diff.has_changes:
        print("  No changes detected.")
        print(f"{'='*60}")
        return

    if diff.grants_added:
        print(f"\n  Grants added ({len(diff.grants_added)}):")
        for g in diff.grants_added:
            print(f"    + [{g.get('securable_type', '')}] {g.get('securable_name', '')} "
                  f"- {g.get('principal', g.get('via_group', ''))} "
                  f"({', '.join(g.get('privileges', []))})")
    if diff.grants_removed:
        print(f"\n  Grants removed ({len(diff.grants_removed)}):")
        for g in diff.grants_removed:
            print(f"    - [{g.get('securable_type', '')}] {g.get('securable_name', '')} "
                  f"- {g.get('principal', g.get('via_group', ''))} "
                  f"({', '.join(g.get('privileges', []))})")
    if diff.members_added:
        print(f"\n  {member_label} added ({len(diff.members_added)}):")
        for m in diff.members_added:
            name = m.get("display_name", m.get("group_name", ""))
            mtype = m.get("type", "GROUP")
            print(f"    + {name} ({mtype})")
    if diff.members_removed:
        print(f"\n  {member_label} removed ({len(diff.members_removed)}):")
        for m in diff.members_removed:
            name = m.get("display_name", m.get("group_name", ""))
            mtype = m.get("type", "GROUP")
            print(f"    - {name} ({mtype})")

    print(f"\n{'='*60}")


def _run_principal_audit(args: argparse.Namespace) -> int:
    """Run the principal-centric audit."""
    from databricks_access_audit.escalation import detect_escalations
    from databricks_access_audit.principal_auditor import PrincipalAuditor
    from databricks_access_audit.workspace import WorkspaceDiscovery

    client = _build_client(args)
    _log = (
        print if args.output == "text"
        else (lambda *a, **kw: print(*a, **{**kw, "file": sys.stderr}))
    )
    ws_disc = WorkspaceDiscovery(client, cloud_provider=args.cloud)
    auditor = PrincipalAuditor(client, workspace_discovery=ws_disc, cloud_provider=args.cloud)

    # Discover workspaces up-front so we can elevate before scanning.
    workspaces = ws_disc.discover(args.workspace_urls)

    obj_types = (
        [t.strip() for t in args.workspace_object_types.split(",") if t.strip()]
        if args.workspace_object_types else None
    )

    _log(f"Auditing principal: {args.principal} ...")
    try:
        with _elevation_context(args, client, workspaces):
            result = auditor.audit(
                identifier=args.principal,
                explicit_workspace_urls=args.workspace_urls,
                scan_schemas=args.scan_schemas,
                scan_tables=args.scan_tables,
                scan_workspace_objects=args.scan_workspace_objects,
                workspace_object_types=obj_types,
                max_workers=args.workers,
            )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Optional: privilege escalation check
    if args.escalation_check:
        result.escalation_findings = detect_escalations(result)
        _log(f"  Escalation check: {len(result.escalation_findings)} finding(s)")

    # Optional: workspace-local group check
    local_findings = _run_local_group_check(args, client, workspaces)

    # Optional: save snapshot
    if args.save_snapshot:
        from databricks_access_audit.snapshot import build_principal_snapshot, save_snapshot
        snap = build_principal_snapshot(result)
        save_snapshot(snap, args.save_snapshot)
        _log(f"  Snapshot saved to: {args.save_snapshot}")

    # Optional: diff against baseline
    if args.baseline:
        from databricks_access_audit.snapshot import (
            build_principal_snapshot,
            diff_snapshots,
            load_snapshot,
        )
        baseline = load_snapshot(args.baseline)
        current_snap = build_principal_snapshot(result)
        try:
            diff = diff_snapshots(baseline, current_snap)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        _print_diff(diff, args.output)
        return 0

    obj_grants = result.workspace_object_grants if args.scan_workspace_objects else []

    if args.output == "html":
        from databricks_access_audit._html_renderer import render_html
        print(render_html(
            result,
            obj_grants,
            show_escalations=args.escalation_check,
            show_workspace_objects=args.scan_workspace_objects,
        ))
        return 0

    if args.output == "csv":
        from databricks_access_audit.csv_output import write_principal_audit_csv
        write_principal_audit_csv(result, result.escalation_findings)
        return 0

    if args.output == "json":
        out: Dict[str, Any] = {
            "principal": result.principal_name,
            "principal_type": result.principal_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "groups": [{
                "name": g.group_name, "direct": g.is_direct, "path": g.path,
                "source": g.source.value,
            } for g in result.groups],
            "workspace_roles": [{
                "workspace": r.workspace_name, "permission": r.permission_level,
                "via_group": r.via_group, "via_path": r.via_path,
            } for r in result.workspace_roles],
            "permissions": [{
                "type": p.securable_type, "name": p.securable_name,
                "privileges": p.privileges, "via_group": p.via_group,
                "via_path": p.via_path, "workspace": p.workspace_name,
            } for p in result.permissions],
            "dead_end_groups": result.dead_end_groups,
            "uc_only_groups": result.uc_only_groups,
            "principal_source": result.principal_source.value,
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
        if args.scan_workspace_objects:
            out["workspace_object_permissions"] = [{
                "object_type": g.object_type,
                "object_id": g.object_id,
                "object_name": g.object_name,
                "permission_level": g.permission_level,
                "principal": g.principal,
                "grant_source": g.grant_source.value,
                "inherited_from": g.inherited_from,
                "workspace": g.workspace_name,
            } for g in result.workspace_object_grants]
        if args.check_local_groups:
            out["local_group_findings"] = [{
                "group_name": f.group_name,
                "workspace": f.workspace_name,
                "member_count": f.member_count,
            } for f in local_findings]
        print(json.dumps(out, indent=2))
    elif getattr(args, "tree", False):
        from databricks_access_audit._tree_renderer import render_principal_tree
        render_principal_tree(
            result,
            obj_grants,
            show_escalations=args.escalation_check,
            show_workspace_objects=args.scan_workspace_objects,
        )
    else:
        p_src = result.principal_source.value
        ext_groups = sum(1 for g in result.groups if g.external_id)
        int_groups = len(result.groups) - ext_groups

        print(f"\n{'='*60}")
        print(f"  Principal: {result.principal_name} ({result.principal_type}, {p_src})")
        print(f"{'='*60}")

        print(f"\n  Group memberships ({len(result.groups)}, "
              f"{ext_groups} IdP-synced, {int_groups} Databricks-managed):")
        for g in result.groups:
            tag = "direct" if g.is_direct else "transitive"
            src_tag = g.source.value
            print(f"    {'*' if g.is_direct else '-'} {g.group_name} ({tag}, {src_tag})")
            print(f"      path: {' -> '.join(g.path)}")

        print(f"\n  Workspace access ({len(result.workspace_roles)}):")
        for r in result.workspace_roles:
            if r.via_path:
                print(f"    * {r.workspace_name}: {r.permission_level}"
                      f"  [{' → '.join(r.via_path)}]")
            else:
                print(f"    * {r.workspace_name}: {r.permission_level} (direct)")

        if result.uc_only_groups:
            print(f"\n  UC-only groups ({len(result.uc_only_groups)}):")
            print("    (no workspace assignment — access via Unity Catalog grants only)")
            for dg in result.uc_only_groups:
                print(f"    - {dg}")

        if result.dead_end_groups:
            print(f"\n  Unused groups ({len(result.dead_end_groups)}):")
            print("    (no workspace assignment and no UC grants — may be safe to remove)")
            for dg in result.dead_end_groups:
                print(f"    - {dg}")

        print(f"\n  UC permissions ({len(result.permissions)}):")
        for p in result.permissions:
            if p.via_path:
                path_str = " → ".join(p.via_path)
                print(f"    * [{p.securable_type}] {p.securable_name}"
                      f"  {', '.join(p.privileges)}"
                      f"  [{path_str}]  @ {p.workspace_name}")
            else:
                print(f"    * [{p.securable_type}] {p.securable_name}"
                      f"  {', '.join(p.privileges)}  (direct) @ {p.workspace_name}")

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

        if args.scan_workspace_objects:
            print(f"\n  Workspace object permissions ({len(obj_grants)}):")
            if obj_grants:
                for g in obj_grants:
                    via = f"via {g.inherited_from}" if g.inherited_from else "direct"
                    print(f"    * [{g.object_type}] {g.object_name or g.object_id}"
                          f"  {g.permission_level}  ({via}) @ {g.workspace_name}")
            else:
                print("    No workspace object permissions found.")
            print("    Note: remediation requires the Databricks permissions REST API,"
                  " not SQL.")

        if args.check_local_groups:
            print(f"\n  Workspace-local groups ({len(local_findings)}):")
            for f in local_findings:
                print(f"    ! {f.group_name} in '{f.workspace_name}' "
                      f"({f.member_count} member(s)) — not in account SCIM")

        print(f"\n{'='*60}")

    return 0


def _run_compare(args: argparse.Namespace) -> int:
    """Run principal comparison."""
    from databricks_access_audit.principal_comparer import PrincipalComparer
    client = _build_client(args)
    _log = (
        print if args.output == "text"
        else (lambda *a, **kw: print(*a, **{**kw, "file": sys.stderr}))
    )
    identifier_a, identifier_b = args.compare
    _log(f"Comparing: {identifier_a} vs {identifier_b} ...")
    comparer = PrincipalComparer(client, cloud_provider=args.cloud)
    try:
        result = comparer.compare(identifier_a, identifier_b)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.output == "csv":
        from databricks_access_audit.csv_output import write_compare_csv
        write_compare_csv(result)
        return 0

    if args.output == "json":
        def _gc(gc):
            return {
                "group_id": gc.group_id,
                "group_name": gc.group_name,
                "source": gc.source.value,
                "in_a": gc.in_a,
                "in_b": gc.in_b,
                "is_direct_in_a": gc.is_direct_in_a,
                "is_direct_in_b": gc.is_direct_in_b,
                "path_in_a": gc.path_in_a,
                "path_in_b": gc.path_in_b,
            }
        out = {
            "principal_a": result.principal_a,
            "principal_b": result.principal_b,
            "display_name_a": result.display_name_a,
            "display_name_b": result.display_name_b,
            "only_in_a": [_gc(g) for g in result.only_in_a],
            "only_in_b": [_gc(g) for g in result.only_in_b],
            "in_both": [_gc(g) for g in result.in_both],
        }
        print(json.dumps(out, indent=2))
        return 0

    # Text output
    na, nb = result.display_name_a, result.display_name_b
    print(f"\n{'='*60}")
    print(f"  Comparison: {na}  vs  {nb}")
    print(f"{'='*60}")

    def _fmt_group(gc, side: str) -> str:
        path = gc.path_in_a if side == "a" else gc.path_in_b
        is_direct = gc.is_direct_in_a if side == "a" else gc.is_direct_in_b
        tag = "direct" if is_direct else "transitive"
        src = gc.source.value
        path_str = " → ".join(path) if path else "?"
        return f"    {gc.group_name} ({tag}, {src})\n      path: {path_str}"

    if result.only_in_a:
        print(f"\n  Groups {na} has that {nb} does not ({len(result.only_in_a)}):")
        for gc in result.only_in_a:
            print(_fmt_group(gc, "a"))
    else:
        print(f"\n  {na} has no groups that {nb} is missing.")

    if result.only_in_b:
        print(f"\n  Groups {nb} has that {na} does not ({len(result.only_in_b)}):")
        for gc in result.only_in_b:
            print(_fmt_group(gc, "b"))
    else:
        print(f"\n  {nb} has no groups that {na} is missing.")

    if result.in_both:
        print(f"\n  Groups both belong to ({len(result.in_both)}):")
        for gc in result.in_both:
            a_tag = "direct" if gc.is_direct_in_a else "transitive"
            b_tag = "direct" if gc.is_direct_in_b else "transitive"
            src = gc.source.value
            print(f"    {gc.group_name} ({src})  [{na}: {a_tag}  |  {nb}: {b_tag}]")

    print(f"\n{'='*60}")
    return 0


def _run_clone(args: argparse.Namespace) -> int:
    """Run access clone / provisioning report."""
    if not args.to:
        print("ERROR: --clone-from requires --to <target_principal>.", file=sys.stderr)
        return 1

    from databricks_access_audit.access_cloner import AccessCloner
    client = _build_client(args)
    _log = (
        print if args.output == "text"
        else (lambda *a, **kw: print(*a, **{**kw, "file": sys.stderr}))
    )
    _log(f"Building clone report: {args.clone_from} → {args.to} ...")
    if args.apply:
        _log("  --apply is set: Databricks-managed group memberships will be written.")
    if args.scan_uc:
        _log("  --scan-uc is set: scanning Unity Catalog grants for unverified groups ...")

    cloner = AccessCloner(client, cloud_provider=args.cloud)
    try:
        report = cloner.build_report(
            source=args.clone_from,
            target=args.to,
            scan_uc=args.scan_uc,
            explicit_workspace_urls=args.workspace_urls,
            max_workers=args.workers,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Apply Databricks-side changes if requested
    if args.apply and report.databricks_actions:
        # Re-resolve target to get their SCIM ID
        from databricks_access_audit.principal_auditor import PrincipalAuditor
        auditor = PrincipalAuditor(client, cloud_provider=args.cloud)
        try:
            _, target_id, _, _, _ = auditor.find_principal(args.to)
        except ValueError as exc:
            print(f"ERROR resolving target for apply: {exc}", file=sys.stderr)
            return 1
        _log(f"  Applying {len(report.databricks_actions)} Databricks group addition(s) ...")
        cloner.apply(report, target_id)

    if args.output == "csv":
        from databricks_access_audit.csv_output import write_clone_report_csv
        write_clone_report_csv(report)
        return 0

    if args.output == "json":
        def _action_dict(a):
            return {
                "action_type": a.action_type.value,
                "group_id": a.group_id,
                "group_name": a.group_name,
                "source": a.source.value,
                "path": a.path,
                "workspace_accesses": a.workspace_accesses,
                "uc_grants_summary": a.uc_grants_summary,
                "applied": a.applied,
                "error": a.error,
            }
        out = {
            "source_principal": report.source_principal,
            "target_principal": report.target_principal,
            "source_display_name": report.source_display_name,
            "target_display_name": report.target_display_name,
            "idp_required": [_action_dict(a) for a in report.idp_actions],
            "databricks": [_action_dict(a) for a in report.databricks_actions],
            "unverified": [_action_dict(a) for a in report.unverified_actions],
            "skipped": [_action_dict(a) for a in report.skipped],
        }
        print(json.dumps(out, indent=2))
        return 0

    # Text output
    src_name = report.source_display_name
    tgt_name = report.target_display_name
    print(f"\n{'='*60}")
    print("  Access provisioning report")
    print(f"  Source: {src_name} ({report.source_principal})")
    print(f"  Target: {tgt_name} ({report.target_principal})")
    print(f"{'='*60}")

    if report.idp_actions:
        print(f"\n  Actions required in your identity provider ({len(report.idp_actions)}):")
        print("  (Cannot be done from Databricks — add target in Entra ID / Okta / etc.)")
        for a in report.idp_actions:
            path_str = " → ".join(a.path) if a.path else a.group_name
            ws_str = (
                f"  [workspaces: {', '.join(a.workspace_accesses)}]"
                if a.workspace_accesses else ""
            )
            print(f"    ! {a.group_name} (IdP-synced){ws_str}")
            print(f"      path: {path_str}")

    if report.databricks_actions:
        applied_count = sum(1 for a in report.databricks_actions if a.applied)
        label = (
            f"Applied ({applied_count}/{len(report.databricks_actions)})"
            if args.apply
            else f"Actions in Databricks ({len(report.databricks_actions)})"
        )
        print(f"\n  {label}:")
        for a in report.databricks_actions:
            ws_str = (
                f"  [workspaces: {', '.join(a.workspace_accesses)}]"
                if a.workspace_accesses else ""
            )
            uc_str = f"  [{a.uc_grants_summary}]" if a.uc_grants_summary else ""
            status = ""
            if args.apply:
                if a.applied:
                    status = "  applied"
                elif a.error:
                    status = f"  ERROR: {a.error}"
            print(f"    + {a.group_name} (Databricks-managed){ws_str}{uc_str}{status}")
            path_str = " → ".join(a.path) if a.path else a.group_name
            print(f"      path: {path_str}")

    if report.unverified_actions:
        n = len(report.unverified_actions)
        print(f"\n  Unverified — no workspace assignment, UC not scanned ({n}):")
        print("  (Databricks-managed; run with --scan-uc to classify as UC-only or dead-end)")
        for a in report.unverified_actions:
            path_str = " → ".join(a.path) if a.path else a.group_name
            print(f"    ? {a.group_name} (Databricks-managed)")
            print(f"      path: {path_str}")

    if report.skipped:
        print(f"\n  Skipped — verified dead-end, no effective grants ({len(report.skipped)}):")
        for a in report.skipped:
            print(f"    - {a.group_name} (Databricks-managed, no grants detected)")

    if not args.apply and report.databricks_actions:
        print(
            f"\n  Dry run — pass --apply to write the {len(report.databricks_actions)}"
            f" Databricks group addition(s)."
        )

    print(f"\n{'='*60}")
    return 0


def _run_group_audit(args: argparse.Namespace) -> int:
    """Run the group-centric audit (original behavior)."""
    from databricks_access_audit.catalog_scanner import CatalogPermissionScanner
    from databricks_access_audit.group_resolver import GroupMembershipResolver
    from databricks_access_audit.models import GrantSource, WorkspaceInfo
    from databricks_access_audit.redundancy import RedundancyDetector
    from databricks_access_audit.revoke import RevokeScriptGenerator
    from databricks_access_audit.schema_scanner import SchemaPermissionScanner
    from databricks_access_audit.table_scanner import TablePermissionScanner
    from databricks_access_audit.workspace import WorkspaceDiscovery

    client = _build_client(args)
    _log = (
        print if args.output == "text"
        else (lambda *a, **kw: print(*a, **{**kw, "file": sys.stderr}))
    )

    resolver = GroupMembershipResolver(client)
    _log(f"Resolving group: {args.group} ...")
    group_node = resolver.resolve_group(args.group)
    if not group_node:
        print(f"ERROR: Group '{args.group}' not found.", file=sys.stderr)
        return 1
    members = resolver.get_all_members_flat(group_node)
    _log(f"  Found {len(members['users'])} users, {len(members['service_principals'])} SPs")

    ws_disc = WorkspaceDiscovery(client, cloud_provider=args.cloud)
    workspaces = ws_disc.discover(args.workspace_urls)
    _log(f"  Scanning {len(workspaces)} workspace(s)")

    cat_scanner = CatalogPermissionScanner(client, resolver)

    schema_grants: List = []
    table_grants: List = []
    workspace_object_grants: List = []

    obj_types = (
        [t.strip() for t in args.workspace_object_types.split(",") if t.strip()]
        if args.workspace_object_types else None
    )

    with _elevation_context(args, client, workspaces):
        catalog_grants = cat_scanner.scan_all_workspaces(
            workspaces, args.group, group_node, members, max_workers=args.workers
        )
        _log(f"  Found {len(catalog_grants)} catalog grant(s)")

        if args.scan_schemas or args.scan_tables:
            sch_scanner = SchemaPermissionScanner(client)
            upstream = cat_scanner.get_groups_containing_target(args.group)
            accessible = sorted({
                (g.catalog_name, g.workspace_url) for g in catalog_grants
                if g.grant_source in (GrantSource.DIRECT, GrantSource.UPSTREAM)
            })
            # Map workspace URL → name so schema/table grants carry the correct
            # workspace_name (the stub WorkspaceInfo has no name otherwise).
            url_to_ws_name = {ws.workspace_url: ws.workspace_name for ws in workspaces}
            workers = max(1, min(args.workers, len(accessible)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                sch_futures = {
                    pool.submit(
                        sch_scanner.scan_schemas,
                        WorkspaceInfo("scan", "", url_to_ws_name.get(ws_url, ""),
                                      ws_url, args.cloud.upper(), ""),
                        cat_name, args.group, members, upstream,
                    ): (cat_name, ws_url)
                    for cat_name, ws_url in accessible
                }
                for fut in as_completed(sch_futures):
                    cat_name, ws_url = sch_futures[fut]
                    try:
                        schema_grants.extend(fut.result())
                    except Exception as exc:
                        log.warning("Schema scan failed for %s on %s: %s", cat_name, ws_url, exc)
            _log(f"  Found {len(schema_grants)} schema grant(s)")

            if args.scan_tables:
                tbl_scanner = TablePermissionScanner(client)
                # Collect (catalog, workspace_url, schema) triples first, then fan out.
                triples = []
                for cat_name, ws_url in accessible:
                    ws = WorkspaceInfo("scan", "", url_to_ws_name.get(ws_url, ""),
                                       ws_url, args.cloud.upper(), "")
                    for sch in sch_scanner.get_schemas(ws, cat_name):
                        sname = sch.get("name", "")
                        if sname:
                            triples.append((cat_name, ws_url, sname))
                tbl_workers = max(1, min(args.workers, len(triples)))
                with ThreadPoolExecutor(max_workers=tbl_workers) as pool:
                    tbl_futures = {
                        pool.submit(
                            tbl_scanner.scan_tables,
                            WorkspaceInfo("scan", "", url_to_ws_name.get(ws_url, ""),
                                          ws_url, args.cloud.upper(), ""),
                            cat_name, sname, args.group, members, upstream,
                        ): (cat_name, sname)
                        for cat_name, ws_url, sname in triples
                    }
                    for fut in as_completed(tbl_futures):
                        cat_name, sname = tbl_futures[fut]
                        try:
                            table_grants.extend(fut.result())
                        except Exception as exc:
                            log.warning("Table scan failed for %s.%s: %s", cat_name, sname, exc)
                _log(f"  Found {len(table_grants)} table grant(s)")

        if args.scan_workspace_objects:
            from databricks_access_audit.workspace_object_scanner import WorkspaceObjectScanner
            obj_scanner = WorkspaceObjectScanner(client, resolver)
            workspace_object_grants = obj_scanner.scan_all_workspaces(
                workspaces, args.group, group_node, members,
                object_types=obj_types, max_workers=args.workers,
            )
            _log(f"  Found {len(workspace_object_grants)} workspace object grant(s)")

    detector = RedundancyDetector()
    redundancy = detector.detect_redundancy(catalog_grants, args.group)

    # Rank members by number of personal (member-direct) catalog grants.
    from collections import Counter
    _grant_counts = Counter(
        g.principal for g in catalog_grants if g.grant_source == GrantSource.MEMBER_DIRECT
    )
    _redundancy_by_principal = {r.principal: r.redundancy_level.value for r in redundancy}
    top_members = [
        {
            "principal": principal,
            "personal_grants": count,
            "redundancy": _redundancy_by_principal.get(principal, "None"),
        }
        for principal, count in _grant_counts.most_common()
    ]

    # Optional: stale grant detection
    stale_findings = _run_stale_check(
        args, client, catalog_grants, workspaces,
        workspace_name=workspaces[0].workspace_name if workspaces else "",
    )

    # Optional: workspace-local group check
    local_findings = _run_local_group_check(args, client, workspaces)

    # Optional: save snapshot
    if args.save_snapshot:
        from databricks_access_audit.snapshot import build_group_snapshot, save_snapshot
        snap = build_group_snapshot(
            args.group, members, catalog_grants, schema_grants, table_grants,
            workspace_object_grants or None,
        )
        save_snapshot(snap, args.save_snapshot)
        _log(f"  Snapshot saved to: {args.save_snapshot}")

    # Optional: diff against baseline
    if args.baseline:
        from databricks_access_audit.snapshot import (
            build_group_snapshot,
            diff_snapshots,
            load_snapshot,
        )
        baseline = load_snapshot(args.baseline)
        current_snap = build_group_snapshot(
            args.group, members, catalog_grants, schema_grants, table_grants,
            workspace_object_grants or None,
        )
        try:
            diff = diff_snapshots(baseline, current_snap)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        _print_diff(diff, args.output)
        return 0

    ext_users = sum(1 for u in members["users"] if u.external_id)
    ext_sps = sum(1 for sp in members["service_principals"] if sp.external_id)

    if args.output == "html":
        from databricks_access_audit._group_html_renderer import render_group_html
        print(render_group_html(
            args.group, group_node, members,
            catalog_grants, schema_grants, table_grants,
            workspace_object_grants or [],
            redundancy,
            show_workspace_objects=args.scan_workspace_objects,
        ))
    elif getattr(args, "tree", False):
        from databricks_access_audit._group_tree_renderer import render_group_tree
        render_group_tree(
            args.group, group_node, members,
            catalog_grants, schema_grants, table_grants,
            workspace_object_grants or [],
            redundancy,
            show_workspace_objects=args.scan_workspace_objects,
        )
    elif args.output == "csv":
        from databricks_access_audit.csv_output import write_group_audit_csv
        write_group_audit_csv(catalog_grants, schema_grants, table_grants, redundancy,
                              workspace_object_grants or None)
    elif args.output == "json":
        result: Dict[str, Any] = {
            "group": args.group,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "users": len(members["users"]),
            "users_external": ext_users,
            "users_internal": len(members["users"]) - ext_users,
            "service_principals": len(members["service_principals"]),
            "sps_external": ext_sps,
            "sps_internal": len(members["service_principals"]) - ext_sps,
            "catalog_grants": len(catalog_grants),
            "schema_grants": len(schema_grants),
            "table_grants": len(table_grants),
            "full_redundancy": sum(1 for r in redundancy if r.redundancy_level.value == "Full"),
            "partial_redundancy": sum(
                1 for r in redundancy if r.redundancy_level.value == "Partial"
            ),
            "top_members": top_members,
        }
        if args.stale_days:
            result["stale_findings"] = [{
                "principal": f.principal,
                "catalog": f.catalog_name,
                "privileges": f.privileges,
                "stale_days": f.stale_days,
                "workspace": f.workspace_name,
            } for f in stale_findings]
        if args.scan_workspace_objects:
            result["workspace_object_grants"] = [{
                "object_type": g.object_type,
                "object_id": g.object_id,
                "object_name": g.object_name,
                "permission_level": g.permission_level,
                "principal": g.principal,
                "principal_type": g.principal_type,
                "grant_source": g.grant_source.value,
                "inherited_from": g.inherited_from,
                "workspace": g.workspace_name,
            } for g in workspace_object_grants]
        if args.check_local_groups:
            result["local_group_findings"] = [{
                "group_name": f.group_name,
                "workspace": f.workspace_name,
                "member_count": f.member_count,
            } for f in local_findings]
        print(json.dumps(result, indent=2))
    else:
        int_users = len(members["users"]) - ext_users
        int_sps = len(members["service_principals"]) - ext_sps

        print(f"\n{'='*60}")
        print(f"  Audit complete for group: {args.group}")
        print(f"  Users: {len(members['users'])} "
              f"({ext_users} IdP-synced, {int_users} Databricks-managed)"
              f"  |  SPs: {len(members['service_principals'])} "
              f"({ext_sps} IdP-synced, {int_sps} Databricks-managed)")
        print(
            f"  Catalog grants: {len(catalog_grants)}"
            f"  |  Schema: {len(schema_grants)}  |  Table: {len(table_grants)}"
        )
        full = sum(1 for r in redundancy if r.redundancy_level.value == "Full")
        partial = sum(1 for r in redundancy if r.redundancy_level.value == "Partial")
        print(f"  Redundancy: {full} full, {partial} partial")

        if top_members:
            _shown = top_members[:5]
            print(f"\n  Top {len(_shown)} member(s) by personal grants:")
            for i, m in enumerate(_shown, 1):
                print(f"    {i}. {m['principal']}  —  {m['personal_grants']} grant(s)"
                      f"  [{m['redundancy']} redundancy]")

        if stale_findings:
            print(
                f"\n  Stale grants ({len(stale_findings)}, no activity in {args.stale_days} days):"
            )
            for f in stale_findings:
                print(f"    ! {f.principal}: {', '.join(f.privileges)} on {f.catalog_name}")

        if args.scan_workspace_objects:
            print(f"\n  Workspace object permissions ({len(workspace_object_grants)}):")
            for g in workspace_object_grants[:20]:
                via = f"via {g.inherited_from}" if g.inherited_from else "direct"
                print(f"    * [{g.object_type}] {g.object_name or g.object_id}"
                      f"  {g.permission_level}  ({via})"
                      f"  [{g.principal}] @ {g.workspace_name}")
            if len(workspace_object_grants) > 20:
                print(f"    ... {len(workspace_object_grants) - 20} more"
                      " (use --output json for full list)")
            print("    Note: remediation requires the Databricks permissions REST API,"
                  " not SQL.")

        if args.check_local_groups:
            print(f"\n  Workspace-local groups ({len(local_findings)}):")
            for f in local_findings:
                print(f"    ! {f.group_name} in '{f.workspace_name}' "
                      f"({f.member_count} member(s)) — not in account SCIM")

        print(f"{'='*60}")

    if args.revoke_script:
        print("\n" + RevokeScriptGenerator.generate(redundancy, include_partial=True))

    return 0


def _run_resource_audit(args: argparse.Namespace, client: Any) -> int:
    """Run the resource-centric audit."""
    from databricks_access_audit.resource_auditor import ResourceAuditor

    _log = (
        print if args.output == "text"
        else (lambda *a, **kw: print(*a, **{**kw, "file": sys.stderr}))
    )

    auditor = ResourceAuditor(client, args.account_id, args.cloud or "azure")
    _log(f"Auditing resource: {args.resource} ...")

    try:
        result = auditor.audit(
            args.resource,
            resource_type=getattr(args, "resource_type", None),
            expand_groups=not args.no_expand_groups,
            explicit_workspace_urls=args.workspace_urls,
            max_workers=args.workers,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    _log(f"  Found {len(result.grants)} grant(s)")

    if args.output == "html":
        from databricks_access_audit._resource_html_renderer import render_resource_html
        print(render_resource_html(result))
        return 0

    if args.output == "csv":
        from databricks_access_audit.csv_output import write_resource_audit_csv
        write_resource_audit_csv(result)
        return 0

    if args.output == "json":
        import json
        from datetime import datetime, timezone
        out: Dict[str, Any] = {
            "resource_type": result.resource_type,
            "resource_name": result.resource_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "grants": [
                {
                    "principal_name": g.principal_name,
                    "principal_type": g.principal_type,
                    "principal_source": g.principal_source.value,
                    "privileges": g.privileges,
                    "via_group": g.via_group,
                    "workspace_name": g.workspace_name,
                }
                for g in result.grants
            ],
        }
        print(json.dumps(out, indent=2))
        return 0

    # Text output
    direct_grants = [g for g in result.grants if g.via_group is None]
    via_grants = [g for g in result.grants if g.via_group is not None]

    print(f"\n{'='*60}")
    print(f"  Resource audit: {result.resource_name} ({result.resource_type})")
    print(f"{'='*60}")

    if direct_grants:
        print(f"\n  Direct grants ({len(direct_grants)}):")
        for g in direct_grants:
            src_tag = f"  [{g.principal_source.value}]" if g.principal_type == "GROUP" else ""
            privs = ", ".join(g.privileges)
            print(f"    {g.principal_type:<20} {g.principal_name:<40}{src_tag}  {privs}")
    else:
        print("\n  No direct grants found.")

    if via_grants:
        # Group by via_group
        by_group: Dict[str, List] = {}
        for g in via_grants:
            key = g.via_group or ""
            by_group.setdefault(key, []).append(g)

        print(f"\n  Via group ({len(via_grants)} individuals):")
        for group_name, members in sorted(by_group.items()):
            print(f"    {group_name} ({len(members)} member(s)):")
            for m in members[:10]:
                privs = ", ".join(m.privileges)
                print(f"      {m.principal_type:<7} {m.principal_name:<40}  {privs}")
            if len(members) > 10:
                print(f"      ... {len(members) - 10} more (use --output json for full list)")

    print(f"{'='*60}")
    return 0


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(argv)
    _resolve_credentials(args)

    if not args.client_id or not args.client_secret or not args.account_id:
        print(
            "ERROR: credentials are required.  Supply --client-id / --client-secret / "
            "--account-id (or set DATABRICKS_CLIENT_ID / DATABRICKS_CLIENT_SECRET / "
            "DATABRICKS_ACCOUNT_ID), or configure a ~/.databrickscfg profile and pass "
            "--profile NAME.",
            file=sys.stderr,
        )
        return 1

    if args.compare:
        return _run_compare(args)
    if args.clone_from:
        return _run_clone(args)
    if args.principal:
        return _run_principal_audit(args)
    if args.resource:
        client = _build_client(args)
        return _run_resource_audit(args, client)
    return _run_group_audit(args)
