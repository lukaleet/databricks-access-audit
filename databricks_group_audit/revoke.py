"""Generate copy-paste-ready REVOKE SQL from redundancy results."""

from __future__ import annotations

from datetime import datetime
from typing import List

from databricks_group_audit.models import RedundancyLevel, RedundancyResult


class RevokeScriptGenerator:
    """Generate REVOKE SQL statements for redundant grants."""

    @staticmethod
    def generate(
        redundancy_results: List[RedundancyResult],
        include_partial: bool = False,
    ) -> str:
        lines: List[str] = [
            f"-- {'=' * 66}",
            "-- AUTO-GENERATED REVOKE SCRIPT",
            f"-- Generated: {datetime.now().isoformat()}",
            "-- Review carefully before executing!",
            f"-- {'=' * 66}",
            "",
        ]

        full_count = 0
        partial_count = 0

        for r in redundancy_results:
            principal = r.principal
            if "@" in principal or " " in principal:
                principal = f"`{principal}`"

            if r.redundancy_level == RedundancyLevel.FULL:
                full_count += 1
                privs = ", ".join(r.member_privileges)
                lines.append(f"-- [FULL REDUNDANCY] {r.principal} on {r.catalog_name}")
                lines.append(f"REVOKE {privs} ON CATALOG `{r.catalog_name}` FROM {principal};")
                lines.append("")

            elif r.redundancy_level == RedundancyLevel.PARTIAL and include_partial:
                partial_count += 1
                redundant_privs = ", ".join(r.redundant_privileges)
                lines.append(f"-- [PARTIAL REDUNDANCY] {r.principal} on {r.catalog_name}")
                lines.append(f"-- Redundant: {r.redundant_privileges}")
                lines.append(f"-- Kept:      {r.additional_privileges}")
                lines.append(f"-- REVOKE {redundant_privs} ON CATALOG `{r.catalog_name}` FROM {principal};")
                lines.append("")

        if not full_count and not partial_count:
            lines.append("-- No redundant grants found.")
        else:
            lines.append(f"-- {'-' * 66}")
            lines.append(f"-- Summary: {full_count} full revoke(s), {partial_count} partial (commented)")
            lines.append(f"-- {'-' * 66}")

        return "\n".join(lines)
