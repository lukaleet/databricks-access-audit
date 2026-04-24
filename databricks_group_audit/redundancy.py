"""Redundancy / overlap detection between member grants and group privileges."""

from __future__ import annotations

from typing import Dict, List, Set

from databricks_group_audit.models import (
    CatalogGrant,
    GrantSource,
    RedundancyLevel,
    RedundancyResult,
)

# Privilege hierarchy: higher privileges imply lower ones.
PRIVILEGE_HIERARCHY: Dict[str, List[str]] = {
    "ALL_PRIVILEGES": [
        "USE_CATALOG", "USE_SCHEMA", "SELECT", "MODIFY", "CREATE_SCHEMA",
        "CREATE_TABLE", "CREATE_VIEW", "CREATE_FUNCTION", "CREATE_MODEL",
        "EXECUTE", "READ_VOLUME", "WRITE_VOLUME", "CREATE_VOLUME",
        "REFRESH", "APPLY_TAG", "BROWSE",
    ],
    "MODIFY": ["SELECT"],
    "WRITE_VOLUME": ["READ_VOLUME"],
    "CREATE_TABLE": ["USE_SCHEMA"],
    "CREATE_VIEW": ["USE_SCHEMA"],
    "CREATE_FUNCTION": ["USE_SCHEMA"],
    "CREATE_MODEL": ["USE_SCHEMA"],
    "CREATE_VOLUME": ["USE_SCHEMA"],
    "CREATE_SCHEMA": ["USE_CATALOG"],
}


def expand_privileges(privileges: List[str]) -> Set[str]:
    """Expand a set of privileges to include all implied privileges."""
    expanded = set(privileges)
    changed = True
    while changed:
        changed = False
        for priv in list(expanded):
            for implied in PRIVILEGE_HIERARCHY.get(priv, []):
                if implied not in expanded:
                    expanded.add(implied)
                    changed = True
    return expanded


class RedundancyDetector:
    """Compare member grants against group effective privileges."""

    def detect_redundancy(
        self,
        catalog_grants: List[CatalogGrant],
        target_group_name: str,
    ) -> List[RedundancyResult]:
        results: List[RedundancyResult] = []

        # Group grants by catalog
        by_catalog: Dict[str, List[CatalogGrant]] = {}
        for g in catalog_grants:
            by_catalog.setdefault(g.catalog_name, []).append(g)

        for catalog_name, grants in by_catalog.items():
            # Effective group privileges (direct + upstream, expanded)
            group_privs: Set[str] = set()
            for g in grants:
                if g.grant_source in (GrantSource.DIRECT, GrantSource.UPSTREAM):
                    group_privs.update(g.privileges)
            group_effective = expand_privileges(list(group_privs))

            # Check each member-direct grant
            for g in grants:
                if g.grant_source != GrantSource.MEMBER_DIRECT:
                    continue

                member_set = set(g.privileges)
                redundant = member_set & group_effective
                additional = member_set - group_effective

                if not redundant:
                    level = RedundancyLevel.NONE
                    rec = "No action needed - member has unique privileges"
                elif not additional:
                    level = RedundancyLevel.FULL
                    rec = f"REVOKE all from {g.principal} - fully covered by group"
                else:
                    level = RedundancyLevel.PARTIAL
                    rec = (
                        f"Consider revoking {sorted(redundant)} from {g.principal}; "
                        f"keeping {sorted(additional)}"
                    )

                results.append(RedundancyResult(
                    catalog_name=catalog_name,
                    principal=g.principal,
                    principal_type=g.principal_type,
                    member_privileges=sorted(member_set),
                    group_effective_privileges=sorted(group_effective),
                    redundant_privileges=sorted(redundant),
                    additional_privileges=sorted(additional),
                    redundancy_level=level,
                    recommendation=rec,
                ))

        return results
