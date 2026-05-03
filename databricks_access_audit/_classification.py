"""Shared grant classification helpers used by all permission scanners."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from databricks_access_audit.models import GrantSource, GroupMember


def build_member_lookups(
    all_members: Dict[str, List[GroupMember]],
) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
    """Build lookup sets from a flat members dict for grant classification.

    Returns ``(member_emails, member_display_names, sp_display_names, sp_app_ids)``.
    Values are stored in their original case; :func:`classify_grant` performs
    case-insensitive comparison where needed.
    """
    member_emails: Set[str] = set()
    member_names: Set[str] = set()
    sp_names: Set[str] = set()
    sp_app_ids: Set[str] = set()

    for u in all_members.get("users", []):
        if u.email:
            member_emails.add(u.email)
        if u.display_name:
            member_names.add(u.display_name)

    for sp in all_members.get("service_principals", []):
        if sp.display_name:
            sp_names.add(sp.display_name)
        if sp.application_id:
            sp_app_ids.add(sp.application_id)

    return member_emails, member_names, sp_names, sp_app_ids


def classify_grant(
    principal: str,
    target_group_name: str,
    upstream_groups: Dict[str, str],
    member_emails: Set[str],
    member_names: Set[str],
    sp_names: Set[str],
    sp_app_ids: Set[str],
) -> Optional[Tuple[GrantSource, str, Optional[str], bool]]:
    """Classify a single UC grant relative to the target group.

    Returns ``(source, principal_type, inherited_from, member_of_target)`` or
    ``None`` when the principal is completely unrelated to the target group.

    Handles several real-world Databricks quirks:

    * Backtick-quoted principal names that the API occasionally returns.
    * Case-insensitive email matching — Azure AD normalises email casing
      differently across APIs, so ``alice@corp.com`` and ``Alice@Corp.com``
      should be treated as the same identity.
    * Display-name grants — some setups grant privileges to a user's
      display name rather than their email address.
    * Service principals identified by either display name or application ID.
    """
    if not principal or not principal.strip():
        return None

    # Strip backtick quoting Databricks sometimes wraps around principal names
    clean = principal.replace("`", "").strip()

    # ------------------------------------------------------------------ #
    # 1. Direct — the target group itself holds this privilege             #
    # ------------------------------------------------------------------ #
    if clean == target_group_name or principal == target_group_name:
        return GrantSource.DIRECT, "GROUP", None, False

    # ------------------------------------------------------------------ #
    # 2. Upstream — a parent / ancestor group of the target holds it       #
    # ------------------------------------------------------------------ #
    if principal in upstream_groups or clean in upstream_groups:
        resolved = principal if principal in upstream_groups else clean
        return GrantSource.UPSTREAM, "GROUP", resolved, False

    clean_lower = clean.lower()

    # ------------------------------------------------------------------ #
    # 3. Member — user identified by email (case-insensitive)              #
    # ------------------------------------------------------------------ #
    if clean in member_emails or any(e.lower() == clean_lower for e in member_emails):
        return GrantSource.MEMBER_DIRECT, "USER", None, True

    # ------------------------------------------------------------------ #
    # 4. Member — user identified by display name                          #
    #    Some Databricks setups (especially with AAD sync) grant using     #
    #    the display name rather than the email address.                   #
    # ------------------------------------------------------------------ #
    if clean in member_names or any(n.lower() == clean_lower for n in member_names):
        return GrantSource.MEMBER_DIRECT, "USER", None, True

    # ------------------------------------------------------------------ #
    # 5. Member — service principal identified by display name             #
    # ------------------------------------------------------------------ #
    if clean in sp_names or any(n.lower() == clean_lower for n in sp_names):
        return GrantSource.MEMBER_DIRECT, "SERVICE_PRINCIPAL", None, True

    # ------------------------------------------------------------------ #
    # 6. Member — service principal identified by application / client ID  #
    #    The application ID is case-sensitive (it's a GUID).               #
    # ------------------------------------------------------------------ #
    if clean in sp_app_ids:
        return GrantSource.MEMBER_DIRECT, "SERVICE_PRINCIPAL", None, True

    return None
