"""Privilege escalation detection for principal audit results.

Scans the effective permissions collected by :class:`PrincipalAuditor` and
flags any grant that contains a *high-privilege* Unity Catalog privilege —
specifically ``ALL_PRIVILEGES`` (which implies every data-plane operation)
and ``MANAGE`` (which allows the principal to grant those privileges to
others, making it the primary escalation vector in Unity Catalog).

The check is intentionally narrow.  It does not attempt to expand the full
privilege hierarchy — that is :mod:`redundancy`'s job.  It only surfaces the
two privileges that security teams consistently want to know about regardless
of context:

* ``ALL_PRIVILEGES`` — grants unrestricted read/write/admin access to the
  securable and all objects beneath it.
* ``MANAGE`` — grants the ability to add and remove grants on the securable,
  which can be used to self-escalate or escalate other principals.

Workspace-level admin roles (e.g. ``WORKSPACE_ADMIN``) are surfaced
separately through the workspace roles section of the principal audit and are
not duplicated here.

Usage::

    from databricks_group_audit.escalation import detect_escalations

    result = auditor.audit("alice@example.com")
    findings = detect_escalations(result)
    for f in findings:
        print(f"RISK [{f.securable_type}] {f.securable_name}: "
              f"{f.privilege} via {f.via_group}")
"""

from __future__ import annotations

from typing import List

from databricks_group_audit.models import EscalationFinding, PrincipalAuditResult

# The two privileges that represent meaningful escalation vectors in UC.
ESCALATION_PRIVILEGES: frozenset = frozenset({"ALL_PRIVILEGES", "MANAGE"})


def detect_escalations(result: PrincipalAuditResult) -> List[EscalationFinding]:
    """Return one :class:`EscalationFinding` per (privilege, securable) pair
    where an escalation privilege is present.

    A finding is *transitive* when the grant is held by a group (``via_group``
    differs from the principal's own name), meaning the principal inherits the
    high-privilege through group membership rather than a direct personal grant.

    Parameters
    ----------
    result:
        A completed :class:`~databricks_group_audit.models.PrincipalAuditResult`
        from :meth:`~databricks_group_audit.principal_auditor.PrincipalAuditor.audit`.

    Returns
    -------
    list of EscalationFinding
        Empty list when no escalation privileges are found.
    """
    findings: List[EscalationFinding] = []

    for perm in result.permissions:
        for priv in perm.privileges:
            if priv in ESCALATION_PRIVILEGES:
                findings.append(EscalationFinding(
                    principal_name=result.principal_name,
                    privilege=priv,
                    securable_type=perm.securable_type,
                    securable_name=perm.securable_name,
                    via_group=perm.via_group,
                    is_transitive=(perm.via_group.lower() != result.principal_name.lower()),
                    workspace_name=perm.workspace_name,
                    workspace_url=perm.workspace_url,
                ))

    return findings
