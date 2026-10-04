"""Privileged directory role holders.

Tenant level
    PRIV_TOO_MANY_GLOBAL_ADMINS / PRIV_TOO_FEW_GLOBAL_ADMINS
    PRIV_PIM_UNAVAILABLE   (no PIM: every assignment is standing, so that check is skipped)
    PRIV_DATA_UNAVAILABLE

Per holder (user or service principal)
    PRIV_ADMIN_NO_MFA          no MFA method registered
    PRIV_ADMIN_WEAK_MFA        only phone/email methods registered
    PRIV_INACTIVE_ADMIN        no recent sign-in (stricter threshold than ordinary users)
    PRIV_PERMANENT_ASSIGNMENT  standing (non-PIM) access to a privileged role
    PRIV_GUEST_ADMIN           external guest holds a privileged role
    PRIV_SERVICE_PRINCIPAL_ROLE  an app or managed identity holds a privileged role
    PRIV_DISABLED_ACCOUNT      disabled account still holds role assignments
    PRIV_SYNCED_ADMIN          admin is synced from on-prem AD (compromise there = compromise here)
    PRIV_EXCESSIVE_ROLES       holds more privileged roles than the configured maximum
    PRIV_ORPHANED_ASSIGNMENT   role assigned to a principal that no longer exists

"Privileged" means Microsoft flags the role ``isPrivileged`` OR it is in our
critical admin list. Holders include people who only inherit a role through a
role-assignable group (the collector expands groups).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from ..models import Finding, RoleAssignment, Severity, TenantSnapshot, User
from ._common import (
    CRITICAL_ADMIN_ROLES,
    GLOBAL_ADMIN_ID,
    TIER0_ROLE_IDS,
    WEAK_MFA_METHODS,
    AuditConfig,
    aware,
    cap,
    days_ago,
    iso,
    lower,
    older_than,
)


def _is_privileged(a: RoleAssignment) -> bool:
    return a.is_privileged_role is True or a.role_id in CRITICAL_ADMIN_ROLES


def _role_evidence(assignments: list[RoleAssignment]) -> list[dict]:
    return [
        {
            "role": a.role_name,
            "role_id": a.role_id,
            "state": a.state,
            "permanent": a.is_permanent,
            "activated_via_pim": a.activated_via_pim,
            "scope": a.directory_scope_id,
            "via_group": a.via_group_id,
            "ends": iso(a.end_date_time),
        }
        for a in assignments
    ]


def _dedupe(assignments: list[RoleAssignment]) -> list[RoleAssignment]:
    """A person holding a role directly and via a group counts once per (role, state, scope)."""
    seen: set[tuple] = set()
    out = []
    for a in assignments:
        key = (a.principal_id, a.role_id, a.state, a.directory_scope_id)
        if key not in seen:
            seen.add(key)
            out.append(a)
    return out


# --------------------------------------------------------------------------- #
# Tenant-level
# --------------------------------------------------------------------------- #

def _global_admin_count_findings(
    snapshot: TenantSnapshot, privileged: list[RoleAssignment], users: dict[str, User], cfg: AuditConfig
) -> list[Finding]:
    admins = {
        a.principal_id: a.principal_upn or a.principal_display_name or a.principal_id
        for a in privileged
        if a.role_id == GLOBAL_ADMIN_ID and a.principal_type == "user"
        and not (users.get(a.principal_id) and users[a.principal_id].account_enabled is False)
    }
    evidence = {"count": len(admins), "admins": cap(sorted(admins.values()), cfg.max_evidence_items)}

    if len(admins) > cfg.max_global_admins:
        return [Finding(
            check_id="PRIV_TOO_MANY_GLOBAL_ADMINS", severity="high", resource_type="tenant",
            resource_id=snapshot.tenant_id,
            title=f"{len(admins)} Global Administrators (recommended: fewer than {cfg.max_global_admins})",
            evidence={**evidence, "max_recommended": cfg.max_global_admins},
            remediation="Move day-to-day admins to narrower roles and make the rest PIM-eligible.",
        )]
    if len(admins) < cfg.min_global_admins:
        return [Finding(
            check_id="PRIV_TOO_FEW_GLOBAL_ADMINS", severity="medium", resource_type="tenant",
            resource_id=snapshot.tenant_id,
            title=f"Only {len(admins)} Global Administrator(s) (recommended: at least "
                  f"{cfg.min_global_admins}, including break-glass)",
            evidence={**evidence, "min_recommended": cfg.min_global_admins},
            remediation="Keep at least two emergency-access Global Admin accounts, monitored and "
                        "excluded from Conditional Access only as needed.",
        )]
    return []


# --------------------------------------------------------------------------- #
# Per holder
# --------------------------------------------------------------------------- #

def _admin_inactivity(user: User, now: datetime, cfg: AuditConfig) -> tuple[str, dict] | None:
    threshold = cfg.admin_inactive_days
    last = aware(user.last_activity)
    if last is None:
        if older_than(now, user.created_at, threshold):
            return (f"has never signed in (account is {days_ago(now, user.created_at)} days old)",
                    {"threshold_days": threshold, "never_signed_in": True})
        return None
    if older_than(now, last, threshold):
        return (f"has not signed in for {days_ago(now, last)} days",
                {"last_activity": last.isoformat(), "days_inactive": days_ago(now, last),
                 "threshold_days": threshold})
    return None


def _holder_findings(
    pid: str,
    held: list[RoleAssignment],
    snapshot: TenantSnapshot,
    users: dict[str, User],
    mfa: dict,
    now: datetime,
    cfg: AuditConfig,
) -> list[Finding]:
    first = held[0]
    user = users.get(pid)
    name = (first.principal_upn or first.principal_display_name
            or (user.user_principal_name if user else None) or pid)
    is_sp = first.principal_type == "servicePrincipal"
    resource_type = "servicePrincipal" if is_sp else "user"
    active = [a for a in held if a.state == "active"]
    tier0 = any(a.role_id in TIER0_ROLE_IDS for a in held)
    findings: list[Finding] = []

    def add(check_id: str, severity: Severity, title: str, remediation: str,
            key: str = "", roles: list[RoleAssignment] | None = None, **evidence: object) -> None:
        findings.append(Finding(
            check_id=check_id, severity=severity, resource_type=resource_type,
            resource_id=pid, resource_name=name, title=f"{name}: {title}",
            evidence={"roles": _role_evidence(roles or held), **evidence},
            remediation=remediation, key=key,
        ))

    # -- orphaned: principal is gone ------------------------------------------------
    if first.principal_type == "unknown" and user is None:
        add("PRIV_ORPHANED_ASSIGNMENT", "low",
            "role assigned to a principal that no longer exists",
            "Remove the dangling role assignment.")
        return findings

    role_names = ", ".join(sorted({a.role_name for a in held}))

    # -- non-human holders ----------------------------------------------------------
    if is_sp:
        add("PRIV_SERVICE_PRINCIPAL_ROLE", "high" if tier0 else "medium",
            f"application/managed identity holds privileged role(s): {role_names}",
            "Prefer least-privilege Graph app permissions over directory roles; if a role is "
            "unavoidable, protect the app's credentials and owners like an admin account.")
        return findings

    guest = user.is_guest if user else "#EXT#" in (first.principal_upn or "")
    if guest:
        add("PRIV_GUEST_ADMIN", "critical" if tier0 else "high",
            f"external guest holds privileged role(s): {role_names}",
            "Avoid giving guests directory roles; use a dedicated internal admin account.")

    if user is not None and user.account_enabled is False:
        add("PRIV_DISABLED_ACCOUNT", "medium",
            f"disabled account still holds role assignment(s): {role_names}",
            "Remove role assignments from disabled accounts so re-enabling can't restore admin rights.")
        return findings  # MFA / activity checks are meaningless for a disabled account

    # -- MFA ------------------------------------------------------------------------
    reg = mfa.get(pid)
    if reg is not None:
        if not reg.is_mfa_registered:
            add("PRIV_ADMIN_NO_MFA", "critical" if active else "high",
                f"privileged account has no MFA method registered ({role_names})",
                "Register MFA immediately; back it with a Conditional Access policy for admin roles.",
                methods=reg.methods_registered)
        elif reg.methods_registered and set(reg.methods_registered) <= WEAK_MFA_METHODS:
            add("PRIV_ADMIN_WEAK_MFA", "high" if tier0 else "medium",
                "privileged account only has phone/email methods registered "
                f"({', '.join(reg.methods_registered)})",
                "Register a phishing-resistant method (FIDO2 key, Windows Hello, passkey) or at "
                "least Microsoft Authenticator, and require an authentication strength for admins.",
                methods=reg.methods_registered)

    # -- inactivity -----------------------------------------------------------------
    if snapshot.sign_in_data_available and user is not None:
        stale = _admin_inactivity(user, now, cfg)
        if stale:
            text, ev = stale
            add("PRIV_INACTIVE_ADMIN", "high" if active else "medium",
                f"privileged account {text} ({role_names})",
                "Remove the role assignments and disable the account if it is no longer needed.",
                **ev)

    # -- standing access ------------------------------------------------------------
    if snapshot.eligible_roles_available:  # otherwise PIM isn't in use; reported once at tenant level
        for a in active:
            if not a.is_permanent:
                continue
            severity: Severity = "high" if a.role_id in TIER0_ROLE_IDS else "medium"
            if a.directory_scope_id not in ("/", "", None):
                severity = lower(severity)  # scoped to an administrative unit: smaller blast radius
            add("PRIV_PERMANENT_ASSIGNMENT", severity,
                f"permanent (standing) assignment to {a.role_name}",
                "Convert to a PIM-eligible assignment with just-in-time activation. "
                "Break-glass accounts are the intended exception.",
                key=f"{a.role_id}:{a.directory_scope_id}", roles=[a])

    # -- role sprawl ----------------------------------------------------------------
    distinct = {a.role_id for a in held}
    if len(distinct) > cfg.max_roles_per_admin:
        add("PRIV_EXCESSIVE_ROLES", "low",
            f"holds {len(distinct)} privileged roles (maximum expected: {cfg.max_roles_per_admin})",
            "Review whether each role is needed; prefer one narrowly scoped role per duty.",
            role_count=len(distinct))

    # -- on-prem synced admin -------------------------------------------------------
    if user is not None and user.on_prem_synced:
        add("PRIV_SYNCED_ADMIN", "medium" if tier0 else "low",
            "privileged account is synced from on-premises AD",
            "Use cloud-only accounts for Entra admin roles so an on-prem compromise "
            "doesn't become a tenant compromise.")

    return findings


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def check_privileged(snapshot: TenantSnapshot, now: datetime, cfg: AuditConfig) -> list[Finding]:
    tenant = snapshot.tenant_id
    if snapshot.role_assignments is None:
        return [Finding(
            check_id="PRIV_DATA_UNAVAILABLE", severity="info", resource_type="tenant",
            resource_id=tenant,
            title="Directory role assignments unavailable; privileged-account checks skipped",
            evidence={"reason": "needs RoleManagement.Read.Directory"},
            remediation="Grant RoleManagement.Read.Directory (and admin consent) to the app.",
        )]

    users = {u.id: u for u in snapshot.users}
    mfa = {m.user_id: m for m in snapshot.mfa_registrations or []}
    privileged = _dedupe([
        a for a in snapshot.role_assignments if a.principal_type != "group" and _is_privileged(a)
    ])

    findings = _global_admin_count_findings(snapshot, privileged, users, cfg)

    if not snapshot.eligible_roles_available:
        findings.append(Finding(
            check_id="PRIV_PIM_UNAVAILABLE", severity="info", resource_type="tenant",
            resource_id=tenant,
            title="PIM data unavailable; all privileged assignments are treated as standing "
                  "and permanent-assignment checks were skipped",
            evidence={"reason": "needs Entra ID P2 and RoleEligibilitySchedule.Read.Directory"},
            remediation="With P2, use PIM so admins activate roles just-in-time.",
        ))

    holders: dict[str, list[RoleAssignment]] = defaultdict(list)
    for a in privileged:
        holders[a.principal_id].append(a)
    for pid, held in holders.items():
        findings += _holder_findings(pid, held, snapshot, users, mfa, now, cfg)
    return findings
