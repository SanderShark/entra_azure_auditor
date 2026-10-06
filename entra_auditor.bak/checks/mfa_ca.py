"""MFA registration and Conditional Access checks.

Three layers of findings:

1. MFA registration gaps (from the registration report).
2. Tenant baseline: which recommended CA protections exist? Each baseline is a
   declarative ``Baseline`` row, so adding a new control is one entry in ``BASELINES``.
3. Per-policy concerns (exclusions, bypasses, report-only, ...) and accounts
   excluded from every all-user policy. These come from ``ca_analysis``.

Use ``analyze_policies`` directly if you want the readable policy profiles
(for the CLI, reports or API) rather than findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from ..models import Finding, Severity, TenantSnapshot
from ._common import (
    CRITICAL_ADMIN_ROLES,
    GLOBAL_ADMIN_ID,
    AuditConfig,
    cap,
    lower,
)
from .ca_analysis import PolicyProfile, Tag, analyze_policies

Predicate = Callable[[PolicyProfile], bool]


# --------------------------------------------------------------------------- #
# Baseline definitions
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Baseline:
    """A recommended protection.

    ``strict`` = fully satisfies the control. ``loose`` = same intent but its scope
    is narrowed by conditions (reported as *partial*). Neither = *missing*.
    A match that is only report-only is reported as *not enforced*.
    """
    check_id: str
    title: str                # phrased as the gap: "No policy ..."
    severity: Severity        # severity when missing entirely
    strict: Predicate
    loose: Predicate
    remediation: str
    note: str = ""


def _mfa_everywhere(p: PolicyProfile) -> bool:
    return p.strict_mfa and p.all_users and p.all_apps and not p.risk_based


BASELINES: list[Baseline] = [
    Baseline(
        "CA_NO_MFA_ALL_USERS",
        "No Conditional Access policy requires MFA for all users on all cloud apps",
        "high",
        strict=lambda p: Tag.MFA_ALL_USERS in p.tags,
        loose=_mfa_everywhere,
        remediation="Create a policy: all users, all cloud apps, grant 'Require multifactor "
                    "authentication' (or an authentication strength). Exclude only break-glass accounts.",
    ),
    Baseline(
        "CA_NO_MFA_ADMINS",
        "No Conditional Access policy requires MFA for administrator roles",
        "critical",
        strict=lambda p: (p.strict_mfa and p.all_apps and bool(p.covered_admin_role_ids)
                          and not p.narrowing and not p.risk_based),
        loose=lambda p: (p.strict_mfa and p.all_apps and bool(p.covered_admin_role_ids)
                         and not p.risk_based),
        remediation="Create a policy targeting directory roles (at least Global Administrator and "
                    "the other admin roles), all cloud apps, requiring MFA.",
    ),
    Baseline(
        "CA_NO_LEGACY_AUTH_BLOCK",
        "No Conditional Access policy blocks legacy authentication for all users",
        "high",
        strict=lambda p: Tag.BLOCK_LEGACY_AUTH in p.tags and p.all_users and p.all_apps,
        loose=lambda p: Tag.BLOCK_LEGACY_AUTH in p.tags,
        remediation="Create a policy: all users, all apps, client apps = Exchange ActiveSync and "
                    "Other clients, grant = Block access. Legacy protocols cannot do MFA.",
    ),
    Baseline(
        "CA_NO_GUEST_PROTECTION",
        "No Conditional Access policy requires MFA for (or blocks) guest and external users",
        "medium",
        strict=lambda p: ((p.strict_mfa and p.covers_guests and p.all_apps
                           and not p.narrowing and not p.risk_based)
                          or (Tag.BLOCK_GUESTS in p.tags and p.all_apps)),
        loose=lambda p: ((p.strict_mfa and p.covers_guests and not p.risk_based)
                         or Tag.BLOCK_GUESTS in p.tags),
        remediation="Add a policy for guest/external users requiring MFA, or rely on cross-tenant "
                    "access settings to trust the home tenant's MFA.",
    ),
    Baseline(
        "CA_NO_AZURE_MANAGEMENT_MFA",
        "No Conditional Access policy requires MFA for Azure management (portal, CLI, ARM)",
        "high",
        strict=lambda p: (p.strict_mfa and p.all_users and p.targets_azure_management
                          and not p.narrowing and not p.risk_based),
        loose=lambda p: (p.strict_mfa and p.all_users and p.targets_azure_management
                         and not p.risk_based),
        remediation="Create a policy for the 'Microsoft Azure Management' app requiring MFA "
                    "(or cover all cloud apps).",
    ),
    Baseline(
        "CA_NO_SECURITY_INFO_PROTECTION",
        "No Conditional Access policy protects registration of security information (MFA methods)",
        "medium",
        strict=lambda p: (Tag.SECURITY_INFO_REGISTRATION in p.tags
                          and p.action in ("grant", "block") and p.all_users),
        loose=lambda p: Tag.SECURITY_INFO_REGISTRATION in p.tags and p.action in ("grant", "block"),
        remediation="Create a policy on the user action 'Register security information' requiring MFA "
                    "or a trusted location, so a stolen password can't enrol an attacker's MFA.",
    ),
    Baseline(
        "CA_NO_SIGNIN_RISK_POLICY",
        "No Conditional Access policy responds to risky sign-ins",
        "low",
        strict=lambda p: Tag.SIGNIN_RISK in p.tags and p.action in ("grant", "block"),
        loose=lambda p: Tag.SIGNIN_RISK in p.tags,
        remediation="Add a sign-in risk policy (medium and above: require MFA).",
        note="Requires Entra ID P2 (Identity Protection).",
    ),
    Baseline(
        "CA_NO_USER_RISK_POLICY",
        "No Conditional Access policy responds to risky users",
        "low",
        strict=lambda p: Tag.USER_RISK in p.tags and p.action in ("grant", "block"),
        loose=lambda p: Tag.USER_RISK in p.tags,
        remediation="Add a user risk policy (high: require secure password change).",
        note="Requires Entra ID P2 (Identity Protection).",
    ),
    Baseline(
        "CA_NO_DEVICE_CODE_BLOCK",
        "No Conditional Access policy blocks device code flow",
        "low",
        strict=lambda p: Tag.BLOCK_DEVICE_CODE in p.tags and p.all_users,
        loose=lambda p: Tag.BLOCK_DEVICE_CODE in p.tags,
        remediation="Block the 'device code flow' authentication flow for all users, with narrow "
                    "exceptions for devices that need it. It is a common phishing vector.",
    ),
    Baseline(
        "CA_NO_ADMIN_AUTH_STRENGTH",
        "No administrator policy uses an authentication strength (e.g. phishing-resistant MFA)",
        "low",
        strict=lambda p: (Tag.AUTH_STRENGTH in p.tags and p.strict_mfa
                          and bool(p.covered_admin_role_ids) and p.all_apps),
        loose=lambda p: Tag.AUTH_STRENGTH in p.tags and bool(p.covered_admin_role_ids),
        remediation="Require a phishing-resistant authentication strength (FIDO2, Windows Hello, "
                    "certificate) for administrator roles.",
    ),
    Baseline(
        "CA_NO_DEVICE_CONTROLS",
        "No Conditional Access policy requires a compliant or managed device",
        "info",
        strict=lambda p: (Tag.REQUIRE_COMPLIANT_DEVICE in p.tags
                          or Tag.REQUIRE_MANAGED_DEVICE in p.tags) and p.action == "grant",
        loose=lambda p: (Tag.REQUIRE_COMPLIANT_DEVICE in p.tags
                         or Tag.REQUIRE_MANAGED_DEVICE in p.tags),
        remediation="Consider requiring compliant/managed devices for sensitive apps or admins.",
        note="Optional hardening; requires Intune or hybrid join.",
    ),
]


def _evaluate(baseline: Baseline, profiles: list[PolicyProfile]) -> tuple[str, list[PolicyProfile]]:
    enforced = [p for p in profiles if p.is_enforced]
    report_only = [p for p in profiles if p.is_report_only]
    for status, pool, predicate in (
        ("met", enforced, baseline.strict),
        ("report_only", report_only, baseline.strict),
        ("partial", enforced, baseline.loose),
        ("report_only", report_only, baseline.loose),
    ):
        matches = [p for p in pool if predicate(p)]
        if matches:
            return status, matches
    return "missing", []


def _baseline_findings(tenant_id: str, profiles: list[PolicyProfile]) -> list[Finding]:
    findings: list[Finding] = []
    for baseline in BASELINES:
        status, matches = _evaluate(baseline, profiles)
        if status == "met":
            continue
        if status == "missing":
            severity, title = baseline.severity, baseline.title
        elif status == "partial":
            severity = lower(baseline.severity)
            title = f"{baseline.title} (closest policy is narrowed by conditions)"
        else:
            severity = lower(baseline.severity)
            title = f"{baseline.title} (matching policy is report-only, not enforced)"
        findings.append(Finding(
            check_id=baseline.check_id,
            severity=severity,
            resource_type="tenant",
            resource_id=tenant_id,
            title=title,
            evidence={
                "status": status,
                "closest_policies": [
                    {"id": p.policy_id, "name": p.name, "state": p.state,
                     "narrowing": p.narrowing, "summary": p.summary}
                    for p in matches
                ],
                **({"note": baseline.note} if baseline.note else {}),
            },
            remediation=baseline.remediation,
        ))
    return findings


# --------------------------------------------------------------------------- #
# Admin role coverage gaps
# --------------------------------------------------------------------------- #

def _admin_role_gap_findings(tenant_id: str, profiles: list[PolicyProfile]) -> list[Finding]:
    """Some admin MFA policy exists, but it skips certain admin roles."""
    covering = [p for p in profiles
                if p.is_enforced and p.strict_mfa and p.all_apps and not p.risk_based]
    covered = {r for p in covering for r in p.covered_admin_role_ids}
    if not covered:  # nothing covers admins at all: the baseline already reports that
        return []
    missing = sorted(set(CRITICAL_ADMIN_ROLES) - covered)
    if not missing:
        return []
    names = [CRITICAL_ADMIN_ROLES[r] for r in missing]
    shown = ", ".join(names[:3]) + (f" +{len(names) - 3} more" if len(names) > 3 else "")
    return [Finding(
        check_id="CA_ADMIN_MFA_ROLE_GAP",
        # Missing Global Administrator is the worst possible gap.
        severity="high" if GLOBAL_ADMIN_ID in missing else "medium",
        resource_type="tenant",
        resource_id=tenant_id,
        title=f"{len(missing)} administrator role(s) are not covered by any enforced MFA policy: {shown}",
        evidence={"uncovered_roles": [{"id": r, "name": CRITICAL_ADMIN_ROLES[r]} for r in missing]},
        remediation="Add these roles to the admin MFA policy (or use an all-users MFA policy).",
    )]


# --------------------------------------------------------------------------- #
# Per-policy concerns and cross-policy exclusions
# --------------------------------------------------------------------------- #

def _policy_findings(profiles: list[PolicyProfile]) -> list[Finding]:
    findings: list[Finding] = []
    for prof in profiles:
        for concern in prof.concerns:
            findings.append(Finding(
                check_id=f"CA_{concern.code}",
                severity=concern.severity,
                resource_type="conditionalAccessPolicy",
                resource_id=prof.policy_id,
                resource_name=prof.name,
                title=f"{prof.name}: {concern.text}",
                evidence={
                    "state": prof.state,
                    "action": prof.action,
                    "summary": prof.summary,
                    "tags": [t.value for t in prof.tags],
                    **concern.evidence,
                },
                remediation=concern.remediation,
            ))
    return findings


def _excluded_from_all_findings(tenant_id: str, profiles: list[PolicyProfile]) -> list[Finding]:
    """Principals excluded from EVERY enforced all-users policy: effectively unprotected."""
    pool = [p for p in profiles
            if p.is_enforced and p.all_users and p.action in ("block", "grant")]
    if len(pool) < 2:
        return []
    users = set.intersection(*({u.id for u in p.exclusions.users} for p in pool))
    groups = set.intersection(*({g.id for g in p.exclusions.groups} for p in pool))
    if not users and not groups:
        return []

    first = pool[0].exclusions
    labels = ([u.label for u in first.users if u.id in users]
              + [g.label for g in first.groups if g.id in groups])
    # One or two users is the classic monitored break-glass pattern; anything
    # broader is a real hole.
    severity: Severity = "medium" if len(users) <= 2 and not groups else "high"
    return [Finding(
        check_id="CA_EXCLUDED_FROM_ALL_POLICIES",
        severity=severity,
        resource_type="tenant",
        resource_id=tenant_id,
        title=f"{len(users) + len(groups)} account(s)/group(s) are excluded from every "
              f"enforced all-users Conditional Access policy",
        evidence={
            "policies_compared": [p.name for p in pool],
            "excluded": labels,
            "user_ids": sorted(users),
            "group_ids": sorted(groups),
        },
        remediation="Fine only for monitored break-glass accounts (alert on every sign-in). "
                    "Otherwise remove the exclusions.",
    )]


# --------------------------------------------------------------------------- #
# MFA registration
# --------------------------------------------------------------------------- #

def _registration_findings(snapshot: TenantSnapshot, cfg: AuditConfig) -> list[Finding]:
    regs = snapshot.mfa_registrations
    if regs is None:
        return [Finding(
            check_id="MFA_DATA_UNAVAILABLE", severity="info", resource_type="tenant",
            resource_id=snapshot.tenant_id,
            title="MFA registration report unavailable; registration gaps not assessed",
            evidence={"reason": "needs Reports.Read.All + AuditLog.Read.All and Entra ID P1/P2"},
        )]

    users = {u.id: u for u in snapshot.users}
    # Enabled member accounts only: guests usually satisfy MFA in their home tenant
    # and disabled accounts can't sign in.
    scoped = [(users[r.user_id], r) for r in regs
              if r.user_id in users
              and users[r.user_id].account_enabled is not False
              and not users[r.user_id].is_guest]
    gaps = [(u, r) for u, r in scoped if not r.is_mfa_capable]
    if not gaps:
        return []

    pct = 100 * len(gaps) / len(scoped)
    severity: Severity = ("high" if pct >= cfg.mfa_gap_high_pct
                          else "medium" if pct >= cfg.mfa_gap_medium_pct else "low")
    return [Finding(
        check_id="MFA_REGISTRATION_GAP",
        severity=severity,
        resource_type="tenant",
        resource_id=snapshot.tenant_id,
        title=f"{len(gaps)} of {len(scoped)} enabled member accounts ({pct:.1f}%) are not MFA-capable",
        evidence={
            "not_capable_count": len(gaps),
            "enabled_member_count": len(scoped),
            "percent": round(pct, 1),
            "users_truncated": len(gaps) > cfg.max_evidence_items,
            "users": [
                {"id": u.id, "upn": u.user_principal_name,
                 "registered": r.is_mfa_registered, "methods": r.methods_registered}
                for u, r in cap(gaps, cfg.max_evidence_items)
            ],
        },
        remediation="Run a registration campaign, and enforce registration with a Conditional Access "
                    "policy on 'Register security information'.",
    )]


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def check_mfa_ca(snapshot: TenantSnapshot, now: datetime, cfg: AuditConfig) -> list[Finding]:
    tenant = snapshot.tenant_id
    findings = _registration_findings(snapshot, cfg)

    policies = snapshot.ca_policies
    if policies is None:
        findings.append(Finding(
            check_id="CA_DATA_UNAVAILABLE", severity="info", resource_type="tenant",
            resource_id=tenant,
            title="Conditional Access policies unavailable; CA checks skipped",
            evidence={"reason": "needs Policy.Read.All (and Entra ID P1 for Conditional Access)"},
        ))
        return findings

    if not policies:
        if snapshot.security_defaults_enabled:
            findings.append(Finding(
                check_id="CA_SECURITY_DEFAULTS_ONLY", severity="low", resource_type="tenant",
                resource_id=tenant,
                title="No Conditional Access policies; the tenant relies on security defaults",
                evidence={"security_defaults_enabled": True},
                remediation="Security defaults are a sound baseline, but Conditional Access gives "
                            "control over exclusions, admin roles, legacy auth and risk.",
            ))
        else:
            unverified = snapshot.security_defaults_enabled is None
            findings.append(Finding(
                check_id="CA_NO_MFA_ENFORCEMENT",
                severity="high" if unverified else "critical",
                resource_type="tenant", resource_id=tenant,
                title="No Conditional Access policies and security defaults are "
                      + ("not confirmed enabled" if unverified else "disabled")
                      + ": nothing enforces MFA",
                evidence={"security_defaults_enabled": snapshot.security_defaults_enabled},
                remediation="Enable security defaults immediately, then build Conditional Access "
                            "policies (MFA for all users, admins, legacy auth block).",
            ))
        return findings

    profiles = analyze_policies(snapshot, cfg, now)
    findings += _baseline_findings(tenant, profiles)
    findings += _admin_role_gap_findings(tenant, profiles)
    findings += _policy_findings(profiles)
    findings += _excluded_from_all_findings(tenant, profiles)
    return findings
