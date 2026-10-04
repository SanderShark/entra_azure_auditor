"""Inactive and stale user accounts.

Findings
--------
INACTIVE_USER            enabled account with no sign-in for longer than the threshold
NEVER_SIGNED_IN          enabled account older than the threshold that has never signed in
GUEST_INVITE_PENDING     guest invitation still unaccepted after ``pending_invite_days``
SIGNIN_DATA_UNAVAILABLE  tenant lacks Entra ID P1/P2, so activity-based checks were skipped

Thresholds are strict: an account is inactive only when it has been quiet for
*more than* N days (exactly N days is not flagged). Guests use a stricter
threshold than members. Privileged accounts are judged more strictly in
``privileged.py``.
"""

from __future__ import annotations

from datetime import datetime

from ..models import Finding, Severity, TenantSnapshot, User
from ._common import AuditConfig, aware, days_ago, iso, older_than


def _user_finding(
    user: User, check_id: str, severity: Severity, title: str, evidence: dict, remediation: str
) -> Finding:
    return Finding(
        check_id=check_id,
        severity=severity,
        resource_type="user",
        resource_id=user.id,
        resource_name=user.user_principal_name or user.display_name,
        title=title,
        evidence={
            "upn": user.user_principal_name,
            "user_type": user.user_type,
            "created_at": iso(user.created_at),
            "on_prem_synced": user.on_prem_synced,
            **evidence,
        },
        remediation=remediation,
    )


def _inactivity_findings(snapshot: TenantSnapshot, now: datetime, cfg: AuditConfig) -> list[Finding]:
    findings: list[Finding] = []
    for user in snapshot.users:
        if user.account_enabled is False:
            continue  # disabled accounts can't sign in
        if user.has_pending_invitation:
            continue  # reported by the invitation check instead

        kind = "guest" if user.is_guest else "member"
        threshold = cfg.guest_inactive_days if user.is_guest else cfg.inactive_days
        severity: Severity = "medium" if user.is_guest else "low"
        name = user.user_principal_name or user.display_name or user.id
        last = aware(user.last_activity)

        if last is None:
            # signInActivity is null for accounts that never signed in (and for
            # sign-ins older than the report's retention), so fall back to age.
            if not older_than(now, user.created_at, threshold):
                continue  # new account: give it time
            findings.append(_user_finding(
                user, "NEVER_SIGNED_IN", severity,
                f"{name}: {kind} account created {days_ago(now, user.created_at)} days ago "
                f"has never signed in",
                {"threshold_days": threshold, "account_age_days": days_ago(now, user.created_at)},
                "Confirm the account is still needed; disable it, then delete after a grace period.",
            ))
        elif older_than(now, last, threshold):
            findings.append(_user_finding(
                user, "INACTIVE_USER", severity,
                f"{name}: {kind} account inactive for {days_ago(now, last)} days",
                {
                    "last_activity": last.isoformat(),
                    "days_inactive": days_ago(now, last),
                    "threshold_days": threshold,
                },
                "Disable the account (and remove its licences and role assignments), "
                "then delete after a grace period.",
            ))
    return findings


def _stale_invitation_findings(
    snapshot: TenantSnapshot, now: datetime, cfg: AuditConfig
) -> list[Finding]:
    findings: list[Finding] = []
    for user in snapshot.users:
        if not user.has_pending_invitation:
            continue
        since = user.external_user_state_changed_at or user.created_at
        if not older_than(now, since, cfg.pending_invite_days):
            continue
        name = user.user_principal_name or user.display_name or user.id
        findings.append(_user_finding(
            user, "GUEST_INVITE_PENDING", "low",
            f"{name}: guest invitation unaccepted for {days_ago(now, since)} days",
            {"invited_since": iso(since), "days_pending": days_ago(now, since),
             "threshold_days": cfg.pending_invite_days},
            "Delete stale invitations. Each one is an external identity that could be "
            "redeemed by whoever controls the invited mailbox.",
        ))
    return findings


def check_inactive_users(snapshot: TenantSnapshot, now: datetime, cfg: AuditConfig) -> list[Finding]:
    findings: list[Finding] = []

    if snapshot.sign_in_data_available:
        findings += _inactivity_findings(snapshot, now, cfg)
    else:
        findings.append(Finding(
            check_id="SIGNIN_DATA_UNAVAILABLE",
            severity="info",
            resource_type="tenant",
            resource_id=snapshot.tenant_id,
            title="Sign-in activity unavailable; inactive-account checks skipped",
            evidence={"reason": "signInActivity needs Entra ID P1/P2 and AuditLog.Read.All"},
            remediation="Licence the tenant (P1 or P2) and grant AuditLog.Read.All.",
        ))

    # Invitation state doesn't depend on sign-in data.
    findings += _stale_invitation_findings(snapshot, now, cfg)
    return findings
