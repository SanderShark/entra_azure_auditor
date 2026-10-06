"""App registrations and service principals: stale, expiring or over-privileged.

Credentials (app registrations and service principals, e.g. SAML certificates)
    APP_CREDENTIAL_EXPIRED     already expired
    APP_CREDENTIAL_EXPIRING    expires within ``credential_warn_days`` (outage risk)
    APP_SECRET_LONG_LIVED      client secret valid for longer than ``long_lived_secret_days``

Lifecycle
    SP_INACTIVE                no sign-in for ``sp_inactive_days`` (never signed in counts too)
    APP_LIKELY_ABANDONED       every credential expired AND its service principal is inactive
    APP_NO_OWNER               app registration with no owner

Privilege
    SP_HIGH_PRIVILEGE_GRANT    holds powerful Microsoft Graph application permissions

Microsoft first-party apps are skipped: you can't fix them and they add noise.
Managed identities are exempt from inactivity and owner checks (they have no
owners, and their sign-ins are not reliably in the SP sign-in report).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from ..models import Credential, Finding, ServicePrincipal, Severity, TenantSnapshot
from ._common import (
    HIGH_PRIV_GRAPH_ROLES,
    AuditConfig,
    aware,
    days_ago,
    highest,
    iso,
    lower,
    older_than,
)


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #

def _credential_findings(
    resource_type: str,
    rid: str,
    name: str,
    creds: list[Credential],
    now: datetime,
    cfg: AuditConfig,
) -> list[Finding]:
    findings: list[Finding] = []

    def valid_after(instant: datetime, exclude: Credential) -> bool:
        """Is there another credential still valid past ``instant``? (rotation in progress)"""
        return any(
            o is not exclude and (aware(o.end) is None or aware(o.end) > instant) for o in creds
        )

    for index, c in enumerate(creds):
        end = aware(c.end)
        key = c.key_id or f"cred{index}"
        base = {"kind": c.kind, "credential_name": c.display_name, "key_id": c.key_id,
                "start": iso(c.start), "end": iso(c.end)}
        label = f"{c.kind} '{c.display_name}'" if c.display_name else c.kind

        def add(check_id: str, severity: Severity, title: str, remediation: str, **extra: object) -> None:
            findings.append(Finding(
                check_id=check_id, severity=severity, resource_type=resource_type,
                resource_id=rid, resource_name=name, title=f"{name}: {title}",
                evidence={**base, **extra}, remediation=remediation, key=key,
            ))

        if end is not None and end < now:
            # Harmless clean-up if a valid credential exists; a dead or abandoned app if not.
            add("APP_CREDENTIAL_EXPIRED", "low" if valid_after(now, c) else "medium",
                f"{label} expired {days_ago(now, end)} days ago",
                "Delete expired credentials. If the app is still used, rotate to a new credential; "
                "if not, remove the app.",
                days_expired=days_ago(now, end))
        elif end is not None and end - now <= timedelta(days=cfg.credential_warn_days):
            days_left = (end - now).days
            severity: Severity = "high" if days_left <= cfg.credential_urgent_days else "medium"
            replaced = valid_after(end, c)
            if replaced:
                severity = lower(severity)  # a successor already exists: rotation underway
            add("APP_CREDENTIAL_EXPIRING", severity,
                f"{label} expires in {days_left} days"
                + (" (a later credential exists)" if replaced else " (no replacement)"),
                "Rotate before expiry (add the new credential first, then remove the old one). "
                "Prefer certificates or workload identity federation over secrets.",
                days_left=days_left, has_replacement=replaced)

        if (c.kind == "secret" and c.start is not None and end is not None and end >= now
                and (end - aware(c.start)).days > cfg.long_lived_secret_days):
            add("APP_SECRET_LONG_LIVED", "low",
                f"{label} is valid for {(end - aware(c.start)).days} days "
                f"(maximum expected: {cfg.long_lived_secret_days})",
                "Use shorter-lived secrets, certificates or federated credentials.",
                lifetime_days=(end - aware(c.start)).days)
    return findings


# --------------------------------------------------------------------------- #
# Service principals
# --------------------------------------------------------------------------- #

def _sp_is_inactive(sp: ServicePrincipal, now: datetime, cfg: AuditConfig) -> bool:
    last = aware(sp.last_sign_in)
    if last is not None:
        return older_than(now, last, cfg.sp_inactive_days)
    return older_than(now, sp.created_at, cfg.sp_inactive_days)  # never signed in


def _grant_severity(sp: ServicePrincipal) -> tuple[Severity | None, list[dict]]:
    matched = [
        {"permission": role, "severity": HIGH_PRIV_GRAPH_ROLES[role]}
        for role in sorted(sp.graph_app_roles) if role in HIGH_PRIV_GRAPH_ROLES
    ]
    if not matched:
        return None, []
    return highest(*(m["severity"] for m in matched)), matched


def _sp_findings(sp: ServicePrincipal, now: datetime, cfg: AuditConfig, sign_in_known: bool) -> list[Finding]:
    findings: list[Finding] = []
    name = sp.display_name or sp.app_id or sp.id
    grant_sev, grants = _grant_severity(sp)

    def add(check_id: str, severity: Severity, title: str, remediation: str, **evidence: object) -> None:
        findings.append(Finding(
            check_id=check_id, severity=severity, resource_type="servicePrincipal",
            resource_id=sp.id, resource_name=name, title=f"{name}: {title}",
            evidence={"app_id": sp.app_id, "type": sp.service_principal_type, **evidence},
            remediation=remediation,
        ))

    if grant_sev is not None:
        add("SP_HIGH_PRIVILEGE_GRANT", grant_sev,
            f"holds {len(grants)} high-privilege Graph application permission(s): "
            + ", ".join(g["permission"] for g in grants[:4]) + ("..." if len(grants) > 4 else ""),
            "Replace with least-privilege permissions (or delegated ones) where possible; make sure "
            "the app has owners, short-lived credentials and monitoring.",
            permissions=grants, owner_count=sp.owner_count)

    if (sign_in_known and not sp.is_managed_identity and sp.account_enabled is not False
            and _sp_is_inactive(sp, now, cfg)):
        # An inactive app that can still change the directory is far worse than a dormant toy.
        severity: Severity = {"critical": "high", "high": "high", "medium": "medium"}.get(
            grant_sev or "", "low")
        last = aware(sp.last_sign_in)
        add("SP_INACTIVE", severity,
            (f"no sign-in for {days_ago(now, last)} days" if last
             else f"created {days_ago(now, sp.created_at)} days ago and has never signed in")
            + (" while still holding high-privilege permissions" if grant_sev else ""),
            "Disable the service principal; delete it (and the app registration) after a grace period.",
            last_sign_in=iso(last), threshold_days=cfg.sp_inactive_days,
            high_privilege=bool(grant_sev))
    return findings


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def check_stale_apps(snapshot: TenantSnapshot, now: datetime, cfg: AuditConfig) -> list[Finding]:
    apps, sps = snapshot.applications, snapshot.service_principals
    tenant = snapshot.tenant_id
    if apps is None and sps is None:
        return [Finding(
            check_id="APPS_DATA_UNAVAILABLE", severity="info", resource_type="tenant",
            resource_id=tenant,
            title="Applications and service principals unavailable; app checks skipped",
            evidence={"reason": "needs Application.Read.All"},
            remediation="Grant Application.Read.All (and admin consent) to the app.",
        )]

    findings: list[Finding] = []
    sign_in_known = snapshot.sp_sign_in_data_available
    sp_by_app = {sp.app_id: sp for sp in sps or [] if sp.app_id}

    for app in apps or []:
        name = app.display_name or app.app_id
        findings += _credential_findings("application", app.id, name, app.credentials, now, cfg)

        if app.owner_count == 0:
            findings.append(Finding(
                check_id="APP_NO_OWNER", severity="low", resource_type="application",
                resource_id=app.id, resource_name=name,
                title=f"{name}: app registration has no owner",
                evidence={"app_id": app.app_id, "multi_tenant": app.is_multi_tenant},
                remediation="Assign at least two owners so someone is accountable for the app's "
                            "credentials and permissions.",
            ))

        sp = sp_by_app.get(app.app_id)
        if (sign_in_known and sp is not None and app.credentials
                and all(c.is_expired(now) for c in app.credentials)
                and _sp_is_inactive(sp, now, cfg)):
            findings.append(Finding(
                check_id="APP_LIKELY_ABANDONED", severity="medium", resource_type="application",
                resource_id=app.id, resource_name=name,
                title=f"{name}: all credentials expired and the service principal is inactive; "
                      f"the app is probably abandoned",
                evidence={"app_id": app.app_id, "credential_count": len(app.credentials),
                          "last_sign_in": iso(sp.last_sign_in)},
                remediation="Confirm with the owner, then delete the app registration and service principal.",
            ))

    for sp in sps or []:
        if sp.is_microsoft_first_party:
            continue
        name = sp.display_name or sp.app_id or sp.id
        findings += _credential_findings("servicePrincipal", sp.id, name, sp.credentials, now, cfg)
        findings += _sp_findings(sp, now, cfg, sign_in_known)

    if sps is not None and not sign_in_known:
        findings.append(Finding(
            check_id="SP_SIGNIN_DATA_UNAVAILABLE", severity="info", resource_type="tenant",
            resource_id=tenant,
            title="Service principal sign-in activity unavailable; inactive-app checks skipped",
            evidence={"reason": "needs AuditLog.Read.All, Entra ID P1/P2, and the beta report endpoint"},
            remediation="Grant AuditLog.Read.All and licence the tenant (P1/P2).",
        ))
    return findings
