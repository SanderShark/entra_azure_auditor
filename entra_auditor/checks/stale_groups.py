"""Unowned, empty and truly stale groups.

Findings (per group)
    GROUP_UNOWNED  no owners. Severity rises when the group is actually in use.
    GROUP_EMPTY    no users (directly or through nested groups).
    GROUP_STALE    empty AND not used anywhere we can see AND old: a deletion candidate.
Tenant level
    GROUPS_DATA_UNAVAILABLE, GROUP_USAGE_UNAVAILABLE (info)

Scope rules
    * Mail-enabled security groups and distribution lists are SKIPPED by default. They are
      managed in Exchange, so Entra shows no owners and "unowned" would be a false alarm.
      Set ``AuditConfig.include_mail_enabled_groups`` to include them.
    * Groups synced from on-premises AD are never "unowned" (Entra can't hold their owners);
      their emptiness is reported with a note to clean them up in AD.
    * Unknown is never flagged: a count that could not be confirmed is ``None`` and skipped.

"In use" signals (any of them keeps a group out of GROUP_STALE and raises severity)
    directory role / role-assignable, group-based licensing, Teams team, access to an app
    (app role assignment), nested inside another group, referenced by a Conditional Access
    policy. NOT visible to Graph, so NOT checked: Azure RBAC, Intune assignments,
    SharePoint/Exchange permissions, on-premises use. The remediation text says so.
"""

from __future__ import annotations

from datetime import datetime

from ..models import DirectoryGroup, Finding, GROUP_KIND_LABELS, Severity, TenantSnapshot
from ._common import AuditConfig, cap, days_ago, iso, older_than

_BLIND_SPOTS = ("Graph can't see Azure RBAC, Intune assignments, SharePoint/Exchange permissions "
                "or on-premises use, so confirm with the group's users before deleting.")


def _ca_references(snapshot: TenantSnapshot) -> dict[str, list[str]]:
    refs: dict[str, list[str]] = {}
    for policy in snapshot.ca_policies or []:
        for gid in policy.include_groups:
            refs.setdefault(gid, []).append(f"{policy.display_name} (included)")
        for gid in policy.exclude_groups:
            refs.setdefault(gid, []).append(f"{policy.display_name} (excluded)")
    return refs


def usage_signals(group: DirectoryGroup, ca_refs: list[str]) -> list[tuple[str, str]]:
    """(code, text) for every way the group is known to be used."""
    signals: list[tuple[str, str]] = []
    if group.directory_roles:
        signals.append(("role", "assigned to directory role(s): " + ", ".join(group.directory_roles)))
    if group.is_role_assignable:
        signals.append(("role", "role-assignable group"))
    if group.has_licenses:
        signals.append(("license", "assigns licences"))
    if group.is_team:
        signals.append(("team", "Microsoft Teams team"))
    if group.app_role_assignments:
        signals.append(("app", f"grants access to {group.app_role_assignments} app(s)"))
    if group.nested_in_groups:
        signals.append(("nested", f"nested in {group.nested_in_groups} other group(s)"))
    if ca_refs:
        signals.append(("ca", "used by Conditional Access: " + ", ".join(ca_refs[:3])))
    return signals


def _evidence(group: DirectoryGroup, signals: list[tuple[str, str]], now: datetime, cfg: AuditConfig) -> dict:
    return {
        "kind": group.kind,
        "kind_label": GROUP_KIND_LABELS[group.kind],
        "owners": group.owner_count,
        "user_members": group.user_member_count,
        "other_members": group.other_member_count,
        "created": iso(group.created_at),
        "age_days": days_ago(now, group.created_at),
        "renewed": iso(group.renewed_at),
        "synced_from_ad": group.on_prem_synced,
        "dynamic_rule": group.membership_rule,
        "role_assignable": group.is_role_assignable,
        "usage": [text for _, text in cap(signals, cfg.max_evidence_items)],
        "usage_checked": group.usage_checked,
        "mail": group.mail,
    }


def _group_findings(
    group: DirectoryGroup,
    ca_refs: list[str],
    now: datetime,
    cfg: AuditConfig,
) -> list[Finding]:
    if group.is_exchange_managed and not cfg.include_mail_enabled_groups:
        return []

    name = group.display_name or group.id
    signals = usage_signals(group, ca_refs)
    codes = {code for code, _ in signals}
    evidence = _evidence(group, signals, now, cfg)
    findings: list[Finding] = []

    def add(check_id: str, severity: Severity, title: str, remediation: str) -> None:
        findings.append(Finding(
            check_id=check_id, severity=severity, resource_type="group", resource_id=group.id,
            resource_name=name, title=f"{name}: {title}", evidence=evidence, remediation=remediation,
        ))

    unowned = (not group.on_prem_synced) and group.owner_count == 0
    empty = group.user_member_count == 0

    if unowned:
        severity: Severity = "high" if "role" in codes else "medium" if signals else "low"
        add("GROUP_UNOWNED", severity,
            "has no owners" + (f" but is in use ({signals[0][1]})" if signals else ""),
            "Assign at least two owners (`auditor group add-owner`), or retire the group if unused.")

    if empty:
        where = " Clean it up in on-premises AD." if group.on_prem_synced else ""
        rule = " Its dynamic rule currently matches nobody." if group.is_dynamic else ""
        add("GROUP_EMPTY", "medium" if signals else "low",
            "has no users" + (f" yet is referenced ({signals[0][1]})" if signals else ""),
            "Confirm nobody needs it, then delete it (Microsoft 365 groups can be restored for "
            "30 days). If something references it, fix that first." + where + rule)

    old_enough = (older_than(now, group.created_at, cfg.group_stale_days)
                  and (group.renewed_at is None
                       or older_than(now, group.renewed_at, cfg.group_stale_days)))
    if empty and not signals and group.usage_checked and old_enough and not group.is_dynamic:
        add("GROUP_STALE", "low",
            f"is empty, unused and {days_ago(now, group.created_at)} days old: likely safe to delete",
            "Candidate for deletion. " + _BLIND_SPOTS
            + (" Delete it in on-premises AD." if group.on_prem_synced else ""))
    return findings


def check_stale_groups(snapshot: TenantSnapshot, now: datetime, cfg: AuditConfig) -> list[Finding]:
    tenant = snapshot.tenant_id
    if snapshot.groups is None:
        return [Finding(
            check_id="GROUPS_DATA_UNAVAILABLE", severity="info", resource_type="tenant",
            resource_id=tenant, title="Groups unavailable; group checks skipped",
            evidence={"reason": "needs Group.Read.All (or Directory.Read.All)"},
            remediation="Grant Group.Read.All (and admin consent) to the app.",
        )]

    ca_refs = _ca_references(snapshot)
    findings: list[Finding] = []
    for group in snapshot.groups:
        findings.extend(_group_findings(group, ca_refs.get(group.id, []), now, cfg))

    has_candidates = any(
        g.owner_count == 0 or g.user_member_count == 0 for g in snapshot.groups
        if cfg.include_mail_enabled_groups or not g.is_exchange_managed
    )
    if has_candidates and not snapshot.group_usage_available:
        findings.append(Finding(
            check_id="GROUP_USAGE_UNAVAILABLE", severity="info", resource_type="tenant",
            resource_id=tenant,
            title="Group usage (app assignments, nesting, roles) unavailable; "
                  "stale-group classification skipped",
            evidence={"reason": "needs Directory.Read.All"},
            remediation="Grant Directory.Read.All to enable GROUP_STALE detection.",
        ))
    return findings
