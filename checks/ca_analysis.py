"""Conditional Access policy analysis.

Turns each raw policy into a ``PolicyProfile`` that answers, in plain terms:

* WHO does it apply to, and who is excluded (names and group sizes resolved)?
* WHAT does it protect (apps, user actions, auth contexts)?
* WHEN does it apply (client apps, platforms, locations, device filter, risk)?
* WHAT HAPPENS: block, or grant with which requirements (and AND/OR logic)?
* WHAT SESSION controls are applied?
* WHAT IS IT FOR (purpose tags) and what is WRONG with it (concerns)?

The profiles are JSON-serialisable, so the CLI, reports and API can all show them.
``mfa_ca.py`` builds its tenant-level findings on top of these profiles.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from ..models import (
    ConditionalAccessPolicy,
    GroupInfo,
    NamedLocation,
    Severity,
    TenantSnapshot,
    User,
)
from ._common import (
    CRITICAL_ADMIN_ROLES,
    AuditConfig,
    aware,
    highest,
)

# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #

class Tag(str, Enum):
    """What a policy is *for*. A policy can carry several tags."""
    MFA_ALL_USERS = "mfa_all_users"            # strict MFA, all users, all apps, no narrowing
    MFA_ADMINS = "mfa_admins"                  # strict MFA covering admin roles
    MFA_GUESTS = "mfa_guests"
    MFA_AZURE_MANAGEMENT = "mfa_azure_management"
    AUTH_STRENGTH = "auth_strength"            # uses an authentication strength (e.g. phishing-resistant)
    BLOCK_LEGACY_AUTH = "block_legacy_auth"
    BLOCK_DEVICE_CODE = "block_device_code_flow"
    BLOCK_BY_LOCATION = "block_by_location"
    BLOCK_BY_PLATFORM = "block_by_platform"
    BLOCK_GUESTS = "block_guests"
    BLOCK_ALL_ACCESS = "block_all_access"
    REQUIRE_COMPLIANT_DEVICE = "require_compliant_device"
    REQUIRE_MANAGED_DEVICE = "require_managed_device"
    REQUIRE_APP_PROTECTION = "require_app_protection"
    REQUIRE_APPROVED_APP = "require_approved_app"
    PASSWORD_CHANGE = "password_change"
    TERMS_OF_USE = "terms_of_use"
    SIGNIN_RISK = "signin_risk"
    USER_RISK = "user_risk"
    INSIDER_RISK = "insider_risk"
    WORKLOAD_IDENTITY = "workload_identity"
    SECURITY_INFO_REGISTRATION = "security_info_registration"
    DEVICE_REGISTRATION = "device_registration"
    SESSION_SIGNIN_FREQUENCY = "session_signin_frequency"
    SESSION_PERSISTENT_BROWSER = "session_persistent_browser"
    SESSION_APP_CONTROL = "session_app_control"      # Defender for Cloud Apps
    SESSION_APP_RESTRICTIONS = "session_app_restrictions"
    SESSION_CAE = "session_continuous_access_evaluation"


_LEGACY_TYPES = frozenset({"exchangeActiveSync", "other", "easSupported"})
_MODERN_TYPES = frozenset({"browser", "mobileAppsAndDesktopClients"})

_CLIENT_LABELS = {
    "browser": "Browsers",
    "mobileAppsAndDesktopClients": "Mobile apps and desktop clients",
    "exchangeActiveSync": "Exchange ActiveSync clients",
    "easSupported": "Exchange ActiveSync (supported platforms)",
    "other": "Other legacy clients (IMAP, POP, SMTP, ...)",
}
_APP_LABELS = {
    "All": "All cloud apps",
    "Office365": "Office 365",
    "MicrosoftAdminPortals": "Microsoft Admin Portals",
    "797f4846-ba00-4fd7-ba43-dac1f8f63013": "Microsoft Azure Management",
    "00000002-0000-0ff1-ce00-000000000000": "Exchange Online",
    "00000003-0000-0ff1-ce00-000000000000": "SharePoint Online",
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe": "Microsoft Teams",
}
AZURE_MANAGEMENT_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
_USER_ACTIONS = {
    "urn:user:registersecurityinfo": "Register security information",
    "urn:user:registerdevice": "Register or join devices",
}
_REQUIREMENT_LABELS = {
    "mfa": "Require multifactor authentication",
    "compliantDevice": "Require device to be marked compliant",
    "domainJoinedDevice": "Require Entra hybrid joined device",
    "approvedApplication": "Require approved client app (deprecated by Microsoft)",
    "compliantApplication": "Require app protection policy",
    "passwordChange": "Require password change",
    "block": "Block access",
}
_FLOW_LABELS = {
    "deviceCodeFlow": "device code flow",
    "authenticationTransfer": "authentication transfer",
}


# --------------------------------------------------------------------------- #
# Output models
# --------------------------------------------------------------------------- #

class Ref(BaseModel):
    """A user/group/role/app/location reference resolved to something readable."""
    id: str
    name: str | None = None
    detail: str | None = None  # e.g. "142 members", "no longer exists"

    @property
    def label(self) -> str:
        base = self.name or self.id
        return f"{base} ({self.detail})" if self.detail else base


class Exclusions(BaseModel):
    users: list[Ref] = Field(default_factory=list)
    groups: list[Ref] = Field(default_factory=list)
    roles: list[Ref] = Field(default_factory=list)
    guests_or_external: bool = False
    applications: list[Ref] = Field(default_factory=list)
    locations: list[Ref] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)

    @property
    def has_principal_exclusions(self) -> bool:
        return bool(self.users or self.groups or self.roles or self.guests_or_external)


class Concern(BaseModel):
    code: str
    severity: Severity
    text: str
    remediation: str = ""
    evidence: dict = Field(default_factory=dict)


class PolicyProfile(BaseModel):
    policy_id: str
    name: str
    state: str
    created_at: datetime | None = None
    modified_at: datetime | None = None

    action: Literal["block", "grant", "session_only", "no_effect"]
    requirements: list[str] = Field(default_factory=list)
    requirement_logic: Literal["all", "any"] | None = None

    users: list[str] = Field(default_factory=list)          # who it includes
    applications: list[str] = Field(default_factory=list)   # what it protects
    conditions: list[str] = Field(default_factory=list)     # when it applies
    session_controls: list[str] = Field(default_factory=list)
    exclusions: Exclusions = Field(default_factory=Exclusions)

    tags: list[Tag] = Field(default_factory=list)
    concerns: list[Concern] = Field(default_factory=list)
    summary: str = ""

    # Facts used by tenant-level baseline checks
    all_users: bool = False
    all_apps: bool = False
    targets_azure_management: bool = False
    covers_guests: bool = False
    strict_mfa: bool = False        # MFA is actually mandatory (no OR-bypass)
    risk_based: bool = False
    narrowing: list[str] = Field(default_factory=list)  # conditions that shrink the scope
    covered_admin_role_ids: list[str] = Field(default_factory=list)

    @property
    def is_enforced(self) -> bool:
        return self.state == "enabled"

    @property
    def is_report_only(self) -> bool:
        return self.state == "enabledForReportingButNotEnforced"


# --------------------------------------------------------------------------- #
# Context: everything needed to resolve ids to names
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class CaContext:
    users: dict[str, User]
    groups: dict[str, GroupInfo]
    locations: dict[str, NamedLocation]
    role_names: dict[str, str]
    critical_role_ids: frozenset[str]
    cfg: AuditConfig
    now: datetime


def build_context(snapshot: TenantSnapshot, cfg: AuditConfig, now: datetime) -> CaContext:
    role_names = dict(CRITICAL_ADMIN_ROLES)
    for definition in snapshot.role_definitions or []:
        role_names[definition.id] = definition.display_name
    return CaContext(
        users={u.id: u for u in snapshot.users},
        groups={g.id: g for g in snapshot.ca_groups or []},
        locations={loc.id: loc for loc in snapshot.named_locations or []},
        role_names=role_names,
        critical_role_ids=frozenset(CRITICAL_ADMIN_ROLES),
        cfg=cfg,
        now=now,
    )


# --------------------------------------------------------------------------- #
# Reference resolution
# --------------------------------------------------------------------------- #

def _user_ref(uid: str, ctx: CaContext) -> Ref:
    user = ctx.users.get(uid)
    name = (user.user_principal_name or user.display_name) if user else None
    return Ref(id=uid, name=name, detail=None if user else "unresolved: deleted?")


def _group_ref(gid: str, ctx: CaContext) -> Ref:
    group = ctx.groups.get(gid)
    if group is None:
        return Ref(id=gid)
    if not group.exists:
        return Ref(id=gid, detail="group no longer exists")
    detail = None
    if group.member_count is not None:
        detail = f"{group.member_count}{'+' if group.member_count_is_lower_bound else ''} members"
    return Ref(id=gid, name=group.display_name, detail=detail)


def _role_ref(rid: str, ctx: CaContext) -> Ref:
    return Ref(id=rid, name=ctx.role_names.get(rid))


def _app_label(app_id: str) -> str:
    return _APP_LABELS.get(app_id, f"App {app_id}")


def _loc_label(loc_id: str, ctx: CaContext) -> str:
    if loc_id == "All":
        return "any location"
    if loc_id == "AllTrusted":
        return "all trusted locations"
    loc = ctx.locations.get(loc_id)
    if loc is None:
        return f"location {loc_id}"
    if loc.kind == "ip":
        trust = "trusted" if loc.is_trusted else "untrusted"
        return f"{loc.display_name} ({trust} IP ranges)"
    if loc.kind == "country":
        shown = ", ".join(loc.countries[:5]) + ("..." if len(loc.countries) > 5 else "")
        return f"{loc.display_name} (countries: {shown})"
    return loc.display_name


def _join(items: list[str], limit: int = 5) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f" +{len(items) - limit} more" if len(items) > limit else "")


# --------------------------------------------------------------------------- #
# Describers (each returns text plus the facts the checks need)
# --------------------------------------------------------------------------- #

def _describe_users(p: ConditionalAccessPolicy, ctx: CaContext) -> tuple[list[str], bool, bool]:
    """Returns (descriptions, targets_all_users, guests_are_included)."""
    parts: list[str] = []
    all_users = "All" in p.include_users
    guests_listed = "GuestsOrExternalUsers" in p.include_users or p.includes_guests_or_external
    if all_users:
        parts.append("All users")
    if guests_listed:
        kinds = f" ({', '.join(p.include_guest_types)})" if p.include_guest_types else ""
        parts.append(f"Guest and external users{kinds}")
    user_ids = [u for u in p.include_users if u not in ("All", "None", "GuestsOrExternalUsers")]
    if user_ids:
        parts.append(f"{len(user_ids)} user(s): {_join([_user_ref(u, ctx).label for u in user_ids])}")
    if p.include_groups:
        parts.append(
            f"{len(p.include_groups)} group(s): "
            f"{_join([_group_ref(g, ctx).label for g in p.include_groups])}"
        )
    if p.include_roles:
        parts.append(
            f"{len(p.include_roles)} directory role(s): "
            f"{_join([_role_ref(r, ctx).label for r in p.include_roles])}"
        )
    if p.include_service_principals:
        what = ("all owned service principals" if "ServicePrincipalsInMyTenant" in p.include_service_principals
                else f"{len(p.include_service_principals)} service principal(s)")
        parts.append(f"Workload identities: {what}")
    if not parts:
        parts.append("No users")
    return parts, all_users, all_users or guests_listed


def _describe_apps(p: ConditionalAccessPolicy) -> tuple[list[str], bool, bool]:
    """Returns (descriptions, targets_all_apps, targets_azure_management)."""
    parts = [_app_label(a) for a in p.include_applications if a != "None"]
    parts += [f"User action: {_USER_ACTIONS.get(a, a)}" for a in p.include_user_actions]
    parts += [f"Authentication context {c}" for c in p.include_auth_contexts]
    all_apps = "All" in p.include_applications
    azure = (all_apps or AZURE_MANAGEMENT_APP_ID in p.include_applications) and \
        AZURE_MANAGEMENT_APP_ID not in p.exclude_applications
    return parts or ["No apps"], all_apps, azure


def _describe_conditions(
    p: ConditionalAccessPolicy, ctx: CaContext
) -> tuple[list[str], list[str], bool]:
    """Returns (descriptions, narrowing_reasons, risk_based)."""
    out: list[str] = []
    narrowing: list[str] = []

    kinds = [c for c in p.client_app_types if c != "all"]
    if kinds:
        out.append("Client apps: " + ", ".join(_CLIENT_LABELS.get(c, c) for c in kinds))
        if not _MODERN_TYPES <= set(kinds) and not set(kinds) <= _LEGACY_TYPES:
            narrowing.append("client app types")

    if (p.include_platforms and "all" not in p.include_platforms) or p.exclude_platforms:
        text = ("Platforms: " + ", ".join(p.include_platforms)
                if p.include_platforms and "all" not in p.include_platforms else "Any platform")
        if p.exclude_platforms:
            text += " except " + ", ".join(p.exclude_platforms)
        out.append(text)
        narrowing.append("platforms")

    if p.include_locations or p.exclude_locations:
        included = ("any location" if not p.include_locations or p.include_locations == ["All"]
                    else ", ".join(_loc_label(x, ctx) for x in p.include_locations))
        text = f"Location: {included}"
        if p.exclude_locations:
            text += " except " + ", ".join(_loc_label(x, ctx) for x in p.exclude_locations)
        out.append(text)
        if p.exclude_locations or (p.include_locations and p.include_locations != ["All"]):
            narrowing.append("locations")

    if p.device_filter_rule:
        out.append(f"Device filter ({p.device_filter_mode or 'include'}): {p.device_filter_rule}")
        narrowing.append("device filter")

    risk_based = False
    for label, levels in (
        ("Sign-in risk", p.sign_in_risk_levels),
        ("User risk", p.user_risk_levels),
        ("Service principal risk", p.service_principal_risk_levels),
        ("Insider risk", p.insider_risk_levels),
    ):
        if levels:
            out.append(f"{label}: {', '.join(levels)}")
            risk_based = True

    if p.authentication_flows:
        out.append("Authentication flows: " +
                   ", ".join(_FLOW_LABELS.get(f, f) for f in p.authentication_flows))
        narrowing.append("authentication flows")

    return out, narrowing, risk_based


def _describe_requirements(p: ConditionalAccessPolicy) -> tuple[list[str], Literal["all", "any"] | None]:
    reqs = [_REQUIREMENT_LABELS.get(c, c) for c in p.grant_controls]
    if p.authentication_strength_id:
        reqs.append("Require authentication strength: "
                    f"{p.authentication_strength_name or p.authentication_strength_id}")
    if p.terms_of_use:
        reqs.append("Require terms of use")
    reqs += [f"Custom control: {c}" for c in p.custom_controls]
    if len(reqs) < 2:
        return reqs, None
    return reqs, "all" if p.grant_operator == "AND" else "any"


def _describe_session(p: ConditionalAccessPolicy) -> list[str]:
    s = p.session_controls
    out: list[str] = []
    freq = s.get("signInFrequency") or {}
    if freq.get("isEnabled"):
        if freq.get("frequencyInterval") == "everyTime":
            out.append("Sign-in frequency: every time")
        else:
            out.append(f"Sign-in frequency: every {freq.get('value')} {freq.get('type')}")
    browser = s.get("persistentBrowser") or {}
    if browser.get("isEnabled"):
        out.append(f"Persistent browser session: {browser.get('mode')}")
    if (s.get("applicationEnforcedRestrictions") or {}).get("isEnabled"):
        out.append("Use app-enforced restrictions")
    mdca = s.get("cloudAppSecurity") or {}
    if mdca.get("isEnabled"):
        out.append(f"Conditional Access App Control ({mdca.get('cloudAppSecurityType')})")
    cae = (s.get("continuousAccessEvaluation") or {}).get("mode")
    if cae:
        out.append(f"Continuous access evaluation: {cae}")
    if s.get("disableResilienceDefaults"):
        out.append("Resilience defaults disabled")
    return out


def _build_exclusions(p: ConditionalAccessPolicy, ctx: CaContext) -> Exclusions:
    return Exclusions(
        users=[_user_ref(u, ctx) for u in p.exclude_users],
        groups=[_group_ref(g, ctx) for g in p.exclude_groups],
        roles=[_role_ref(r, ctx) for r in p.exclude_roles],
        guests_or_external=p.excludes_guests_or_external,
        applications=[Ref(id=a, name=_app_label(a)) for a in p.exclude_applications],
        locations=[Ref(id=x, name=_loc_label(x, ctx)) for x in p.exclude_locations],
        platforms=list(p.exclude_platforms),
    )


def _strict_mfa(p: ConditionalAccessPolicy) -> bool:
    """MFA is truly mandatory: it's the only control, or all controls are ANDed."""
    if p.blocks_access or not p.requires_mfa:
        return False
    total = (len(p.grant_controls) + (1 if p.authentication_strength_id else 0)
             + len(p.terms_of_use) + len(p.custom_controls))
    return total == 1 or p.grant_operator == "AND"


def _covered_admin_roles(p: ConditionalAccessPolicy, all_users: bool, ctx: CaContext) -> list[str]:
    base = set(ctx.critical_role_ids) if all_users else set(p.include_roles) & ctx.critical_role_ids
    return sorted(base - set(p.exclude_roles))


# --------------------------------------------------------------------------- #
# Tags
# --------------------------------------------------------------------------- #

def _tags(p: ConditionalAccessPolicy, prof: PolicyProfile) -> list[Tag]:
    tags: list[Tag] = []
    kinds = set(p.client_app_types) - {"all"}
    legacy_only = bool(kinds) and kinds <= _LEGACY_TYPES
    guests_listed = "GuestsOrExternalUsers" in p.include_users or p.includes_guests_or_external

    if prof.action == "block":
        if legacy_only:
            tags.append(Tag.BLOCK_LEGACY_AUTH)
        if "deviceCodeFlow" in p.authentication_flows:
            tags.append(Tag.BLOCK_DEVICE_CODE)
        if p.include_locations or p.exclude_locations:
            tags.append(Tag.BLOCK_BY_LOCATION)
        if p.include_platforms and "all" not in p.include_platforms:
            tags.append(Tag.BLOCK_BY_PLATFORM)
        if guests_listed and not prof.all_users:
            tags.append(Tag.BLOCK_GUESTS)
        if prof.all_users and prof.all_apps and not prof.conditions:
            tags.append(Tag.BLOCK_ALL_ACCESS)

    if prof.strict_mfa:
        if prof.all_users and prof.all_apps and not prof.narrowing and not prof.risk_based:
            tags.append(Tag.MFA_ALL_USERS)
        if prof.covered_admin_role_ids:
            tags.append(Tag.MFA_ADMINS)
        if prof.covers_guests:
            tags.append(Tag.MFA_GUESTS)
        if prof.all_users and prof.targets_azure_management:
            tags.append(Tag.MFA_AZURE_MANAGEMENT)

    if p.authentication_strength_id:
        tags.append(Tag.AUTH_STRENGTH)
    for control, tag in (
        ("compliantDevice", Tag.REQUIRE_COMPLIANT_DEVICE),
        ("domainJoinedDevice", Tag.REQUIRE_MANAGED_DEVICE),
        ("compliantApplication", Tag.REQUIRE_APP_PROTECTION),
        ("approvedApplication", Tag.REQUIRE_APPROVED_APP),
        ("passwordChange", Tag.PASSWORD_CHANGE),
    ):
        if control in p.grant_controls:
            tags.append(tag)
    if p.terms_of_use:
        tags.append(Tag.TERMS_OF_USE)
    if p.sign_in_risk_levels:
        tags.append(Tag.SIGNIN_RISK)
    if p.user_risk_levels:
        tags.append(Tag.USER_RISK)
    if p.insider_risk_levels:
        tags.append(Tag.INSIDER_RISK)
    if p.include_service_principals:
        tags.append(Tag.WORKLOAD_IDENTITY)
    if "urn:user:registersecurityinfo" in p.include_user_actions:
        tags.append(Tag.SECURITY_INFO_REGISTRATION)
    if "urn:user:registerdevice" in p.include_user_actions:
        tags.append(Tag.DEVICE_REGISTRATION)

    s = p.session_controls
    if (s.get("signInFrequency") or {}).get("isEnabled"):
        tags.append(Tag.SESSION_SIGNIN_FREQUENCY)
    if (s.get("persistentBrowser") or {}).get("isEnabled"):
        tags.append(Tag.SESSION_PERSISTENT_BROWSER)
    if (s.get("cloudAppSecurity") or {}).get("isEnabled"):
        tags.append(Tag.SESSION_APP_CONTROL)
    if (s.get("applicationEnforcedRestrictions") or {}).get("isEnabled"):
        tags.append(Tag.SESSION_APP_RESTRICTIONS)
    if (s.get("continuousAccessEvaluation") or {}).get("mode"):
        tags.append(Tag.SESSION_CAE)
    return tags


# --------------------------------------------------------------------------- #
# Concerns: weaknesses in a single policy
# --------------------------------------------------------------------------- #

def _concerns(p: ConditionalAccessPolicy, prof: PolicyProfile, ctx: CaContext) -> list[Concern]:
    out: list[Concern] = []
    cfg = ctx.cfg

    def add(code: str, severity: Severity, text: str, remediation: str = "", **evidence: object) -> None:
        out.append(Concern(code=code, severity=severity, text=text,
                           remediation=remediation, evidence=evidence))

    if p.state == "disabled":
        add("POLICY_DISABLED", "info", "Policy is disabled and has no effect",
            "Delete it if obsolete, or enable it (via report-only first) if it is still wanted.")
        return out

    if prof.is_report_only:
        stamp = aware(p.modified_at or p.created_at)
        age = (ctx.now - stamp).days if stamp else None
        stale = age is not None and age > cfg.report_only_stale_days
        add("POLICY_REPORT_ONLY", "medium" if stale else "low",
            "Policy is report-only: it logs what it would do but enforces nothing"
            + (f" (unchanged for {age} days)" if age is not None else ""),
            "Review the report-only impact in the sign-in logs, then switch the policy to On.",
            days_unchanged=age)

    if prof.action == "no_effect":
        add("POLICY_NO_EFFECT", "low", "Policy has no grant or session controls, so it does nothing",
            "Add a grant/block control or a session control, or remove the policy.")

    if p.include_users in ([], ["None"]) and not (
        p.include_groups or p.include_roles or p.includes_guests_or_external
        or p.include_service_principals
    ):
        add("POLICY_TARGETS_NOBODY", "low", "Policy targets no users, groups or roles",
            "Assign the intended users/groups or delete the policy.")

    relevant = prof.action in ("block", "grant")
    ex = prof.exclusions
    critical_excluded = [r for r in p.exclude_roles if r in ctx.critical_role_ids]

    if relevant and ex.users:
        n = len(ex.users)
        add("EXCLUDES_USERS", "low" if n <= 2 else "medium",
            f"Excludes {n} individual user(s): {_join([u.label for u in ex.users])}",
            "Limit user exclusions to monitored break-glass accounts; use a governed group otherwise.",
            users=[u.model_dump() for u in ex.users])
        orphans = [u for u in ex.users if u.name is None] if ctx.users else []
        if orphans:
            add("ORPHANED_EXCLUSIONS", "low",
                f"{len(orphans)} excluded user ID(s) match no user in the tenant (deleted accounts?)",
                "Remove stale IDs from the exclusion list.", ids=[u.id for u in orphans])

    if relevant and ex.groups:
        severity: Severity = "low"
        for gid in p.exclude_groups:
            g = ctx.groups.get(gid)
            if g is None or (g.exists and g.member_count is None):
                severity = highest(severity, "medium")
            elif g.exists and (g.member_count or 0) >= cfg.large_exclusion_group:
                severity = highest(severity, "high")
            elif g.exists:
                severity = highest(severity, "medium")
        add("EXCLUDES_GROUPS", severity,
            f"Excludes {len(ex.groups)} group(s): {_join([g.label for g in ex.groups])}",
            "Keep exclusion groups small and governed (access reviews, no self-service join).",
            groups=[g.model_dump() for g in ex.groups])

    if relevant and p.exclude_roles:
        add("EXCLUDES_ADMIN_ROLES", "high" if critical_excluded else "medium",
            f"Excludes directory role(s): {_join([r.label for r in ex.roles])}",
            "Administrators need protection most; remove role exclusions.",
            roles=[r.model_dump() for r in ex.roles])

    if relevant and ex.guests_or_external:
        add("EXCLUDES_GUESTS", "medium" if (prof.strict_mfa or prof.action == "block") else "low",
            "Excludes guest and external users",
            "Cover guests with this or a dedicated policy.")

    if relevant and prof.all_apps and ex.applications:
        add("EXCLUDES_APPS", "medium" if (prof.strict_mfa or prof.action == "block") else "low",
            f"Applies to all apps except: {_join([a.label for a in ex.applications])}",
            "Every excluded app is reachable without this control; keep exclusions minimal and justified.",
            apps=[a.model_dump() for a in ex.applications])

    if prof.strict_mfa is False and p.requires_mfa and prof.action == "grant":
        others = [_REQUIREMENT_LABELS.get(c, c) for c in p.grant_controls if c != "mfa"]
        if others:
            device_only = set(p.grant_controls) - {"mfa"} <= {"compliantDevice", "domainJoinedDevice"}
            add("MFA_BYPASSABLE", "low" if device_only else "medium",
                "MFA is not mandatory: users can satisfy an alternative instead (" + _join(others) + ")",
                "Use 'Require all selected controls' if MFA must always apply.",
                alternatives=others)

    if prof.strict_mfa:
        trusted_excluded = [
            x for x in p.exclude_locations
            if x == "AllTrusted" or (ctx.locations.get(x) and ctx.locations[x].is_trusted)
        ]
        if trusted_excluded:
            add("MFA_SKIPPED_FROM_TRUSTED_LOCATIONS", "medium",
                "MFA is skipped from trusted locations; network location alone is weak proof of identity",
                "Prefer requiring MFA everywhere (Zero Trust) or add device-based signals.",
                locations=[_loc_label(x, ctx) for x in trusted_excluded])
        if prof.narrowing and not prof.risk_based:
            add("MFA_NARROW_SCOPE", "low",
                "MFA only applies under certain conditions: " + ", ".join(prof.narrowing),
                "Confirm a separate policy covers the situations this one skips.",
                narrowing=prof.narrowing)

    if "approvedApplication" in p.grant_controls:
        add("DEPRECATED_CONTROL", "low",
            "Uses 'Require approved client app', which Microsoft has deprecated",
            "Migrate to 'Require app protection policy'.")

    if prof.action == "block" and Tag.BLOCK_ALL_ACCESS in prof.tags:
        if ex.has_principal_exclusions:
            add("BLOCKS_EVERYTHING", "medium",
                "Blocks all users from all apps with no conditions; the exclusions are the only way in",
                "Verify exclusions are exactly your monitored break-glass accounts.")
        else:
            add("BLOCKS_EVERYTHING", "high",
                "Blocks all users from all apps with no conditions and no exclusions (lockout risk)",
                "Confirm this is intended and that break-glass accounts are excluded.")
    return out


# --------------------------------------------------------------------------- #
# Summary sentence
# --------------------------------------------------------------------------- #

def _summary(prof: PolicyProfile) -> str:
    lead = {
        "block": "BLOCK access",
        "grant": "REQUIRE " + (" OR ".join(prof.requirements) if prof.requirement_logic == "any"
                               else " AND ".join(prof.requirements)),
        "session_only": "APPLY session controls (" + ", ".join(prof.session_controls) + ")",
        "no_effect": "Does nothing (no grant or session controls)",
    }[prof.action]

    who = "; ".join(prof.users)
    ex = prof.exclusions
    bits = []
    if ex.users:
        bits.append(f"{len(ex.users)} user(s)")
    if ex.groups:
        bits.append("group " + _join([g.label for g in ex.groups], 3))
    if ex.roles:
        bits.append("role " + _join([r.label for r in ex.roles], 3))
    if ex.guests_or_external:
        bits.append("guests/external users")
    if bits:
        who += f" (except {'; '.join(bits)})"

    what = "; ".join(prof.applications)
    if ex.applications:
        what += f" (except {_join([a.label for a in ex.applications], 3)})"

    when = f" when {' and '.join(prof.conditions)}" if prof.conditions else ""
    session = (f" Session: {', '.join(prof.session_controls)}."
               if prof.session_controls and prof.action != "session_only" else "")
    return f"{lead} for {who} accessing {what}{when}.{session}"


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def analyze_policy(p: ConditionalAccessPolicy, ctx: CaContext) -> PolicyProfile:
    users, all_users, guests_in = _describe_users(p, ctx)
    apps, all_apps, azure = _describe_apps(p)
    conditions, narrowing, risk_based = _describe_conditions(p, ctx)
    session = _describe_session(p)
    requirements, logic = _describe_requirements(p)

    if p.blocks_access:
        action = "block"
    elif requirements:
        action = "grant"
    elif session:
        action = "session_only"
    else:
        action = "no_effect"

    prof = PolicyProfile(
        policy_id=p.id, name=p.display_name, state=p.state,
        created_at=p.created_at, modified_at=p.modified_at,
        action=action,
        requirements=requirements if action != "block" else ["Block access"],
        requirement_logic=logic if action == "grant" else None,
        users=users, applications=apps, conditions=conditions, session_controls=session,
        exclusions=_build_exclusions(p, ctx),
        all_users=all_users, all_apps=all_apps, targets_azure_management=azure,
        covers_guests=guests_in and not p.excludes_guests_or_external,
        strict_mfa=_strict_mfa(p), risk_based=risk_based, narrowing=narrowing,
        covered_admin_role_ids=_covered_admin_roles(p, all_users, ctx),
    )
    prof.tags = _tags(p, prof)
    prof.concerns = _concerns(p, prof, ctx)
    prof.summary = _summary(prof)
    return prof


def analyze_policies(snapshot: TenantSnapshot, cfg: AuditConfig, now: datetime) -> list[PolicyProfile]:
    """Profiles for every CA policy (empty list if none were collected)."""
    if not snapshot.ca_policies:
        return []
    ctx = build_context(snapshot, cfg, now)
    return [analyze_policy(p, ctx) for p in snapshot.ca_policies]