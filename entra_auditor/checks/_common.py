"""Shared config, constants and helpers for checks.

Every check has the signature ``(snapshot, now, cfg) -> list[Finding]`` and is a
pure function: no network, no database, no ``datetime.now()`` (``now`` is passed
in so tests are deterministic).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Sequence, TypeVar

from ..models import Finding, Severity, TenantSnapshot

T = TypeVar("T")


@dataclass(frozen=True)
class AuditConfig:
    inactive_days: int = 90
    guest_inactive_days: int = 60          # guests: stricter
    admin_inactive_days: int = 45          # admins: strictest
    max_global_admins: int = 5             # Microsoft recommends fewer than 5
    min_global_admins: int = 2             # break-glass / bus-factor floor
    credential_warn_days: int = 30
    credential_urgent_days: int = 7
    long_lived_secret_days: int = 730
    sp_inactive_days: int = 90
    large_exclusion_group: int = 100       # excluded CA group at/above this size = high
    report_only_stale_days: int = 30       # report-only longer than this = "stuck"
    mfa_gap_medium_pct: float = 5.0
    mfa_gap_high_pct: float = 25.0
    max_roles_per_admin: int = 3           # more privileged roles than this = least-privilege smell
    pending_invite_days: int = 30          # guest invitation unaccepted this long = stale
    max_evidence_items: int = 100          # cap lists stored in evidence


Check = Callable[[TenantSnapshot, datetime, AuditConfig], list[Finding]]

# --------------------------------------------------------------------------- #
# Severity helpers
# --------------------------------------------------------------------------- #

SEVERITY_ORDER: list[Severity] = ["info", "low", "medium", "high", "critical"]


def lower(severity: Severity, steps: int = 1) -> Severity:
    return SEVERITY_ORDER[max(0, SEVERITY_ORDER.index(severity) - steps)]


def highest(*severities: Severity) -> Severity:
    return max(severities, key=SEVERITY_ORDER.index)


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #

def aware(dt: datetime | None) -> datetime | None:
    """Treat naive datetimes as UTC so comparisons never raise."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def older_than(now: datetime, then: datetime | None, days: int) -> bool:
    """True if ``then`` is strictly more than ``days`` days before ``now``."""
    then = aware(then)
    return then is not None and now - then > timedelta(days=days)


def days_ago(now: datetime, then: datetime | None) -> int | None:
    then = aware(then)
    return None if then is None else (now - then).days


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def cap(items: Sequence[T], limit: int) -> list[T]:
    return list(items[:limit])


# --------------------------------------------------------------------------- #
# Directory roles
# --------------------------------------------------------------------------- #

GLOBAL_ADMIN_ID = "62e90394-69f5-4237-9190-012177145e10"

# Roles Microsoft's "require MFA for administrators" template covers. Used both to
# decide "is this a privileged holder" (in addition to Microsoft's own isPrivileged
# flag) and as the yardstick for CA admin-MFA coverage.
CRITICAL_ADMIN_ROLES: dict[str, str] = {
    GLOBAL_ADMIN_ID: "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
}

# Roles that can take over the tenant or its identities; standing access to these
# is rated more severely.
TIER0_ROLE_IDS = frozenset({
    GLOBAL_ADMIN_ID,
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
})

# --------------------------------------------------------------------------- #
# Graph application permissions worth flagging on a service principal
# --------------------------------------------------------------------------- #

HIGH_PRIV_GRAPH_ROLES: dict[str, Severity] = {
    # Can escalate to Global Admin or rewrite the directory
    "RoleManagement.ReadWrite.Directory": "critical",
    "AppRoleAssignment.ReadWrite.All": "critical",
    "Application.ReadWrite.All": "critical",
    "Directory.ReadWrite.All": "critical",
    # Broad write access to identities, policy, data
    "User.ReadWrite.All": "high",
    "Group.ReadWrite.All": "high",
    "GroupMember.ReadWrite.All": "high",
    "UserAuthenticationMethod.ReadWrite.All": "high",
    "Policy.ReadWrite.ConditionalAccess": "high",
    "Mail.ReadWrite": "high",
    "Mail.Send": "high",
    "Files.ReadWrite.All": "high",
    "Sites.FullControl.All": "high",
    "Sites.ReadWrite.All": "high",
    "DeviceManagementManagedDevices.ReadWrite.All": "high",
    "DeviceManagementConfiguration.ReadWrite.All": "high",
    # Tenant-wide read
    "Directory.Read.All": "medium",
    "Mail.Read": "medium",
    "Files.Read.All": "medium",
    "Sites.Read.All": "medium",
}

# --------------------------------------------------------------------------- #
# Authentication methods
# --------------------------------------------------------------------------- #

# Methods that are phishable / SIM-swappable, or not real MFA at all (SSPR-only).
# An admin whose ONLY registered methods are these has weak protection.
WEAK_MFA_METHODS = frozenset({
    "mobilePhone", "alternateMobilePhone", "officePhone", "email", "securityQuestion",
})
