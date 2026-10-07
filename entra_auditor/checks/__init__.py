"""Check registry. The engine (and CLI ``--checks``) select checks by name."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from ..models import Finding, TenantSnapshot
from ._common import SEVERITY_ORDER, AuditConfig, Check
from .inactive_users import check_inactive_users
from .mfa_ca import check_mfa_ca
from .privileged import check_privileged
from .stale_apps import check_stale_apps
from .stale_groups import check_stale_groups

CHECKS: dict[str, Check] = {
    "inactive": check_inactive_users,
    "privileged": check_privileged,
    "mfa_ca": check_mfa_ca,
    "stale_apps": check_stale_apps,
    "groups": check_stale_groups,
}


def run_checks(
    snapshot: TenantSnapshot,
    now: datetime,
    cfg: AuditConfig | None = None,
    only: Iterable[str] | None = None,
) -> list[Finding]:
    """Run the selected checks (default: all) and return findings, worst first."""
    cfg = cfg or AuditConfig()
    names = list(only) if only is not None else list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        raise ValueError(f"Unknown check(s): {', '.join(unknown)}. Available: {', '.join(CHECKS)}")

    findings: list[Finding] = []
    for name in names:
        findings.extend(CHECKS[name](snapshot, now, cfg))
    return sort_findings(findings)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Worst severity first, then by check and resource name (stable, readable order)."""
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.index(f.severity), f.check_id, f.resource_name or f.resource_id),
    )


__all__ = ["CHECKS", "AuditConfig", "run_checks", "sort_findings"]
