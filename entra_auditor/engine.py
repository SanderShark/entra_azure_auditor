"""Audit engine: collect tenant data, run the selected checks, produce an ``AuditRun``.

Two entry points:

``run_audit(graph, tenant_id, ...)``   talks to Graph, then analyses. Never raises for
                                       Graph/auth failures; returns a run with status
                                       ``failed`` and the error message instead, which is
                                       what a background API task or the CLI wants.
``analyze_snapshot(snapshot, ...)``    pure analysis of an already-collected snapshot
                                       (no network), used by tests and offline re-analysis.

Resilience: a bug in one check never sinks the others. The crash is recorded as a
warning and the run is marked ``partial``.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Callable, Iterable

from pydantic import BaseModel, Field

from .checks import CHECKS, sort_findings
from .checks._common import SEVERITY_ORDER, AuditConfig
from .checks.ca_analysis import PolicyProfile, analyze_policies
from .models import Finding, Severity, TenantSnapshot

if TYPE_CHECKING:  # heavy/optional deps are imported lazily so analysis works without them
    from .graph.client import GraphClient

log = logging.getLogger(__name__)

# Which collector sections each check needs (users are always collected).
CHECK_SECTIONS: dict[str, set[str]] = {
    "inactive": set(),
    "privileged": {"roles", "mfa"},
    "mfa_ca": {"ca", "mfa", "role_defs"},
    "stale_apps": {"apps"},
    "groups": {"groups", "ca"},  # "ca" so groups used by Conditional Access count as in use
}

# Graph permissions each check reads (same names for application and delegated access).
REQUIRED_PERMISSIONS: dict[str, set[str]] = {
    "inactive": {"User.Read.All", "AuditLog.Read.All"},
    "privileged": {
        "User.Read.All", "RoleManagement.Read.Directory", "RoleEligibilitySchedule.Read.Directory",
        "RoleAssignmentSchedule.Read.Directory", "Group.Read.All", "Reports.Read.All",
        "AuditLog.Read.All",
    },
    "mfa_ca": {
        "User.Read.All", "Policy.Read.All", "Reports.Read.All", "AuditLog.Read.All",
        "Group.Read.All", "RoleManagement.Read.Directory",
    },
    "stale_apps": {"Application.Read.All", "AuditLog.Read.All"},
    "groups": {"Group.Read.All", "Directory.Read.All", "Policy.Read.All"},
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #

class RunStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"    # finished, but at least one check crashed
    FAILED = "failed"      # could not collect data (auth/Graph failure)


class RunSummary(BaseModel):
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_check: dict[str, int] = Field(default_factory=dict)
    highest_severity: Severity | None = None


class AuditRun(BaseModel):
    id: str
    tenant_id: str
    identity: str = ""                       # who ran it: "app:<client id>" or "user:<upn>"
    status: RunStatus
    started_at: datetime
    finished_at: datetime
    checks: list[str] = Field(default_factory=list)
    config: dict = Field(default_factory=dict)
    inventory: dict[str, int | None] = Field(default_factory=dict)  # None = not collected
    findings: list[Finding] = Field(default_factory=list)
    policies: list[PolicyProfile] = Field(default_factory=list)     # readable CA policy profiles
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def summary(self) -> RunSummary:
        by_severity = {s: 0 for s in reversed(SEVERITY_ORDER)}  # critical .. info, always present
        by_check: dict[str, int] = {}
        for f in self.findings:
            by_severity[f.severity] += 1
            by_check[f.check_id] = by_check.get(f.check_id, 0) + 1
        present = [s for s in reversed(SEVERITY_ORDER) if by_severity[s]]
        return RunSummary(
            total=len(self.findings),
            by_severity=by_severity,
            by_check=dict(sorted(by_check.items(), key=lambda kv: (-kv[1], kv[0]))),
            highest_severity=present[0] if present else None,
        )

    def findings_at_or_above(self, severity: Severity) -> list[Finding]:
        floor = SEVERITY_ORDER.index(severity)
        return [f for f in self.findings if SEVERITY_ORDER.index(f.severity) >= floor]


class SeverityChange(BaseModel):
    fingerprint: str
    title: str
    old: Severity
    new: Severity


class RunDiff(BaseModel):
    """What changed between two runs, matched on ``Finding.fingerprint``."""
    new: list[Finding] = Field(default_factory=list)
    resolved: list[Finding] = Field(default_factory=list)
    persisting: list[Finding] = Field(default_factory=list)
    severity_changed: list[SeverityChange] = Field(default_factory=list)
    checks_differ: bool = False  # if True, "new"/"resolved" may just reflect different checks run


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def resolve_checks(selection: Iterable[str] | str | None) -> list[str]:
    """Normalise a selection (``None``, ``"all"``, ``"a,b"`` or a list) to check names."""
    if selection is None:
        return list(CHECKS)
    if isinstance(selection, str):
        selection = selection.split(",")
    names = [n.strip() for n in selection if n.strip()]
    if not names or "all" in names:
        return list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        raise ValueError(f"Unknown check(s): {', '.join(unknown)}. Available: {', '.join(CHECKS)}")
    return [n for n in CHECKS if n in names]  # canonical order, de-duplicated


def required_permissions(checks: Iterable[str]) -> set[str]:
    return set().union(*(REQUIRED_PERMISSIONS[c] for c in checks)) if checks else set()


def _inventory(snapshot: TenantSnapshot) -> dict[str, int | None]:
    def count(items: list | None) -> int | None:
        return None if items is None else len(items)

    return {
        "users": len(snapshot.users),
        "enabled_users": sum(1 for u in snapshot.users if u.account_enabled is not False),
        "guests": sum(1 for u in snapshot.users if u.is_guest),
        "role_assignments": count(snapshot.role_assignments),
        "conditional_access_policies": count(snapshot.ca_policies),
        "applications": count(snapshot.applications),
        "service_principals": count(snapshot.service_principals),
        "groups": count(snapshot.groups),
    }


def _dedupe(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


# --------------------------------------------------------------------------- #
# Analysis (no network)
# --------------------------------------------------------------------------- #

def analyze_snapshot(
    snapshot: TenantSnapshot,
    *,
    cfg: AuditConfig | None = None,
    checks: Iterable[str] | str | None = None,
    identity: str = "",
    started_at: datetime | None = None,
    run_id: str | None = None,
    progress: Callable[[str], None] | None = None,
    clock: Callable[[], datetime] = utcnow,
) -> AuditRun:
    cfg = cfg or AuditConfig()
    names = resolve_checks(checks)
    started = started_at or clock()
    say = progress or (lambda _msg: None)
    # Ages are measured against when the data was collected, so re-analysing a
    # saved snapshot gives the same answer as it did on the day.
    now = snapshot.collected_at

    findings: list[Finding] = []
    warnings = list(snapshot.warnings)
    crashed = False

    for name in names:
        say(f"Running check: {name}")
        try:
            findings.extend(CHECKS[name](snapshot, now, cfg))
        except Exception as exc:  # noqa: BLE001 - isolate check failures on purpose
            crashed = True
            log.exception("check %s crashed", name)
            warnings.append(f"check '{name}' crashed and was skipped: {type(exc).__name__}: {exc}")

    policies: list[PolicyProfile] = []
    if "mfa_ca" in names:
        try:
            policies = analyze_policies(snapshot, cfg, now)
        except Exception as exc:  # noqa: BLE001
            crashed = True
            log.exception("CA policy analysis crashed")
            warnings.append(f"CA policy analysis crashed: {type(exc).__name__}: {exc}")

    return AuditRun(
        id=run_id or str(uuid.uuid4()),
        tenant_id=snapshot.tenant_id,
        identity=identity,
        status=RunStatus.PARTIAL if crashed else RunStatus.COMPLETED,
        started_at=started,
        finished_at=clock(),
        checks=names,
        config=asdict(cfg),
        inventory=_inventory(snapshot),
        findings=sort_findings(findings),
        policies=policies,
        warnings=_dedupe(warnings),
    )


# --------------------------------------------------------------------------- #
# Full audit (collect + analyse)
# --------------------------------------------------------------------------- #

def run_audit(
    graph: "GraphClient",
    tenant_id: str,
    *,
    cfg: AuditConfig | None = None,
    checks: Iterable[str] | str | None = None,
    identity: str = "",
    progress: Callable[[str], None] | None = None,
    clock: Callable[[], datetime] = utcnow,
) -> AuditRun:
    """Collect from Graph and run the checks. Auth/Graph failures yield a ``failed`` run."""
    from .auth import AuthenticationError
    from .graph.client import GraphError
    from .graph.collectors import TenantCollector

    cfg = cfg or AuditConfig()
    names = resolve_checks(checks)
    started = clock()
    run_id = str(uuid.uuid4())
    sections = set().union(*(CHECK_SECTIONS[n] for n in names))

    try:
        snapshot = TenantCollector(graph, progress=progress).collect(tenant_id, sections)
    except (GraphError, AuthenticationError) as exc:
        log.info("collection failed: %s", exc)
        return AuditRun(
            id=run_id, tenant_id=tenant_id, identity=identity, status=RunStatus.FAILED,
            started_at=started, finished_at=clock(), checks=names, config=asdict(cfg),
            error=f"{type(exc).__name__}: {exc}",
        )

    return analyze_snapshot(
        snapshot, cfg=cfg, checks=names, identity=identity, started_at=started,
        run_id=run_id, progress=progress, clock=clock,
    )


# --------------------------------------------------------------------------- #
# Diffing
# --------------------------------------------------------------------------- #

def diff_runs(old: AuditRun, new: AuditRun) -> RunDiff:
    """New, resolved and persisting findings between two runs, by fingerprint."""
    old_by = {f.fingerprint: f for f in old.findings}
    new_by = {f.fingerprint: f for f in new.findings}

    changed = [
        SeverityChange(fingerprint=fp, title=f.title, old=old_by[fp].severity, new=f.severity)
        for fp, f in new_by.items()
        if fp in old_by and old_by[fp].severity != f.severity
    ]
    return RunDiff(
        new=sort_findings(f for fp, f in new_by.items() if fp not in old_by),
        resolved=sort_findings(f for fp, f in old_by.items() if fp not in new_by),
        persisting=sort_findings(f for fp, f in new_by.items() if fp in old_by),
        severity_changed=changed,
        checks_differ=set(old.checks) != set(new.checks),
    )
