"""Small builders so check tests state only what matters to them."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from entra_auditor.checks._common import AuditConfig
from entra_auditor.models import (
    Application,
    ConditionalAccessPolicy,
    Credential,
    DirectoryGroup,
    MfaRegistration,
    RoleAssignment,
    ServicePrincipal,
    TenantSnapshot,
    User,
)

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
GA = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator role id


def ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


def later(days: float) -> datetime:
    return NOW + timedelta(days=days)


def user(uid="u1", upn=None, **kw) -> User:
    base = dict(id=uid, user_principal_name=upn or f"{uid}@contoso.com", user_type="Member",
                account_enabled=True, created_at=ago(1000))
    base.update(kw)
    return User(**base)


def role(pid="u1", *, role_id=GA, name="Global Administrator", state="active", ptype="user", **kw) -> RoleAssignment:
    base = dict(principal_id=pid, principal_type=ptype, principal_upn=f"{pid}@contoso.com", role_id=role_id,
                role_name=name, is_privileged_role=True, state=state)
    base.update(kw)
    return RoleAssignment(**base)


def mfa(uid="u1", *, registered=True, capable=True, methods=("microsoftAuthenticatorPush",)) -> MfaRegistration:
    return MfaRegistration(user_id=uid, is_mfa_registered=registered, is_mfa_capable=capable,
                           methods_registered=list(methods))


def policy(pid="p1", name=None, state="enabled", **kw) -> ConditionalAccessPolicy:
    return ConditionalAccessPolicy(id=pid, display_name=name or f"Policy {pid}", state=state, **kw)


def cred(kind="secret", *, start=None, end=None, key="k1", name=None) -> Credential:
    return Credential(kind=kind, key_id=key, display_name=name, start=start, end=end)


def app(aid="a1", **kw) -> Application:
    return Application(**{**dict(id=aid, app_id=f"app-{aid}", display_name=f"App {aid}", owner_count=1), **kw})


def sp(sid="s1", **kw) -> ServicePrincipal:
    base = dict(id=sid, app_id=f"app-{sid}", display_name=f"SP {sid}", account_enabled=True,
                created_at=ago(1000), service_principal_type="Application", app_owner_organization_id="tenant")
    base.update(kw)
    return ServicePrincipal(**base)


def group(gid="g1", **kw) -> DirectoryGroup:
    base = dict(id=gid, display_name=f"Group {gid}", security_enabled=True, created_at=ago(900),
                owner_count=1, user_member_count=3)
    base.update(kw)
    return DirectoryGroup(**base)


def snapshot(**kw) -> TenantSnapshot:
    return TenantSnapshot(**{**dict(tenant_id="tenant", collected_at=NOW), **kw})


def cfg(**kw) -> AuditConfig:
    return AuditConfig(**kw)


def ids(findings) -> list[str]:
    return [f.check_id for f in findings]


def only(findings, check_id):
    """The single finding with this check id (fails if there isn't exactly one)."""
    found = [f for f in findings if f.check_id == check_id]
    assert len(found) == 1, f"expected exactly one {check_id}, got {ids(findings)}"
    return found[0]


def make_run(findings=(), policies=(), *, started_at=None, run_id="run-1", status=None, checks=("inactive",), **kw):
    """An AuditRun without running an audit."""
    from entra_auditor.engine import AuditRun, RunStatus

    started = started_at or NOW
    return AuditRun(id=run_id, tenant_id="tenant", status=status or RunStatus.COMPLETED, started_at=started,
                    finished_at=started, checks=list(checks), findings=list(findings), policies=list(policies), **kw)


def finding(check_id="INACTIVE_USER", severity="low", rid="u1", **kw):
    from entra_auditor.models import Finding

    base = dict(check_id=check_id, severity=severity, resource_type="user", resource_id=rid,
                resource_name=f"{rid}@contoso.com", title=f"{rid}: {check_id}", remediation="fix it")
    base.update(kw)
    return Finding(**base)
