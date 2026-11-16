"""Check what a sign-in can do in a tenant, and produce a report that is safe to share.

Built for the first live test: instead of finding out feature by feature that a permission or role is
missing, one run reads the signed-in token and tries one harmless read per feature.

    report = run_checks(graph, token)
    print(report.text())          # shareable: no names, ids, tenant or e-mail addresses

What is checked:
  * the token (decoded locally, signature not verified: it is our own token and only its claims are read):
    the delegated permissions it carries (``scp``) and the directory roles active when it was issued
    (``wids``), so "consented on the app registration but not requested at sign-in" can be confirmed live;
  * one read per feature, asking for a single item (``$top=1``) and keeping only the outcome: OK, DENIED
    (403), NOT FOUND (404), UNSUPPORTED (400) or another error, with Graph's error code and the time taken.
Nothing is written; reading a BitLocker key or a LAPS password is NOT attempted (only that keys can be listed).

The report deliberately leaves out everything identifying: the signed-in user, tenant name and id, object
ids, and Graph's error messages (they can contain names); it keeps permission names, role names, HTTP
statuses and Graph error codes.
"""

from __future__ import annotations

import base64
import itertools
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Sequence

from .. import __version__
from ..graph.client import GraphAuthError, GraphError
from . import group_pim, pim
from .devices import BITLOCKER_PATH

# Permissions the toolkit uses but deliberately does NOT request at sign-in (an unconsented scope there breaks
# every sign-in): they only work if an admin consented them and Entra includes them in the token anyway.
OPTIONAL_PERMISSIONS = {
    "PrivilegedEligibilitySchedule.Read.AzureADGroup": "PIM for Groups: see eligible group memberships",
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup": "PIM for Groups: activate group memberships",
    "AdministrativeUnit.ReadWrite.All": "change administrative units",
    "Member.Read.Hidden": "list members of hidden-membership units",
    "BitlockerKey.Read.All": "read BitLocker recovery keys",
    "DeviceLocalCredential.Read.All": "read LAPS passwords",
}


@dataclass(frozen=True)
class Probe:
    feature: str
    path: str
    needs: str                              # permission and role hint shown when it fails
    select: tuple[str, ...] = ()


PROBES: tuple[Probe, ...] = (
    Probe("Users list", "/users", "User.Read.All or Directory.Read.All", ("id",)),
    Probe("Last sign-in", "/users", "AuditLog.Read.All and an Entra ID P1/P2 licence", ("id", "signInActivity")),
    Probe("Groups", "/groups", "Group.Read.All or Directory.Read.All", ("id",)),
    Probe("Devices", "/devices", "Device.Read.All or Directory.Read.All", ("id",)),
    Probe("Administrative units", "/directory/administrativeUnits", "AdministrativeUnit.Read.All or Directory.Read.All",
          ("id",)),
    Probe("Licences (subscriptions)", "/subscribedSkus", "Directory.Read.All (or LicenseAssignment.Read.All)"),
    Probe("Role assignments (Roles tab, Who can manage)", "/roleManagement/directory/roleAssignments",
          "RoleManagement.Read.Directory, and a role that may read them (Directory Readers, Global Reader)"),
    Probe("PIM eligibility of others (Who can manage, unit roles)", "/roleManagement/directory/roleEligibilitySchedules",
          "RoleEligibilitySchedule.Read.Directory, and Global Reader or Privileged Role Administrator"),
    Probe("Your eligible PIM roles", pim.ELIGIBLE_PATH, "RoleEligibilitySchedule.Read.Directory"),
    Probe("Your active roles", pim.ACTIVE_PATH, "RoleAssignmentSchedule.Read(Write).Directory"),
    Probe("Your eligible PIM groups", group_pim.ELIGIBLE_PATH, "PrivilegedEligibilitySchedule.Read.AzureADGroup "
          "(optional: consented on the app registration)"),
    Probe("BitLocker keys (listing only, no key is read)", BITLOCKER_PATH,
          "BitlockerKey.ReadBasic.All or BitlockerKey.Read.All, and a role such as Cloud Device Administrator"),
    Probe("Your own sign-in methods", "/me/authentication/methods", "UserAuthenticationMethod.Read.All"),
)


@dataclass
class ProbeResult:
    probe: Probe
    outcome: str                            # OK | DENIED | NOT FOUND | UNSUPPORTED | ERROR
    status: Optional[int] = None
    code: str = ""
    milliseconds: int = 0

    @property
    def ok(self) -> bool:
        return self.outcome == "OK"

    @property
    def detail(self) -> str:
        bits = [f"HTTP {self.status}" if self.status else "", self.code]
        return " ".join(b for b in bits if b)


@dataclass
class TokenFacts:
    """None for a field = the token couldn't be read."""
    scopes: Optional[list[str]] = None
    role_ids: Optional[list[str]] = None    # wids: directory roles active when the token was issued
    expires: Optional[datetime] = None
    error: str = ""


@dataclass
class Report:
    token: TokenFacts
    results: list[ProbeResult]
    role_names: dict[str, str] = field(default_factory=dict)
    read_only: bool = False
    when: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def roles(self) -> Optional[list[str]]:
        if self.token.role_ids is None:
            return None
        return sorted(self.role_names.get(r, f"role {r}") for r in self.token.role_ids)

    @property
    def optional_present(self) -> Optional[list[str]]:
        if self.token.scopes is None:
            return None
        return sorted(p for p in OPTIONAL_PERMISSIONS if p in self.token.scopes)

    @property
    def optional_missing(self) -> Optional[list[str]]:
        if self.token.scopes is None:
            return None
        return sorted(p for p in OPTIONAL_PERMISSIONS if p not in self.token.scopes)

    def text(self) -> str:
        """The shareable report: permissions, roles and outcomes only."""
        lines = [f"entra-auditor {__version__} tenant check, {self.when:%Y-%m-%d %H:%M} UTC"
                 + (" (read-only session)" if self.read_only else ""),
                 "Contains no user names, ids, tenant name or e-mail addresses.", ""]
        if self.token.error:
            lines.append(f"Token: couldn't be read ({self.token.error})")
        else:
            lines.append(f"Delegated permissions in the token ({len(self.token.scopes or [])}): "
                         + ", ".join(self.token.scopes or []))
            roles = self.roles
            lines.append("Directory roles active in the token: " + (", ".join(roles) if roles else
                         "none (or the token doesn't list them)"))
            lines.append("Optional permissions present: " + (", ".join(self.optional_present or []) or "none"))
            lines.append("Optional permissions missing: " + (", ".join(self.optional_missing or []) or "none"))
        lines += ["", "Feature checks (one harmless read each):"]
        width = max(len(r.probe.feature) for r in self.results) if self.results else 10
        for result in self.results:
            lines.append(f"  {result.probe.feature:<{width}}  {result.outcome:<11} {result.detail:<32} "
                         f"{result.milliseconds:>5} ms")
        failed = [r for r in self.results if not r.ok]
        if failed:
            lines += ["", "What the failed checks need:"]
            lines += [f"  {r.probe.feature}: {r.probe.needs}" for r in failed]
        return "\n".join(lines)


def token_facts(token: Optional[str]) -> TokenFacts:
    if not token:
        return TokenFacts(error="no token available")
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError) as exc:
        return TokenFacts(error=f"not a readable token: {type(exc).__name__}")
    expires = claims.get("exp")
    return TokenFacts(scopes=sorted(set(str(claims.get("scp", "")).split())),
                      role_ids=sorted(set(claims.get("wids") or [])),
                      expires=datetime.fromtimestamp(expires, timezone.utc) if isinstance(expires, (int, float)) else None)


def _probe(graph: Any, probe: Probe, clock: Callable[[], float]) -> ProbeResult:
    start = clock()

    def elapsed() -> int:
        return int((clock() - start) * 1000)

    try:
        list(itertools.islice(graph.get_paged(probe.path, select=list(probe.select) or None, top=1), 1))
    except GraphAuthError:
        raise                                   # the sign-in itself failed: nothing else is worth running
    except GraphError as exc:
        status = exc.status_code
        outcome = {403: "DENIED", 401: "DENIED", 404: "NOT FOUND", 400: "UNSUPPORTED"}.get(status or 0, "ERROR")
        return ProbeResult(probe, outcome, status, str(exc.code or ""), elapsed())
    return ProbeResult(probe, "OK", 200, "", elapsed())


def _role_names(graph: Any) -> dict[str, str]:
    """Role definition id -> name. Built-in role ids equal their template ids, which is what ``wids`` holds."""
    try:
        return {str(d["id"]): str(d.get("displayName") or d["id"]) for d in
                graph.get_all("/roleManagement/directory/roleDefinitions", select=["id", "displayName"])}
    except GraphError:
        return {}


def run_checks(graph: Any, token: Optional[str], *, probes: Sequence[Probe] = PROBES, read_only: bool = False,
               clock: Callable[[], float] = time.perf_counter) -> Report:
    facts = token_facts(token)
    results = [_probe(graph, probe, clock) for probe in probes]
    names = _role_names(graph) if facts.role_ids else {}
    return Report(facts, results, names, read_only)


def session_token(session: Any) -> Optional[str]:
    """The session's current access token, if its provider can hand one out (fakes may not)."""
    get_token = getattr(getattr(session, "provider", None), "get_token", None)
    if get_token is None:
        return None
    try:
        return get_token()
    except Exception:  # noqa: BLE001 - a token problem is reported, not raised
        return None
