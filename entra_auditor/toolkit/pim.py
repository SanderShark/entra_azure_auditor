"""Privileged Identity Management from inside the tool: see the roles you are *eligible* for,
activate one just-in-time (with justification and duration), and deactivate it afterwards.

This is what lets you sign in with NO standing admin role and elevate only when a task needs it.
Works only with user sign-in (device/browser): PIM activates roles for a person, not an app.

Endpoints (Microsoft Graph v1.0):
    GET  /roleManagement/directory/roleEligibilitySchedules/filterByCurrentUser(on='principal')
    GET  /roleManagement/directory/roleAssignmentScheduleInstances/filterByCurrentUser(on='principal')
    POST /roleManagement/directory/roleAssignmentScheduleRequests   (selfActivate / selfDeactivate)
Permissions: RoleEligibilitySchedule.Read.Directory, RoleAssignmentSchedule.ReadWrite.Directory.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from ..graph.client import GraphClient, GraphError, GraphPermissionError

ELIGIBLE_PATH = "/roleManagement/directory/roleEligibilitySchedules/filterByCurrentUser(on='principal')"
ACTIVE_PATH = "/roleManagement/directory/roleAssignmentScheduleInstances/filterByCurrentUser(on='principal')"
REQUEST_PATH = "/roleManagement/directory/roleAssignmentScheduleRequests"

# Request statuses meaning "the role is (or is about to be) active"
_ACTIVE_STATUSES = {"granted", "provisioned", "pendingprovisioning", "pendingevaluation",
                    "pendingschedulecreation", "schedulecreated", "accepted"}
_PENDING_APPROVAL = {"pendingapproval", "pendingapprovalprovisioning"}


class PimError(Exception):
    """An activation problem, with plain-English advice in ``hint``."""

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.hint = hint


@dataclass(frozen=True)
class PimRole:
    role_id: str
    name: str
    scope: str = "/"
    state: str = "eligible"             # eligible | active
    ends: datetime | None = None
    activated: bool = False             # active through a PIM activation (vs a standing assignment)

    @property
    def label(self) -> str:
        return self.name if self.scope in ("/", "") else f"{self.name} (scope {self.scope})"


@dataclass(frozen=True)
class ActivationResult:
    status: str
    role: PimRole
    request_id: str | None = None

    @property
    def active_now(self) -> bool:
        return self.status.lower() in _ACTIVE_STATUSES

    @property
    def pending_approval(self) -> bool:
        return self.status.lower() in _PENDING_APPROVAL


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def iso_duration(minutes: int) -> str:
    """90 -> 'PT1H30M'. PIM policies cap activation (usually 8-24h); Graph enforces the cap."""
    if not 1 <= minutes <= 24 * 60:
        raise PimError("The duration must be between 1 minute and 24 hours.")
    hours, mins = divmod(minutes, 60)
    return "PT" + (f"{hours}H" if hours else "") + (f"{mins}M" if mins else "")


class PimService:
    def __init__(
        self,
        graph: GraphClient,
        *,
        clock: Callable[[], datetime] = _utcnow,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._graph = graph
        self._clock = clock
        self._sleep = sleep
        self._me: tuple[str, str] | None = None
        self._names: dict[str, str] | None = None

    # -- identity & names --------------------------------------------------- #

    def me(self) -> tuple[str, str]:
        """(object id, UPN) of the signed-in user."""
        if self._me is None:
            body = self._graph.get("/me", select=["id", "userPrincipalName"])
            self._me = (body["id"], body.get("userPrincipalName", ""))
        return self._me

    def _role_name(self, role_id: str) -> str:
        if self._names is None:
            self._names = {d["id"]: d.get("displayName", d["id"]) for d in self._graph.get_all(
                "/roleManagement/directory/roleDefinitions", select=["id", "displayName"])}
        return self._names.get(role_id, role_id)

    def _name(self, item: dict[str, Any]) -> str:
        return (item.get("roleDefinition") or {}).get("displayName") or self._role_name(item["roleDefinitionId"])

    # -- listing ------------------------------------------------------------ #

    def eligible(self) -> list[PimRole]:
        roles: dict[tuple[str, str], PimRole] = {}
        for item in self._graph.get_all(ELIGIBLE_PATH, expand="roleDefinition"):
            ends = _to_dt(((item.get("scheduleInfo") or {}).get("expiration") or {}).get("endDateTime"))
            role = PimRole(item["roleDefinitionId"], self._name(item), item.get("directoryScopeId", "/"),
                           "eligible", ends)
            roles[(role.role_id, role.scope)] = role
        return sorted(roles.values(), key=lambda r: r.name.lower())

    def active(self) -> list[PimRole]:
        roles: dict[tuple[str, str], PimRole] = {}
        for item in self._graph.get_all(ACTIVE_PATH, expand="roleDefinition"):
            role = PimRole(item["roleDefinitionId"], self._name(item), item.get("directoryScopeId", "/"),
                           "active", _to_dt(item.get("endDateTime")),
                           activated=item.get("assignmentType") == "Activated")
            roles[(role.role_id, role.scope)] = role
        return sorted(roles.values(), key=lambda r: r.name.lower())

    # -- choosing ----------------------------------------------------------- #

    @staticmethod
    def match(eligible: Iterable[PimRole], names: Iterable[str],
              active: Iterable[PimRole] = ()) -> list[PimRole]:
        """Eligible roles named in ``names`` (in that order of preference), skipping ones that are
        already active."""
        active_ids = {r.role_id for r in active}
        by_name = {r.name.lower(): r for r in eligible if r.role_id not in active_ids}
        return [by_name[n.lower()] for n in names if n.lower() in by_name]

    @staticmethod
    def find(roles: Iterable[PimRole], text: str) -> PimRole:
        """Pick one role by exact name, else by unique substring, else by role id."""
        roles = list(roles)
        needle = text.strip().lower()
        exact = [r for r in roles if r.name.lower() == needle or r.role_id.lower() == needle]
        if len(exact) == 1:
            return exact[0]
        partial = [r for r in roles if needle in r.name.lower()]
        if len(partial) == 1:
            return partial[0]
        if not partial and not exact:
            raise PimError(f"No role matches '{text}'.",
                           "Run `auditor pim list` to see the roles you can activate.")
        raise PimError(f"'{text}' matches several roles: " + ", ".join(r.name for r in (exact or partial)),
                       "Be more specific, or use the exact name.")

    # -- activation --------------------------------------------------------- #

    def activate(self, role: PimRole, *, reason: str, minutes: int = 60,
                 ticket_number: str | None = None, ticket_system: str | None = None) -> ActivationResult:
        if not reason.strip():
            raise PimError("A justification is required.", "Pass --reason, e.g. a ticket or task description.")
        body: dict[str, Any] = {
            "action": "selfActivate",
            "principalId": self.me()[0],
            "roleDefinitionId": role.role_id,
            "directoryScopeId": role.scope or "/",
            "justification": reason.strip(),
            "scheduleInfo": {
                "startDateTime": self._clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expiration": {"type": "afterDuration", "duration": iso_duration(minutes)},
            },
        }
        if ticket_number:
            body["ticketInfo"] = {"ticketNumber": ticket_number, "ticketSystem": ticket_system or "ticket"}
        try:
            response = self._graph.post(REQUEST_PATH, body)
        except GraphError as exc:
            raise self._translate(exc, role) from exc
        return ActivationResult(str(response.body.get("status", "Granted")), role, response.body.get("id"))

    def deactivate(self, role: PimRole) -> ActivationResult:
        body = {"action": "selfDeactivate", "principalId": self.me()[0], "roleDefinitionId": role.role_id,
                "directoryScopeId": role.scope or "/"}
        try:
            response = self._graph.post(REQUEST_PATH, body)
        except GraphError as exc:
            raise self._translate(exc, role) from exc
        return ActivationResult(str(response.body.get("status", "Revoked")), role, response.body.get("id"))

    def wait_until_active(self, role_id: str, timeout: float = 90.0, interval: float = 3.0) -> bool:
        """Poll until the role shows as active (activation is asynchronous)."""
        waited = 0.0
        while True:
            if any(r.role_id == role_id for r in self.active()):
                return True
            if waited >= timeout:
                return False
            self._sleep(interval)
            waited += interval

    # -- error translation -------------------------------------------------- #

    @staticmethod
    def _translate(exc: GraphError, role: PimRole) -> PimError:
        text = f"{exc.code or ''} {exc}".lower()
        name = role.name
        if "roleassignmentexists" in text or ("already exists" in text and "assignment" in text):
            return PimError(f"{name} is already active.", "Nothing to do. If a task still fails, wait a minute "
                                                           "for the role to take effect.")
        if "pendingroleassignmentrequest" in text:
            return PimError(f"A request for {name} is already pending.", "Wait for approval or cancel it in the portal.")
        if "mfarule" in text or "multi-factor" in text or "multifactor" in text:
            return PimError(f"{name} requires multifactor authentication to activate.",
                            "Sign in again with a fresh MFA prompt: `auditor logout`, then "
                            "`auditor login --mode browser`, and retry.")
        if "justificationrule" in text:
            return PimError(f"{name} requires a justification.", "Pass --reason.")
        if "ticketingrule" in text:
            return PimError(f"{name} requires a ticket number.", "Pass --ticket and --ticket-system.")
        if "expirationrule" in text:
            return PimError(f"The requested duration is longer than {name} allows.", "Try a shorter --minutes.")
        if "approvalrule" in text or "approval" in text:
            return PimError(f"{name} needs approval before it becomes active.",
                            "The request was sent to the approvers; run `auditor pim list` afterwards.")
        if isinstance(exc, GraphPermissionError):
            return PimError(f"You aren't allowed to activate {name}.",
                            "Check you are eligible (`auditor pim list`) and that the app registration has the "
                            "RoleAssignmentSchedule.ReadWrite.Directory delegated permission with admin consent.")
        return PimError(f"Could not activate {name}: {exc}")
