"""PIM for Groups: just-in-time membership or ownership of a group.

Many tenants grant admin roles to role-assignable groups and make people *eligible* for membership of
those groups instead of for the roles themselves. Activating the membership then gives the group's roles.
This module lists what you're eligible for, activates and deactivates it, and says which directory roles
each group carries (so a UI can offer "activate Helpdesk Admins to get Helpdesk Administrator").

Endpoints (Microsoft Graph v1.0):
    GET  /identityGovernance/privilegedAccess/group/eligibilityScheduleInstances/filterByCurrentUser(on='principal')
    GET  /identityGovernance/privilegedAccess/group/assignmentScheduleInstances/filterByCurrentUser(on='principal')
    POST /identityGovernance/privilegedAccess/group/assignmentScheduleRequests   (selfActivate / selfDeactivate)
Delegated permissions: PrivilegedEligibilitySchedule.Read.AzureADGroup,
PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup. These are NOT in the default toolkit scopes: an admin
consents them on the app registration, and Entra then includes them in the user's token.

NOT VERIFIED AGAINST A LIVE TENANT (built from the Graph docs and tested against a fake). See CLAUDE.md.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Literal

from ..graph.client import GraphError, GraphNotFoundError, GraphPermissionError
from .odata import literal, segment
from .pim import ActivationResult, PimError, PimService, _to_dt, _utcnow, iso_duration

BASE = "/identityGovernance/privilegedAccess/group"
ELIGIBLE_PATH = f"{BASE}/eligibilityScheduleInstances/filterByCurrentUser(on='principal')"
ACTIVE_PATH = f"{BASE}/assignmentScheduleInstances/filterByCurrentUser(on='principal')"
REQUEST_PATH = f"{BASE}/assignmentScheduleRequests"
PERMISSIONS_HINT = ("The app registration needs the delegated permissions PrivilegedEligibilitySchedule.Read.AzureADGroup "
                    "and PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup, with admin consent.")

Access = Literal["member", "owner"]


@dataclass(frozen=True)
class GroupAccess:
    """Your eligible or active membership/ownership of one group."""
    group_id: str
    group_name: str
    access: str                       # member | owner
    state: str = "eligible"           # eligible | active
    ends: datetime | None = None
    activated: bool = False           # active through a PIM activation (vs a standing assignment)
    roles: tuple[str, ...] = field(default=(), compare=False)   # directory roles the group holds

    @property
    def name(self) -> str:            # what PimService._translate and the UIs call it
        return f"{self.group_name} ({self.access})"

    @property
    def label(self) -> str:
        return self.name + (f" - grants {', '.join(self.roles)}" if self.roles else "")

    @property
    def key(self) -> tuple[str, str]:
        return (self.group_id, self.access)


class GroupPimService:
    def __init__(self, graph: Any, *, clock: Callable[[], datetime] = _utcnow,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self._graph = graph
        self._clock = clock
        self._sleep = sleep
        self._me: str | None = None
        self._names: dict[str, str] = {}
        self._roles: dict[str, tuple[str, ...]] = {}

    def me(self) -> str:
        if self._me is None:
            self._me = str(self._graph.get("/me", select=["id"])["id"])
        return self._me

    # -- names and roles (best effort: an unreadable name falls back to the id) -------------- #

    def group_name(self, group_id: str) -> str:
        if group_id not in self._names:
            try:
                self._names[group_id] = self._graph.get(f"/groups/{segment(group_id)}",
                                                        select=["id", "displayName"]).get("displayName") or group_id
            except GraphError:
                self._names[group_id] = group_id
        return self._names[group_id]

    def group_roles(self, group_id: str) -> tuple[str, ...]:
        """Directory roles assigned (active) to the group: what activating its membership gives you."""
        if group_id not in self._roles:
            try:
                items = self._graph.get_all("/roleManagement/directory/roleAssignments",
                                            filter=f"principalId eq {literal(group_id)}", expand="roleDefinition")
                self._roles[group_id] = tuple(sorted({(i.get("roleDefinition") or {}).get("displayName")
                                                      or i.get("roleDefinitionId", "?") for i in items}))
            except GraphError:
                self._roles[group_id] = ()
        return self._roles[group_id]

    def _access(self, item: dict[str, Any], state: str, *, with_roles: bool) -> GroupAccess:
        group_id = str(item["groupId"])
        return GroupAccess(
            group_id=group_id, group_name=self.group_name(group_id), access=str(item.get("accessId", "member")),
            state=state, ends=_to_dt(item.get("endDateTime")),
            activated=str(item.get("assignmentType", "")).lower() == "activated",
            roles=self.group_roles(group_id) if with_roles else ())

    # -- listing ------------------------------------------------------------------------------ #

    def _list(self, path: str, state: str, with_roles: bool) -> list[GroupAccess]:
        try:
            items = self._graph.get_all(path)
        except GraphPermissionError as exc:
            raise PimError("Your PIM group assignments couldn't be read.", PERMISSIONS_HINT) from exc
        found: dict[tuple[str, str], GroupAccess] = {}
        for item in items:
            access = self._access(item, state, with_roles=with_roles)
            found[access.key] = access
        return sorted(found.values(), key=lambda a: (a.group_name.casefold(), a.access))

    def eligible(self, *, with_roles: bool = True) -> list[GroupAccess]:
        return self._list(ELIGIBLE_PATH, "eligible", with_roles)

    def active(self, *, with_roles: bool = False) -> list[GroupAccess]:
        return self._list(ACTIVE_PATH, "active", with_roles)

    @staticmethod
    def granting(eligible: Iterable[GroupAccess], role_names: Iterable[str],
                 active: Iterable[GroupAccess] = ()) -> list[GroupAccess]:
        """Eligible *memberships* whose group holds one of ``role_names`` (in that order of preference),
        skipping ones already active. Ownership doesn't give a group's roles, so it never counts."""
        active_keys = {a.key for a in active}
        candidates = [a for a in eligible if a.access == "member" and a.key not in active_keys]
        ordered: list[GroupAccess] = []
        for name in role_names:
            for access in candidates:
                if name.lower() in (r.lower() for r in access.roles) and access not in ordered:
                    ordered.append(access)
        return ordered

    # -- activation --------------------------------------------------------------------------- #

    def _request(self, access: GroupAccess, action: str, body_extra: dict[str, Any]) -> ActivationResult:
        body: dict[str, Any] = {"accessId": access.access, "principalId": self.me(), "groupId": access.group_id,
                                "action": action, **body_extra}
        try:
            response = self._graph.post(REQUEST_PATH, body)
        except GraphError as exc:
            raise self._translate(exc, access) from exc
        return ActivationResult(str(response.body.get("status", "Granted")), access, response.body.get("id"))  # type: ignore[arg-type]

    def activate(self, access: GroupAccess, *, reason: str, minutes: int = 60) -> ActivationResult:
        if not reason.strip():
            raise PimError("A justification is required.", "Give a ticket or task description.")
        return self._request(access, "selfActivate", {
            "justification": reason.strip(),
            "scheduleInfo": {"startDateTime": self._clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
                             "expiration": {"type": "afterDuration", "duration": iso_duration(minutes)}},
        })

    def deactivate(self, access: GroupAccess) -> ActivationResult:
        return self._request(access, "selfDeactivate", {})

    def wait_until_active(self, access: GroupAccess, timeout: float = 90.0, interval: float = 3.0) -> bool:
        waited = 0.0
        while True:
            if any(a.key == access.key for a in self.active()):
                return True
            if waited >= timeout:
                return False
            self._sleep(interval)
            waited += interval

    @staticmethod
    def _translate(exc: GraphError, access: GroupAccess) -> PimError:
        if isinstance(exc, GraphNotFoundError):
            return PimError(f"{access.name}: the group or your eligibility no longer exists.",
                            "Reload the list; the eligibility may have expired.")
        error = PimService._translate(exc, access)  # type: ignore[arg-type]  # same policy rules as roles
        if isinstance(exc, GraphPermissionError):
            return PimError(f"You aren't allowed to activate {access.name}.", PERMISSIONS_HINT)
        return error
