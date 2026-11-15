"""Administrative units (AUs): list them, their members, their settings and the roles scoped to them.

AUs are Entra's closest thing to AD organisational units, with differences worth knowing:
  * they don't nest (an AU can't contain an AU), so they are a flat list;
  * a user or group can be in several AUs at once;
  * membership is assigned, or dynamic (a rule, like a dynamic group; needs Entra ID P1);
  * a *restricted management* AU shields its members from tenant-wide admins (set at creation, immutable);
  * *hidden membership* AUs only show their members to members (and need Member.Read.Hidden to list).

Endpoints (Microsoft Graph v1.0):
    GET /directory/administrativeUnits                       AdministrativeUnit.Read.All or Directory.Read.All
    GET /directory/administrativeUnits/{id}/members          (same)
    GET /roleManagement/directory/roleAssignments?$filter=directoryScopeId eq '/administrativeUnits/{id}'
    GET /roleManagement/directory/roleEligibilitySchedules?$filter=directoryScopeId eq ...
    GET /directory/administrativeUnits/{id}/scopedRoleMembers   (fallback; active assignments only)
    GET /users/{id}/memberOf, /groups/{id}/memberOf          the units an object is in (direct membership
                                                             includes administrative units; User.Read.All /
                                                             GroupMember.Read.All or Directory.Read.All)
Changes (members, settings) are planned in toolkit/actions.py and need AdministrativeUnit.ReadWrite.All.

NOT VERIFIED AGAINST A LIVE TENANT (built from the Graph docs and tested against a fake). See CLAUDE.md.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel

from ..graph.client import GraphAuthError, GraphError, GraphRetryExhaustedError
from .models import DeviceSummary, GroupSummary, UserSummary
from .odata import literal, segment

AU_PATH = "/directory/administrativeUnits"
AU_SELECT = ["id", "displayName", "description", "membershipType", "membershipRule",
             "membershipRuleProcessingState", "isMemberManagementRestricted", "visibility"]
AU_BASIC_SELECT = ["id", "displayName", "description"]
MEMBER_SELECT = ["id", "displayName", "userPrincipalName", "mail", "accountEnabled", "groupTypes",
                 "mailEnabled", "securityEnabled", "onPremisesSyncEnabled", "operatingSystem",
                 "operatingSystemVersion", "trustType"]
PRINCIPAL_SELECT = ["id", "displayName", "userPrincipalName"]


class AdminUnit(BaseModel):
    id: str
    display_name: str | None = None
    description: str | None = None
    membership_type: str | None = None          # "dynamic" | "assigned" | None (= assigned)
    membership_rule: str | None = None
    processing_state: str | None = None         # "On" | "Paused"
    restricted: bool | None = None              # isMemberManagementRestricted (immutable)
    visibility: str | None = None               # "HiddenMembership" | None (= public)
    settings_known: bool = True                 # False when only the basic properties could be read

    @property
    def label(self) -> str:
        return self.display_name or self.id

    @property
    def is_dynamic(self) -> bool:
        return (self.membership_type or "").lower() == "dynamic"

    @property
    def hidden(self) -> bool:
        return (self.visibility or "").lower() == "hiddenmembership"

    @property
    def badges(self) -> list[str]:
        return [b for b in ("dynamic" if self.is_dynamic else "", "restricted" if self.restricted else "",
                            "hidden membership" if self.hidden else "") if b]


class AuMember(BaseModel):
    id: str
    kind: str = "object"            # user | group | device | object
    name: str | None = None
    detail: str | None = None       # UPN / mail / operating system
    enabled: bool | None = None     # users and devices
    # group facts that matter for restricted-management AUs
    security_enabled: bool | None = None
    mail_enabled: bool | None = None
    unified: bool = False
    synced: bool = False

    @property
    def label(self) -> str:
        return self.name or self.detail or self.id


class ScopedRole(BaseModel):
    role: str
    principal_id: str
    principal_name: str | None = None
    state: str = "active"           # active | eligible

    @property
    def principal_label(self) -> str:
        return self.principal_name or self.principal_id


class AuRoles(BaseModel):
    """None = could not be read (unknown is not empty)."""
    active: list[ScopedRole] | None = None
    eligible: list[ScopedRole] | None = None
    warnings: list[str] = []


def member_from_user(user: UserSummary) -> AuMember:
    return AuMember(id=user.id, kind="user", name=user.display_name, detail=user.upn, enabled=user.account_enabled)


def member_from_group(group: GroupSummary) -> AuMember:
    return AuMember(id=group.id, kind="group", name=group.display_name, detail=group.mail,
                    security_enabled=group.security_enabled, mail_enabled=group.mail_enabled,
                    unified="Unified" in group.group_types, synced=group.on_prem_synced)


def member_from_device(device: DeviceSummary) -> AuMember:
    # the directory OBJECT id: an AU membership link to the hardware deviceId would point at nothing
    return AuMember(id=device.id, kind="device", name=device.display_name, detail=device.os_label,
                    enabled=device.account_enabled)


def _unit(raw: dict[str, Any]) -> AdminUnit:
    return AdminUnit(
        id=raw["id"], display_name=raw.get("displayName"), description=raw.get("description"),
        membership_type=raw.get("membershipType"), membership_rule=raw.get("membershipRule"),
        processing_state=raw.get("membershipRuleProcessingState"),
        restricted=raw.get("isMemberManagementRestricted"), visibility=raw.get("visibility"),
        settings_known=not raw.get("_basic"))


def _kind(raw: dict[str, Any]) -> str:
    odata = str(raw.get("@odata.type", "")).rsplit(".", 1)[-1].lower()
    return odata if odata in ("user", "group", "device") else "object"


def _member(raw: dict[str, Any]) -> AuMember:
    kind = _kind(raw)
    detail = (raw.get("userPrincipalName") if kind == "user" else
              " ".join(x for x in (raw.get("operatingSystem"), raw.get("operatingSystemVersion")) if x) or None
              if kind == "device" else raw.get("mail"))
    return AuMember(
        id=raw["id"], kind=kind, name=raw.get("displayName"), detail=detail,
        enabled=raw.get("accountEnabled") if kind in ("user", "device") else None,
        security_enabled=raw.get("securityEnabled") if kind == "group" else None,
        mail_enabled=raw.get("mailEnabled") if kind == "group" else None,
        unified="Unified" in (raw.get("groupTypes") or []), synced=bool(raw.get("onPremisesSyncEnabled")))


def admin_units_of(graph: Any, kind: str, object_id: str) -> dict[str, str]:
    """{unit id: name} of the administrative units a user or group is a member of. Raises GraphError when
    they can't be read (the caller decides what "unknown" means).

    Plain ``memberOf`` filtered here by ``@odata.type``: the OData cast
    (``/memberOf/microsoft.graph.administrativeUnit``) needs ConsistencyLevel: eventual and $count.
    Membership of a hidden-membership unit may be missing without Member.Read.Hidden.
    """
    collection = {"user": "users", "group": "groups"}[kind]
    items = graph.get_all(f"/{collection}/{segment(object_id)}/memberOf", select=["id", "displayName"])
    return {str(i["id"]): str(i.get("displayName") or i["id"]) for i in items
            if str(i.get("@odata.type", "")).lower().endswith("administrativeunit")}


def _hard(exc: GraphError) -> bool:
    """Problems that mean "stop", not "try another way"."""
    return isinstance(exc, (GraphAuthError, GraphRetryExhaustedError))


def list_admin_units(graph: Any) -> tuple[list[AdminUnit], list[str]]:
    """Every AU, sorted by name, plus warnings. If the full property set is rejected (a cloud that lacks
    one of them), the basic properties are used and the rest show as unknown."""
    warnings: list[str] = []
    try:
        raw = graph.get_all(AU_PATH, select=AU_SELECT, top=999)
    except GraphError as exc:
        if _hard(exc) or exc.status_code != 400:
            raise
        warnings.append(f"Some administrative unit settings couldn't be read ({exc}); showing names only.")
        raw = [{**r, "_basic": True} for r in graph.get_all(AU_PATH, select=AU_BASIC_SELECT, top=999)]
    units = [_unit(r) for r in raw]
    units.sort(key=lambda u: u.label.casefold())
    return units, warnings


def get_admin_unit(graph: Any, unit_id: str) -> AdminUnit:
    return _unit(graph.get(f"{AU_PATH}/{segment(unit_id)}", select=AU_SELECT))


def list_members(graph: Any, unit_id: str) -> list[AuMember]:
    members = [_member(r) for r in graph.get_all(f"{AU_PATH}/{segment(unit_id)}/members",
                                                 select=MEMBER_SELECT, top=999)]
    order = {"user": 0, "group": 1, "device": 2}
    members.sort(key=lambda m: (order.get(m.kind, 3), m.label.casefold()))
    return members


class RoleNames:
    """Role definition id -> display name, read once."""

    def __init__(self, graph: Any) -> None:
        self._graph = graph
        self._names: Optional[dict[str, str]] = None

    def __call__(self, role_id: str) -> str:
        if self._names is None:
            try:
                self._names = {d["id"]: d.get("displayName") or d["id"] for d in self._graph.get_all(
                    "/roleManagement/directory/roleDefinitions", select=["id", "displayName"])}
            except GraphError:
                self._names = {}
        return self._names.get(role_id, role_id)


def _principal_name(item: dict[str, Any]) -> Optional[str]:
    principal = item.get("principal") or {}
    name, upn = principal.get("displayName"), principal.get("userPrincipalName")
    return f"{name} ({upn})" if name and upn else name or upn


def scoped_roles(graph: Any, unit_id: str, names: Optional[RoleNames] = None) -> AuRoles:
    """Roles assigned with this AU as their scope: active and PIM-eligible."""
    names = names or RoleNames(graph)
    scope = f"directoryScopeId eq {literal('/administrativeUnits/' + unit_id)}"
    roles = AuRoles()

    def read(path: str, state: str) -> list[ScopedRole]:
        items = graph.get_all(path, filter=scope, expand="principal")
        found = [ScopedRole(role=names(i["roleDefinitionId"]), principal_id=i.get("principalId", "?"),
                            principal_name=_principal_name(i), state=state) for i in items]
        return sorted(found, key=lambda r: (r.role.casefold(), r.principal_label.casefold()))

    try:
        roles.active = read("/roleManagement/directory/roleAssignments", "active")
    except GraphError as exc:
        if _hard(exc):
            raise
        try:   # the documented AU-specific listing (active assignments only)
            items = graph.get_all(f"{AU_PATH}/{segment(unit_id)}/scopedRoleMembers")
            roles.active = sorted((ScopedRole(role=_directory_role_name(graph, i.get("roleId", "?")),
                                              principal_id=(i.get("roleMemberInfo") or {}).get("id", "?"),
                                              principal_name=(i.get("roleMemberInfo") or {}).get("displayName"))
                                   for i in items), key=lambda r: (r.role.casefold(), r.principal_label.casefold()))
        except GraphError as exc2:
            if _hard(exc2):
                raise
            roles.warnings.append(f"Active role assignments couldn't be read ({exc2}).")
    try:
        roles.eligible = read("/roleManagement/directory/roleEligibilitySchedules", "eligible")
    except GraphError as exc:
        if _hard(exc):
            raise
        roles.warnings.append(f"Eligible (PIM) role assignments couldn't be read ({exc}).")
    return roles


def _directory_role_name(graph: Any, directory_role_id: str) -> str:
    """scopedRoleMembers gives the id of an activated directoryRole (not a role definition)."""
    try:
        return graph.get(f"/directoryRoles/{segment(directory_role_id)}",
                         select=["displayName"]).get("displayName") or directory_role_id
    except GraphError:
        return directory_role_id
