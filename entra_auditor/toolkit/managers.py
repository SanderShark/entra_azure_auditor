"""Who can manage this user? Entra's answer to "delegation" on an AD organisational unit.

For one user this lists the admins whose role lets them act on that user, and what each can do:

  * tenant-wide role holders (Global Administrator, User Administrator, Helpdesk Administrator, ...);
  * admins whose role is scoped to an administrative unit the user is in;
  * active assignments and PIM-eligible ones (eligible admins must activate first).

and applies the rules that decide whether a role actually reaches *this* user:

  * **Restricted management units.** If the user is in one, tenant-wide admins (Global Administrators
    included) and admins scoped to ordinary units are blocked; only admins scoped to a restricted unit the
    user is in can change them. Licences and usage location stay manageable.
  * **The user's own admin roles.** Helpdesk/Password/Authentication/User Administrators can only reset
    passwords of, or do sensitive things to, users holding no role or one of a few low-privilege roles
    (Microsoft's "Who can reset passwords" and "Who can perform sensitive actions" tables, below).
    Members and owners of role-assignable groups are protected the same way.
  * **Unit-scoped roles** only act on users without admin roles.

Read-only. Endpoints (Microsoft Graph v1.0):
    GET /roleManagement/directory/roleDefinitions
    GET /roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{id}'&$expand=principal
    GET /roleManagement/directory/roleEligibilitySchedules?$filter=roleDefinitionId eq '{id}'&$expand=principal
    GET /roleManagement/directory/roleAssignments?$filter=principalId eq '{user}'   (the user's own roles)
    GET /users/{id}/memberOf, /users/{id}/ownedObjects, /directory/administrativeUnits/{id}
Delegated permissions: RoleManagement.Read.Directory, RoleEligibilitySchedule.Read.Directory,
Directory.Read.All (all already in the toolkit scopes). The signed-in user also needs a role that may read
role assignments (Directory Readers, Global Reader, ...); without it the lists show as unreadable.

Sources: learn.microsoft.com "Privileged roles and permissions" (the two tables), "Restricted management
administrative units", "Assign Microsoft Entra roles" (administrative unit scope).

Not covered (the desktop tab says so): custom roles, group owners, admins who would get a role by
activating a PIM group membership, application permissions held by apps, and one row of Microsoft's tables:
a user holding a role scoped to a restricted management unit is protected like an admin.

NOT VERIFIED AGAINST A LIVE TENANT (built from the docs and tested against a fake). See CLAUDE.md.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel

from ..graph.client import GraphAuthError, GraphError, GraphRetryExhaustedError
from .admin_units import AdminUnit, get_admin_unit
from .odata import literal, segment
from .pim import AU_SCOPE_PREFIX, TENANT_SCOPE, is_tenant_wide

GA = "Global Administrator"
PAA = "Privileged Authentication Administrator"
UA = "User Administrator"
AA = "Authentication Administrator"
HD = "Helpdesk Administrator"
PA = "Password Administrator"
LA = "License Administrator"
# Built-in roles that act on user accounts, strongest first (the order rows are shown in).
MANAGER_ROLES = (GA, PAA, UA, AA, HD, PA, LA)

CAN_PASSWORD = "reset password"
CAN_ACCOUNT = "enable/disable, delete, change sign-in name"
CAN_METHODS = "sign-in methods"
CAN_PROFILE = "edit profile"
CAN_LICENCES = "licences"
# What each role can do to a user it reaches (before the rules about who that user is).
ROLE_CAN: dict[str, tuple[str, ...]] = {
    GA: (CAN_PASSWORD, CAN_ACCOUNT, CAN_METHODS, CAN_PROFILE, CAN_LICENCES),
    PAA: (CAN_PASSWORD, CAN_ACCOUNT, CAN_METHODS),
    UA: (CAN_PASSWORD, CAN_ACCOUNT, CAN_PROFILE, CAN_LICENCES),
    AA: (CAN_PASSWORD, CAN_ACCOUNT, CAN_METHODS),
    HD: (CAN_PASSWORD,),
    PA: (CAN_PASSWORD,),
    LA: (CAN_LICENCES,),
}
# Capabilities that depend on which admin roles the target holds.
_GUARDED = (CAN_PASSWORD, CAN_ACCOUNT, CAN_METHODS)
# Roles never limited by the target's own roles (at tenant scope).
_UNLIMITED = (GA, PAA)

_ALL4 = frozenset({PA, HD, AA, UA})
_HD_AA_UA = frozenset({HD, AA, UA})
_AA_UA = frozenset({AA, UA})
_NONE: frozenset[str] = frozenset()
# "Who can reset passwords": the target's role -> which limited admin roles can reset its password.
# A target role that isn't listed protects the user from all four.
PASSWORD_RESET: dict[str, frozenset[str]] = {
    "Authentication Administrator": frozenset({AA}),
    "Directory Readers": _ALL4,
    "Groups Administrator": frozenset({UA}),
    "Guest Inviter": _ALL4,
    "Helpdesk Administrator": frozenset({HD, UA}),
    "Message Center Reader": _HD_AA_UA,
    "Password Administrator": _ALL4,
    "Reports Reader": _HD_AA_UA,
    "User Administrator": frozenset({UA}),
    "User Experience Success Manager": _HD_AA_UA,
    "Usage Summary Reports Reader": _HD_AA_UA,
}
# "Who can perform sensitive actions" (and manage sign-in methods): same idea, for AA and UA.
SENSITIVE: dict[str, frozenset[str]] = {
    "Authentication Administrator": frozenset({AA}),
    "Directory Readers": _AA_UA,
    "Groups Administrator": frozenset({UA}),
    "Guest Inviter": _AA_UA,
    "Helpdesk Administrator": frozenset({UA}),
    "Message Center Reader": _AA_UA,
    "Password Administrator": _AA_UA,
    "Reports Reader": _AA_UA,
    "User Administrator": frozenset({UA}),
    "User Experience Success Manager": _AA_UA,
    "Usage Summary Reports Reader": _AA_UA,
}


class Manager(BaseModel):
    """One role assignment that concerns the user."""
    role: str
    principal_id: str
    principal_name: Optional[str] = None
    principal_kind: str = "user"        # user | group | app
    state: str = "active"               # active | eligible (must activate with PIM first)
    scope: str = TENANT_SCOPE
    unit_name: Optional[str] = None     # for a unit-scoped assignment
    can: list[str] = []                 # what they can do to this user; empty = nothing
    why_not: Optional[str] = None       # why something the role normally allows is missing

    @property
    def who(self) -> str:
        name = self.principal_name or self.principal_id
        if self.principal_kind == "group":
            return f"{name} (group: its members hold the role)"
        return f"{name} (app)" if self.principal_kind == "app" else name

    @property
    def scope_label(self) -> str:
        return "Whole tenant" if is_tenant_wide(self.scope) else f"Unit: {self.unit_name or self.scope}"

    @property
    def assignment_label(self) -> str:
        return "Active" if self.state == "active" else "Eligible (PIM)"


class ManagerReport(BaseModel):
    """None = could not be read (unknown is not empty)."""
    user_id: str
    units: Optional[list[AdminUnit]] = None         # the administrative units the user is in
    user_roles: Optional[list[str]] = None          # the user's own active admin roles
    protected_by: list[str] = []                    # why limited admins can't touch them (besides roles)
    managers: Optional[list[Manager]] = None
    eligible_known: bool = True                     # False: PIM-eligible assignments couldn't be read
    notes: list[str] = []                           # plain-English findings, most important first
    warnings: list[str] = []

    @property
    def restricted_units(self) -> list[AdminUnit]:
        return [u for u in self.units or [] if u.restricted]

    @property
    def effective(self) -> list[Manager]:
        return [m for m in self.managers or [] if m.can]

    @property
    def ineffective(self) -> list[Manager]:
        return [m for m in self.managers or [] if not m.can]


# --------------------------------------------------------------------------- #
# The rules (pure)
# --------------------------------------------------------------------------- #

def _reaches(role: str, capability: str, user_roles: list[str], protected: bool) -> bool:
    """Tenant scope: can ``role`` do ``capability`` to a user holding ``user_roles``?"""
    if capability not in _GUARDED or role in _UNLIMITED:
        return True
    if protected:
        return False
    table = PASSWORD_RESET if capability == CAN_PASSWORD else SENSITIVE
    return all(role in table.get(held, _NONE) for held in user_roles)


def capabilities(role: str, scope: str, *, user_roles: Optional[list[str]], protected: bool,
                 unit_scopes: Optional[frozenset[str]], restricted_scopes: frozenset[str]
                 ) -> tuple[list[str], Optional[str]]:
    """What a holder of ``role`` at ``scope`` can do to the user, and why anything is missing.

    ``unit_scopes``: scopes of the units the user is in (None = unknown); ``restricted_scopes``: those of
    them with restricted management. ``user_roles`` None = the user's own roles couldn't be read.
    """
    normal = ROLE_CAN.get(role, ())
    tenant_wide = is_tenant_wide(scope)
    if not tenant_wide:
        if unit_scopes is not None and scope not in unit_scopes:
            return [], "the user isn't in that administrative unit"
    # a restricted unit blocks everyone not scoped to a restricted unit the user is in (licences excepted)
    if restricted_scopes and scope not in restricted_scopes:
        can = [c for c in normal if c == CAN_LICENCES]
        return can, ("everything else is " if can else "") + "blocked by a restricted management unit"

    if user_roles is None:
        can = [c for c in normal if c not in _GUARDED or (tenant_wide and role in _UNLIMITED)]
        missing = len(can) < len(normal)
        return can, "the rest depends on this user's own admin roles, which couldn't be read" if missing else None
    if tenant_wide:
        can = [c for c in normal if _reaches(role, c, user_roles, protected)]
    else:   # unit-scoped roles only act on users who aren't admins themselves
        can = [c for c in normal if c not in _GUARDED or not (user_roles or protected)]
    if len(can) == len(normal):
        return can, None
    reason = ("the user is in a role-assignable group" if protected and not user_roles
              else "the user holds " + ", ".join(user_roles))
    return can, f"limited because {reason}"


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def _hard(exc: GraphError) -> bool:
    return isinstance(exc, (GraphAuthError, GraphRetryExhaustedError))


def _principal(item: dict[str, Any]) -> tuple[Optional[str], str]:
    principal = item.get("principal") or {}
    kind = str(principal.get("@odata.type", "")).rsplit(".", 1)[-1].lower()
    kind = {"user": "user", "group": "group", "serviceprincipal": "app"}.get(kind, "user")
    name, upn = principal.get("displayName"), principal.get("userPrincipalName")
    return (f"{name} ({upn})" if name and upn else name or upn), kind


def who_can_manage(graph: Any, user_id: str) -> ManagerReport:
    """Build the report. One unreadable source becomes a warning; only auth failures abort."""
    report = ManagerReport(user_id=user_id)
    base = f"/users/{segment(user_id)}"

    def soft(label: str, fn: Any) -> Any:
        try:
            return fn()
        except GraphError as exc:
            if _hard(exc):
                raise
            report.warnings.append(f"{label} couldn't be read ({exc}).")
            return None

    # -- the user: units, role-assignable groups, own roles ---------------------------------
    memberships = soft("The user's group and unit memberships", lambda: graph.get_all(
        f"{base}/memberOf", select=["id", "displayName", "isAssignableToRole"]))
    if memberships is not None:
        units: list[AdminUnit] = []
        for item in memberships:
            kind = str(item.get("@odata.type", "")).lower()
            if kind.endswith("administrativeunit"):
                unit = soft(f"Administrative unit {item.get('displayName') or item['id']}",
                            lambda item=item: get_admin_unit(graph, item["id"]))
                units.append(unit or AdminUnit(id=item["id"], display_name=item.get("displayName"),
                                               settings_known=False))
            elif kind.endswith("group") and item.get("isAssignableToRole"):
                report.protected_by.append(f"member of the role-assignable group {item.get('displayName') or item['id']}")
        report.units = sorted(units, key=lambda u: u.label.casefold())
    owned = soft("The objects the user owns", lambda: graph.get_all(
        f"{base}/ownedObjects", select=["id", "displayName", "isAssignableToRole"]))
    for item in owned or []:
        if item.get("isAssignableToRole"):
            report.protected_by.append(f"owner of the role-assignable group {item.get('displayName') or item['id']}")

    own = soft("The user's own admin roles", lambda: graph.get_all(
        "/roleManagement/directory/roleAssignments", filter=f"principalId eq {literal(user_id)}",
        expand="roleDefinition"))
    if own is not None:
        report.user_roles = sorted({(i.get("roleDefinition") or {}).get("displayName")
                                    or i.get("roleDefinitionId", "?") for i in own})

    unit_scopes = None if report.units is None else frozenset(AU_SCOPE_PREFIX + u.id for u in report.units)
    restricted = frozenset(AU_SCOPE_PREFIX + u.id for u in report.restricted_units)
    unit_names = {AU_SCOPE_PREFIX + u.id: u.label for u in report.units or []}

    # -- the admins ------------------------------------------------------------------------
    definitions = soft("Role definitions", lambda: graph.get_all(
        "/roleManagement/directory/roleDefinitions", select=["id", "displayName"]))
    role_ids = {d.get("displayName"): d["id"] for d in definitions or []}

    def read(path: str, state: str) -> Optional[list[Manager]]:
        found: list[Manager] = []
        for role in MANAGER_ROLES:
            if role not in role_ids:
                continue
            items = graph.get_all(path, filter=f"roleDefinitionId eq {literal(role_ids[role])}", expand="principal")
            for item in items:
                scope = item.get("directoryScopeId") or TENANT_SCOPE
                if not is_tenant_wide(scope) and (not scope.startswith(AU_SCOPE_PREFIX)
                                                  or (unit_scopes is not None and scope not in unit_scopes)):
                    continue        # scoped to an app, or to a unit this user isn't in: not about this user
                if item.get("principalId") == user_id:
                    continue        # the user's own roles are shown separately
                name, kind = _principal(item)
                can, why_not = capabilities(role, scope, user_roles=report.user_roles,
                                            protected=bool(report.protected_by), unit_scopes=unit_scopes,
                                            restricted_scopes=restricted)
                if not is_tenant_wide(scope) and unit_scopes is None:
                    why_not = "only if the user is in that unit (their units couldn't be read)"
                found.append(Manager(role=role, principal_id=str(item.get("principalId", "?")), principal_name=name,
                                     principal_kind=kind, state=state, scope=scope,
                                     unit_name=unit_names.get(scope), can=can, why_not=why_not))
        return found

    managers: Optional[list[Manager]] = None
    if definitions is not None:
        managers = soft("Role assignments", lambda: read("/roleManagement/directory/roleAssignments", "active"))
    if managers is not None:
        eligible = soft("PIM-eligible role assignments",
                        lambda: read("/roleManagement/directory/roleEligibilitySchedules", "eligible"))
        report.eligible_known = eligible is not None
        managers += eligible or []
        order = {role: index for index, role in enumerate(MANAGER_ROLES)}
        managers.sort(key=lambda m: (not m.can, order[m.role], not is_tenant_wide(m.scope), m.state != "active",
                                     m.who.casefold()))
    report.managers = managers
    report.notes = _notes(report)
    return report


def _notes(report: ManagerReport) -> list[str]:
    notes: list[str] = []
    if report.restricted_units:
        names = ", ".join(u.label for u in report.restricted_units)
        notes.append(f"In the restricted management unit {names}: only admins with a role scoped to it can change "
                     "this user. Tenant-wide admins, Global Administrators included, are blocked (a Global or "
                     "Privileged Role Administrator can still take the user out of the unit).")
    if report.units is None:
        notes.append("The user's administrative units couldn't be read, so restricted units and unit-scoped "
                     "admins can't be judged.")
    elif any(not u.settings_known for u in report.units):
        notes.append("Some of the user's units couldn't be read fully; one of them may be a restricted management unit.")
    if report.user_roles:
        notes.append("This user is an admin (" + ", ".join(report.user_roles) + "), which limits who can reset "
                     "their password or change their account.")
    elif report.user_roles is None:
        notes.append("The user's own admin roles couldn't be read; what limited admins can do is uncertain.")
    for reason in report.protected_by:
        notes.append(f"Protected like an admin: {reason}. Only Privileged Authentication Administrators and "
                     "Global Administrators can reset the password or change the account.")
    if report.managers is not None and not report.eligible_known:
        notes.append("PIM-eligible admins couldn't be read; only active assignments are listed.")
    if report.managers is not None and not report.effective:
        notes.append("No listed admin can currently change this user.")
    return notes
