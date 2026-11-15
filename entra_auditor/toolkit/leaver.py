"""Offboarding ("leaver") workflow: everything that usually happens when someone leaves, as ONE plan you
preview before anything is sent.

    disable the account -> revoke sign-in sessions -> reset the password to one nobody knows
    -> remove direct licences -> remove from groups -> (optionally) drop group ownerships
    -> remove from administrative units

``gather_leaver_facts`` reads what the user has (a part that can't be read is None and is then left alone:
unknown is not empty). ``plan_leaver`` is pure: it turns the facts and the chosen options into an
``ActionPlan`` whose steps keep going when one fails, so the result says exactly what was and wasn't done.

Deliberately NOT done here (listed in the plan so nothing is forgotten):
  * admin roles (active or PIM-eligible) are not removed: role-assignment writes are not built yet;
  * memberships Graph can't change: dynamic, synced and Exchange-managed groups, dynamic units;
  * licences inherited from a group (they go when the group membership goes);
  * the mailbox (forwarding, conversion to shared), devices, and deleting the account.

Roles: User Administrator covers most steps. Removing from administrative units and from role-assignable
groups needs Privileged Role Administrator; those steps come last and are reported if refused.

NOT VERIFIED AGAINST A LIVE TENANT (built from the Graph docs and tested against a fake). See CLAUDE.md.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel

from ..graph.client import GraphAuthError, GraphError, GraphRetryExhaustedError
from .actions import PASSWORD_METHOD_ID, ActionPlan, PlanError, PlannedRequest
from .licences import UserLicence, load_user_licences
from .models import GroupSummary, UserSummary
from .odata import literal, segment
from .search import _group, get_user

MEMBERSHIP_SELECT = ["id", "displayName", "mail", "description", "securityEnabled", "mailEnabled", "groupTypes",
                     "onPremisesSyncEnabled", "isAssignableToRole", "membershipRule", "membershipType"]
ROLES_LEAVER = ("User Administrator", "Global Administrator")


class LeaverUnit(BaseModel):
    id: str
    name: str
    dynamic: bool = False


class LeaverFacts(BaseModel):
    """What the user has. None = could not be read (and is then left alone)."""
    user: UserSummary
    groups: Optional[list[GroupSummary]] = None
    units: Optional[list[LeaverUnit]] = None
    owned: Optional[list[GroupSummary]] = None
    licences: Optional[list[UserLicence]] = None
    roles_active: Optional[list[str]] = None
    roles_eligible: Optional[list[str]] = None
    warnings: list[str] = []

    @property
    def removable_groups(self) -> list[GroupSummary]:
        return [g for g in self.groups or [] if not group_blocker(g)]

    @property
    def direct_licences(self) -> list[UserLicence]:
        return [lic for lic in self.licences or [] if lic.direct]

    @property
    def removable_units(self) -> list[LeaverUnit]:
        return [u for u in self.units or [] if not u.dynamic]

    @property
    def is_admin(self) -> bool:
        return bool(self.roles_active or self.roles_eligible)


class LeaverOptions(BaseModel):
    disable: bool = True
    revoke_sessions: bool = True
    reset_password: bool = True
    remove_licences: bool = True
    remove_groups: bool = True
    remove_ownerships: bool = False     # off by default: it can leave groups without any owner
    remove_units: bool = True


def group_blocker(group: GroupSummary) -> str:
    """Why this membership can't be removed through Graph; '' when it can."""
    if group.on_prem_synced:
        return "synced from on-premises AD"
    if group.is_exchange_managed:
        return "managed in Exchange"
    if group.is_dynamic:
        return "dynamic membership"
    return ""


def gather_leaver_facts(graph: Any, user_id: str) -> LeaverFacts:
    facts = LeaverFacts(user=get_user(graph, user_id))
    base = f"/users/{segment(user_id)}"

    def soft(label: str, fn: Any) -> Any:
        try:
            return fn()
        except GraphError as exc:
            if isinstance(exc, (GraphAuthError, GraphRetryExhaustedError)):
                raise
            facts.warnings.append(f"{label} couldn't be read ({exc}) and will be left alone.")
            return None

    def kind(item: dict[str, Any]) -> str:
        return str(item.get("@odata.type", "")).rsplit(".", 1)[-1].lower()

    memberships = soft("Group and unit memberships", lambda: graph.get_all(f"{base}/memberOf", select=MEMBERSHIP_SELECT))
    if memberships is not None:
        facts.groups = sorted((_group(m) for m in memberships if kind(m) == "group"), key=lambda g: g.label.casefold())
        facts.units = sorted((LeaverUnit(id=m["id"], name=m.get("displayName") or m["id"],
                                         dynamic=str(m.get("membershipType") or "").lower() == "dynamic")
                              for m in memberships if kind(m) == "administrativeunit"), key=lambda u: u.name.casefold())
    owned = soft("Owned groups", lambda: graph.get_all(f"{base}/ownedObjects", select=MEMBERSHIP_SELECT))
    if owned is not None:
        facts.owned = sorted((_group(o) for o in owned if kind(o) == "group"), key=lambda g: g.label.casefold())

    report = load_user_licences(graph, user_id)
    facts.licences = report.licences
    facts.warnings += [w + " Licences will be left alone." for w in report.warnings if report.licences is None]

    def role_names(path: str) -> list[str]:
        items = graph.get_all(path, filter=f"principalId eq {literal(user_id)}", expand="roleDefinition")
        return sorted({(i.get("roleDefinition") or {}).get("displayName") or i.get("roleDefinitionId", "?")
                       for i in items})

    facts.roles_active = soft("Admin roles", lambda: role_names("/roleManagement/directory/roleAssignments"))
    facts.roles_eligible = soft("PIM-eligible roles",
                                lambda: role_names("/roleManagement/directory/roleEligibilitySchedules"))
    return facts


def plan_leaver(facts: LeaverFacts, options: LeaverOptions) -> ActionPlan:
    user = facts.user
    uid = segment(user.id)
    requests: list[PlannedRequest] = []
    details: list[str] = []
    warnings: list[str] = list(facts.warnings)

    if options.disable and user.account_enabled is not False:
        requests.append(PlannedRequest("PATCH", f"/users/{uid}", {"accountEnabled": False}, "Disable account"))
        details.append("Disable the account")
    if options.revoke_sessions:
        requests.append(PlannedRequest("POST", f"/users/{uid}/revokeSignInSessions", None, "Revoke sign-in sessions"))
        details.append("Sign the user out everywhere")
    if options.reset_password:
        if user.on_prem_synced:
            warnings.append("Password not reset: the account is synced from on-premises AD; reset it there.")
        else:
            requests.append(PlannedRequest(
                "POST", f"/users/{uid}/authentication/methods/{PASSWORD_METHOD_ID}/resetPassword", {},
                "Reset password", secret_keys=("newPassword",)))
            details.append("Reset the password to a new one generated by Entra (shown once afterwards)")
            if facts.is_admin or facts.roles_active is None:
                warnings.append("The password reset may be refused: this user holds admin roles (or they couldn't "
                                "be read), which needs a Privileged Authentication Administrator.")

    if options.remove_licences and facts.direct_licences:
        requests.append(PlannedRequest(
            "POST", f"/users/{uid}/assignLicense",
            {"addLicenses": [], "removeLicenses": [lic.sku_id for lic in facts.direct_licences]}, "Remove licences"))
        details += [f"- licence: {lic.name}" for lic in facts.direct_licences]
        warnings.append("Removing licences starts Microsoft's retention clock for the mailbox and OneDrive: "
                        "convert the mailbox to shared or export the data first if it must be kept.")
    inherited = [lic for lic in facts.licences or [] if lic.groups and not lic.direct]

    if options.remove_groups:
        ordinary = [g for g in facts.removable_groups if not g.is_role_assignable]
        privileged = [g for g in facts.removable_groups if g.is_role_assignable]
        for group in ordinary:
            requests.append(PlannedRequest("DELETE", f"/groups/{segment(group.id)}/members/{uid}/$ref", None,
                                           f"Remove from group {group.label}"))
            details.append(f"- group: {group.label}")
        stuck = [f"{g.label} ({group_blocker(g)})" for g in facts.groups or [] if group_blocker(g)]
        if stuck:
            warnings.append("Left in these groups, which can't be changed here: " + ", ".join(stuck))
        kept = [lic for lic in inherited if not _all_removed(lic, ordinary + privileged)]
    else:
        privileged, kept = [], inherited
    if kept:
        warnings.append("Licences inherited from a group stay until that membership ends: "
                        + ", ".join(lic.name for lic in kept))

    if facts.owned:
        if options.remove_ownerships:
            for group in facts.owned:
                if group.on_prem_synced or group.is_exchange_managed:
                    warnings.append(f"Still owner of {group.label} ({group_blocker(group)}).")
                    continue
                requests.append(PlannedRequest("DELETE", f"/groups/{segment(group.id)}/owners/{uid}/$ref", None,
                                               f"Remove as owner of {group.label}"))
                details.append(f"- owner of: {group.label}")
            warnings.append("A group whose only owner this was will be left without an owner: give it a new one.")
        else:
            warnings.append("Still owns: " + ", ".join(g.label for g in facts.owned) + ". Give them a new owner.")

    # Steps that need Privileged Role Administrator go last, so a refusal doesn't hold up the rest.
    for group in privileged:
        requests.append(PlannedRequest("DELETE", f"/groups/{segment(group.id)}/members/{uid}/$ref", None,
                                       f"Remove from role-assignable group {group.label}"))
        details.append(f"- role-assignable group: {group.label} (needs Privileged Role Administrator)")
    if options.remove_units:
        for unit in facts.removable_units:
            requests.append(PlannedRequest(
                "DELETE", f"/directory/administrativeUnits/{segment(unit.id)}/members/{uid}/$ref", None,
                f"Remove from administrative unit {unit.name}"))
            details.append(f"- administrative unit: {unit.name} (needs Privileged Role Administrator)")
        dynamic = [u.name for u in facts.units or [] if u.dynamic]
        if dynamic:
            warnings.append("Left in these dynamic administrative units (their rule decides): " + ", ".join(dynamic))

    if not requests:
        raise PlanError("Nothing to do: nothing is selected, or the user has none of what was selected.")
    roles = sorted(set(facts.roles_active or []) | {f"{r} (eligible)" for r in facts.roles_eligible or []})
    if roles:
        warnings.insert(0, "ADMIN ROLES ARE NOT REMOVED by this workflow: " + ", ".join(roles)
                        + ". Remove them in the Entra admin center.")
    warnings.append("Not covered: the mailbox (forwarding, shared mailbox), devices, and deleting the account.")
    return ActionPlan(action="user.offboard", title=f"Offboard {user.full_label}", target_type="user",
                      target_id=user.id, target_name=user.full_label, requests=requests, details=details,
                      warnings=warnings, suggested_roles=ROLES_LEAVER, continue_on_error=True)


def _all_removed(licence: UserLicence, removed: list[GroupSummary]) -> bool:
    names = {g.label for g in removed}
    return bool(licence.groups) and all(name in names for name in licence.groups)
