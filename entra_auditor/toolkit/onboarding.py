"""Onboarding: create a user, optionally modelled on an existing one (the "template").

    create the account (with an initial password the user must change)
    -> set the manager -> assign the template's direct licences -> add to the template's groups

``gather_template`` reads what can be copied from the template user; ``plan_onboard`` is pure and builds
ONE plan. The steps after the creation refer to the new user through ``actions.NEW_ID``, which is filled in
when Graph has answered the creation; they keep going when one fails, and the result says which.

Copied from the template when asked: department, job title, company, office, usage location; the manager;
direct licences that still have a free unit; memberships of groups Graph can change. Never copied: admin
roles, role-assignable groups, administrative units, dynamic/synced/Exchange-managed groups (dynamic ones
follow by rule), licences inherited from a group (they follow the group), the mailbox.

Endpoints (Microsoft Graph v1.0): POST /users (201 with the new id; User.ReadWrite.All; User Administrator),
PUT /users/{id}/manager/$ref, POST /users/{id}/assignLicense, POST /groups/{id}/members/$ref.
The initial password is a secret: redacted in previews and logs, shown once at the end.

NOT VERIFIED AGAINST A LIVE TENANT (built from the Graph docs and tested against a fake). See CLAUDE.md.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from pydantic import BaseModel

from ..graph.client import GraphAuthError, GraphError, GraphRetryExhaustedError
from .actions import DEFAULT_GRAPH_BASE, NEW_ID, ActionPlan, PlanError, PlannedRequest
from .leaver import MEMBERSHIP_SELECT, group_blocker
from .licences import Sku, UserLicence, load_user_licences
from .models import GroupSummary, UserSummary
from .odata import segment
from .passwords import password_problems
from .search import _group, get_user

COPIED_ATTRIBUTES = {"department": "department", "jobTitle": "job title", "companyName": "company",
                     "officeLocation": "office", "usageLocation": "usage location"}
ROLES_ONBOARD = ("User Administrator", "Global Administrator")
# Microsoft's rule for user principal names (docs: Create user): letters, digits and ' . - _ ! # ^ ~
_UPN = re.compile(r"^[A-Za-z0-9'._!#^~-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


class NewUser(BaseModel):
    display_name: str
    upn: str
    password: str
    given_name: Optional[str] = None
    surname: Optional[str] = None
    force_change: bool = True

    @property
    def label(self) -> str:
        return f"{self.display_name.strip()} ({self.upn.strip()})"


class Template(BaseModel):
    """What can be copied from an existing user. None = could not be read (and is then not copied)."""
    user: UserSummary
    attributes: dict[str, str] = {}
    manager_id: Optional[str] = None
    manager_name: Optional[str] = None
    groups: Optional[list[GroupSummary]] = None
    licences: Optional[list[UserLicence]] = None
    skus: Optional[list[Sku]] = None
    warnings: list[str] = []

    @property
    def copyable_groups(self) -> list[GroupSummary]:
        return [g for g in self.groups or [] if not group_blocker(g) and not g.is_role_assignable]

    @property
    def copyable_licences(self) -> list[Sku]:
        """Subscriptions the template holds directly that can still be assigned."""
        skus = {s.sku_id: s for s in self.skus or []}
        direct = [skus[lic.sku_id] for lic in self.licences or [] if lic.direct and lic.sku_id in skus]
        return [s for s in direct if s.assignable and s.available != 0]

    @property
    def domain(self) -> str:
        return (self.user.upn or "").rpartition("@")[2]


class OnboardOptions(BaseModel):
    copy_attributes: bool = True
    copy_manager: bool = True
    copy_licences: bool = True
    copy_groups: bool = True


def gather_template(graph: Any, user_id: str) -> Template:
    template = Template(user=get_user(graph, user_id))
    base = f"/users/{segment(user_id)}"

    def soft(label: str, fn: Any, missing_ok: bool = False) -> Any:
        try:
            return fn()
        except GraphError as exc:
            if isinstance(exc, (GraphAuthError, GraphRetryExhaustedError)):
                raise
            if not (missing_ok and exc.status_code == 404):
                template.warnings.append(f"{label} couldn't be read ({exc}) and won't be copied.")
            return None

    raw = soft("The template's attributes", lambda: graph.get(base, select=list(COPIED_ATTRIBUTES)))
    template.attributes = {k: str(v) for k, v in (raw or {}).items() if k in COPIED_ATTRIBUTES and v}
    manager = soft("The template's manager", lambda: graph.get(f"{base}/manager", select=["id", "displayName"]),
                   missing_ok=True)
    if manager and manager.get("id"):
        template.manager_id, template.manager_name = str(manager["id"]), manager.get("displayName") or str(manager["id"])
    memberships = soft("The template's groups", lambda: graph.get_all(f"{base}/memberOf", select=MEMBERSHIP_SELECT))
    if memberships is not None:
        template.groups = sorted((_group(m) for m in memberships
                                  if str(m.get("@odata.type", "")).lower().endswith("group")),
                                 key=lambda g: g.label.casefold())
    report = load_user_licences(graph, user_id)
    template.licences, template.skus = report.licences, report.skus
    template.warnings += [w + " Licences won't be copied." for w in report.warnings]
    return template


def suggest_upn(given: str, surname: str, domain: str) -> str:
    """first.last@domain, reduced to the characters a UPN may contain."""
    clean = [re.sub(r"[^A-Za-z0-9'_-]", "", part.strip()).lower() for part in (given, surname)]
    local = ".".join(part for part in clean if part)
    return f"{local}@{domain}" if local and domain else ""


def plan_onboard(new: NewUser, template: Optional[Template] = None, options: Optional[OnboardOptions] = None,
                 base: str = DEFAULT_GRAPH_BASE) -> ActionPlan:
    options = options or OnboardOptions()
    name, upn = new.display_name.strip(), new.upn.strip()
    if not name:
        raise PlanError("The new user needs a display name.")
    if not _UPN.match(upn):
        raise PlanError("The sign-in name must look like name@your-domain and may only contain letters, digits "
                        "and ' . - _ ! # ^ ~ (no spaces or accents).")
    problems = password_problems(new.password, upn)
    if problems:
        raise PlanError("Password rejected: " + "; ".join(problems) + ".")

    body: dict[str, Any] = {
        "accountEnabled": True, "displayName": name, "mailNickname": upn.partition("@")[0],
        "userPrincipalName": upn,
        "passwordProfile": {"password": new.password, "forceChangePasswordNextSignIn": new.force_change},
    }
    for key, value in (("givenName", new.given_name), ("surname", new.surname)):
        if value and value.strip():
            body[key] = value.strip()
    details = [f"Create {name} ({upn})",
               "Initial password: shown once afterwards" + ("; must be changed at first sign-in" if new.force_change else "")]
    warnings: list[str] = []
    later: list[PlannedRequest] = []
    new_path = f"/users/{NEW_ID}"

    if template is not None:
        warnings += template.warnings
        if options.copy_attributes:
            body.update(template.attributes)
            details += [f"{COPIED_ATTRIBUTES[k]}: '{v}'" for k, v in template.attributes.items()]
        if options.copy_manager and template.manager_id:
            later.append(PlannedRequest("PUT", f"{new_path}/manager/$ref",
                                        {"@odata.id": f"{base.rstrip('/')}/users/{template.manager_id}"}, "Set manager"))
            details.append(f"manager: {template.manager_name}")
        if options.copy_licences:
            licences = template.copyable_licences
            if licences and not body.get("usageLocation"):
                warnings.append("Licences not copied: the new user has no usage location (the template has none, "
                                "or attributes aren't being copied).")
            elif licences:
                later.append(PlannedRequest(
                    "POST", f"{new_path}/assignLicense",
                    {"addLicenses": [{"skuId": s.sku_id, "disabledPlans": []} for s in licences], "removeLicenses": []},
                    "Assign licences"))
                details += [f"+ licence: {s.name}" for s in licences]
            held = {lic.sku_id: lic for lic in template.licences or []}
            skipped = [lic.name for lic in held.values() if lic.direct and lic.sku_id not in {s.sku_id for s in licences}]
            if skipped:
                warnings.append("Not assigned (none left, or not assignable): " + ", ".join(skipped))
            inherited = [lic.name for lic in held.values() if lic.groups and not lic.direct]
            if inherited:
                warnings.append("Comes with group membership, not assigned directly: " + ", ".join(inherited))
        if options.copy_groups:
            for group in template.copyable_groups:
                later.append(PlannedRequest("POST", f"/groups/{segment(group.id)}/members/$ref",
                                            {"@odata.id": f"{base.rstrip('/')}/directoryObjects/{NEW_ID}"},
                                            f"Add to group {group.label}"))
                details.append(f"+ group: {group.label}")
            left = [f"{g.label} ({group_blocker(g) or 'role-assignable'})" for g in template.groups or []
                    if group_blocker(g) or g.is_role_assignable]
            if left:
                warnings.append("Groups not copied: " + ", ".join(left))
        warnings.append(f"Modelled on {template.user.full_label}. Never copied: admin roles, administrative units, "
                        "the mailbox.")

    create = PlannedRequest("POST", "/users", body, "Create user", secret_keys=("passwordProfile",), capture_id=True)
    return ActionPlan(action="user.create", title=f"Create user {name}", target_type="new user", target_id=upn,
                      target_name=f"{name} ({upn})", requests=[create, *later], details=details, warnings=warnings,
                      suggested_roles=ROLES_ONBOARD, continue_on_error=True)
