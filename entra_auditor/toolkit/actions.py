"""Identity and group changes: PLAN first (pure), then EXECUTE.

``plan_*`` functions build an ``ActionPlan``: exactly which Graph requests would be sent, in
readable form, with secrets redacted. They never touch the network, so they are easy to
preview, dry-run and test, and they refuse changes Graph can't perform (synced groups,
dynamic membership, Exchange-managed groups, ...) with a clear reason instead of a cryptic 400.

``execute_plan`` sends the requests and records the outcome in the local action log
(who, what, to whom, result; never a password).

Each plan lists ``suggested_roles``: the Entra roles that can perform it. When Graph answers
"forbidden", the CLI uses that list to offer PIM elevation.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Literal, Mapping

from ..graph.client import GraphClient, GraphError, GraphNotFoundError, GraphPermissionError
from . import audit_log
from .admin_units import AdminUnit, AuMember
from .models import GroupSummary, UserSummary
from .odata import segment
from .passwords import password_problems

DEFAULT_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
PASSWORD_METHOD_ID = "28c10230-6103-485e-b985-444c60001490"  # the user's password method
# Stands for the id of the object a plan creates (see PlannedRequest.capture_id). Later requests in the same
# plan use it in their path or body; it is filled in when the creating request has answered.
NEW_ID = "{new-id}"
REPLICATION_ATTEMPTS = 6      # a just-created object can take a few seconds to be known everywhere
REPLICATION_WAIT = 3.0

# Roles that can perform each kind of change (names as shown in Entra / PIM).
ROLES_USER_EDIT = ("User Administrator",)
ROLES_PASSWORD = ("Helpdesk Administrator", "Password Administrator", "User Administrator",
                  "Authentication Administrator")
ROLES_PASSWORD_ADMIN_TARGET = ("Privileged Authentication Administrator", "Global Administrator")
ROLES_SESSIONS = ("User Administrator", "Helpdesk Administrator", "Authentication Administrator")
ROLES_GROUP_MEMBERS = ("Groups Administrator", "User Administrator")
ROLES_GROUP_OWNERS = ("Groups Administrator",)
ROLES_ROLE_GROUPS = ("Privileged Role Administrator",)
ROLES_CERT_IDS = ("Privileged Authentication Administrator",)
ROLES_CERT_IDS_SYNCED = ("Hybrid Identity Administrator",)
ROLES_ADMIN_UNITS = ("Privileged Role Administrator",)
ROLES_LICENCES = ("License Administrator", "User Administrator")
ROLES_TAP = ("Authentication Administrator", "Privileged Authentication Administrator")
ROLES_TAP_ADMIN_TARGET = ("Privileged Authentication Administrator",)
TAP_MIN_MINUTES, TAP_MAX_MINUTES = 10, 43200      # Graph's limits: 10 minutes to 30 days
EDITABLE_AU_FIELDS = ("displayName", "description", "membershipType", "membershipRule",
                      "membershipRuleProcessingState")

EDITABLE_USER_FIELDS = {
    "displayName", "givenName", "surname", "jobTitle", "department", "officeLocation",
    "companyName", "employeeId", "mobilePhone", "usageLocation",
}
FIELD_ALIASES = {
    "name": "displayName", "first": "givenName", "firstname": "givenName", "last": "surname",
    "lastname": "surname", "title": "jobTitle", "dept": "department", "office": "officeLocation",
    "company": "companyName", "employee": "employeeId", "employeeid": "employeeId",
    "phone": "mobilePhone", "mobile": "mobilePhone", "location": "usageLocation",
    "country": "usageLocation",
}


class PlanError(ValueError):
    """The requested change can't be made (or makes no sense); the message says why."""


@dataclass(frozen=True)
class PlannedRequest:
    method: str
    path: str
    json: dict[str, Any] | None = None
    description: str = ""
    secret_keys: tuple[str, ...] = ()
    capture_id: bool = False          # this request creates an object; its id replaces NEW_ID afterwards
    reveal: tuple[str, ...] = ()      # response fields that are secrets: shown once in the result, never logged

    def redacted_json(self) -> dict[str, Any] | None:
        if self.json is None:
            return None
        return {k: ("********" if k in self.secret_keys else v) for k, v in self.json.items()}


@dataclass
class ActionPlan:
    action: str                       # machine id, e.g. "user.reset_password"
    title: str
    target_type: str                  # user | group
    target_id: str
    target_name: str
    requests: list[PlannedRequest]
    details: list[str] = field(default_factory=list)      # human-readable change lines
    warnings: list[str] = field(default_factory=list)
    suggested_roles: tuple[str, ...] = ()
    # Multi-step workflows (offboarding): a step that fails is reported and the rest still run, instead of
    # stopping at the first problem. A refusal of the very first step is still "denied" (so PIM is offered).
    continue_on_error: bool = False

    def log_requests(self) -> list[dict[str, Any]]:
        return [{"method": r.method, "path": r.path, "json": r.redacted_json(), "what": r.description}
                for r in self.requests]


@dataclass
class ActionResult:
    status: Literal["ok", "dry_run", "denied", "failed", "partial", "skipped"]
    message: str = ""
    lines: list[str] = field(default_factory=list)
    secrets: dict[str, str] = field(default_factory=dict)   # shown to the operator once, never logged
    error: GraphError | None = None

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "dry_run")


# --------------------------------------------------------------------------- #
# Plan builders: users
# --------------------------------------------------------------------------- #

def resolve_field(name: str) -> str:
    key = name.strip()
    canonical = {f.lower(): f for f in EDITABLE_USER_FIELDS}
    lowered = key.lower().replace("_", "").replace("-", "")
    if lowered in canonical:
        return canonical[lowered]
    if lowered in FIELD_ALIASES:
        return FIELD_ALIASES[lowered]
    raise PlanError(f"'{name}' can't be edited here. Editable fields: "
                    + ", ".join(sorted(EDITABLE_USER_FIELDS)))


def parse_assignments(items: Iterable[str]) -> dict[str, str | None]:
    """``["title=Engineer", "dept="]`` -> ``{"jobTitle": "Engineer", "department": None}``
    (an empty value clears the attribute)."""
    changes: dict[str, str | None] = {}
    for item in items:
        if "=" not in item:
            raise PlanError(f"'{item}' is not in field=value form.")
        name, value = item.split("=", 1)
        field_name = resolve_field(name)
        value = value.strip()
        if any(ord(c) < 32 for c in value):
            raise PlanError(f"{field_name}: control characters are not allowed.")
        if len(value) > 256:
            raise PlanError(f"{field_name}: value is too long (max 256 characters).")
        if field_name == "displayName" and not value:
            raise PlanError("displayName can't be empty.")
        if field_name == "usageLocation":
            if value and not re.fullmatch(r"[A-Za-z]{2}", value):
                raise PlanError("usageLocation must be a two-letter country code, e.g. US.")
            value = value.upper()
        changes[field_name] = value or None
    if not changes:
        raise PlanError("Nothing to change.")
    return changes


def _show(value: Any) -> str:
    return "(empty)" if value in (None, "") else f"'{value}'"


def plan_update_user(
    user: UserSummary, changes: Mapping[str, str | None], current: Mapping[str, Any] | None = None
) -> ActionPlan:
    current = current or {}
    effective = {k: v for k, v in changes.items() if str(current.get(k) or "") != str(v or "")}
    if not effective:
        raise PlanError("Nothing to change: the user already has those values.")
    plan = ActionPlan(
        action="user.update", title="Update user attributes", target_type="user",
        target_id=user.id, target_name=user.full_label,
        requests=[PlannedRequest("PATCH", f"/users/{segment(user.id)}", dict(effective), "Update attributes")],
        details=[f"{k}: {_show(current.get(k))} -> {_show(v)}" for k, v in effective.items()],
        suggested_roles=ROLES_USER_EDIT,
    )
    if user.on_prem_synced:
        plan.warnings.append(
            "This account is synced from on-premises AD. Graph rejects changes to attributes "
            "mastered there (name, title, department, ...). Change them in AD instead.")
    return plan


def plan_change_licences(user: UserSummary, add: list[Any], remove: list[Any], *, current: list[Any],
                         usage_location: str | None, set_usage_location: str | None = None) -> ActionPlan:
    """Assign and/or remove licences in one request. ``add`` are ``licences.Sku``; ``remove`` anything with
    ``sku_id`` and ``name``; ``current`` the user's ``licences.UserLicence`` (to tell direct from inherited).
    A user without a usage location needs one first: pass ``set_usage_location`` to set it in the same plan."""
    held = {lic.sku_id: lic for lic in current}
    add = [s for s in add if not (s.sku_id in held and held[s.sku_id].direct)]
    if not add and not remove:
        raise PlanError("Nothing to change: the user already has exactly those licences.")
    for sku in add:
        if not sku.assignable:
            raise PlanError(f"{sku.name} can't be assigned (subscription status: {sku.status or 'unknown'}).")
        if sku.available == 0:
            raise PlanError(f"No {sku.name} licences are left ({sku.used:,} of {sku.total:,} in use).")
    for sku in remove:
        licence = held.get(sku.sku_id)
        if licence is None:
            raise PlanError(f"The user doesn't have {sku.name}.")
        if not licence.direct:
            raise PlanError(f"{licence.name} comes from the group {', '.join(licence.groups) or '?'}; "
                            "remove the user from that group instead.")
    requests: list[PlannedRequest] = []
    details: list[str] = []
    if add and not usage_location:
        location = (set_usage_location or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", location):
            raise PlanError("A licence can only be assigned to a user with a usage location: give the "
                            "two-letter country code (for example US, GB, DE).")
        requests.append(PlannedRequest("PATCH", f"/users/{segment(user.id)}", {"usageLocation": location},
                                       "Set usage location"))
        details.append(f"usageLocation: (empty) -> '{location}'")
    requests.append(PlannedRequest(
        "POST", f"/users/{segment(user.id)}/assignLicense",
        {"addLicenses": [{"skuId": s.sku_id, "disabledPlans": []} for s in add],
         "removeLicenses": [s.sku_id for s in remove]},
        "Change licences"))
    details += [f"+ {s.name}" for s in add] + [f"- {s.name}" for s in remove]
    plan = ActionPlan(action="user.licences", title="Change licences", target_type="user", target_id=user.id,
                      target_name=user.full_label, requests=requests, details=details,
                      suggested_roles=ROLES_LICENCES)
    if remove:
        plan.warnings.append("Removing a licence cuts the user off from that service; its data (mailbox, "
                             "OneDrive, ...) is deleted after Microsoft's retention period.")
    kept = [held[s.sku_id] for s in remove if held[s.sku_id].groups]
    if kept:
        plan.warnings.append("Still inherited from a group afterwards: " + ", ".join(lic.name for lic in kept))
    return plan


def plan_create_tap(user: UserSummary, minutes: int = 60, *, usable_once: bool = True,
                    target_is_admin: bool = False) -> ActionPlan:
    """A Temporary Access Pass: a time-limited code the user signs in with to set up their sign-in methods
    (a new phone, a lost security key). Entra generates it; it is shown once and never logged."""
    if not TAP_MIN_MINUTES <= minutes <= TAP_MAX_MINUTES:
        raise PlanError(f"A Temporary Access Pass lasts between {TAP_MIN_MINUTES} minutes and 30 days "
                        f"({TAP_MAX_MINUTES} minutes).")
    hours, rest = divmod(minutes, 60)
    lifetime = (f"{hours} h" if hours else "") + (f" {rest} min" if rest else "")
    plan = ActionPlan(
        action="user.create_tap", title="Create a Temporary Access Pass", target_type="user",
        target_id=user.id, target_name=user.full_label,
        requests=[PlannedRequest("POST", f"/users/{segment(user.id)}/authentication/temporaryAccessPassMethods",
                                 {"lifetimeInMinutes": minutes, "isUsableOnce": usable_once},
                                 "Create Temporary Access Pass", reveal=("temporaryAccessPass",))],
        details=[f"Valid for {lifetime.strip()}, from now", "Usable once" if usable_once else "Usable repeatedly "
                 "while valid", "The pass is generated by Entra and shown once afterwards"],
        warnings=["Any Temporary Access Pass the user already has is replaced.",
                  "Temporary Access Pass must be enabled in the tenant's Authentication methods policy"
                  + ("." if usable_once else ", and must allow passes that can be used more than once.")],
        suggested_roles=ROLES_TAP_ADMIN_TARGET if target_is_admin else ROLES_TAP)
    if target_is_admin:
        plan.warnings.append("This user holds admin roles, so only a Privileged Authentication Administrator can "
                             "create a pass for them.")
    return plan


def plan_set_enabled(user: UserSummary, enabled: bool) -> ActionPlan:
    if user.account_enabled is enabled:
        raise PlanError(f"The account is already {'enabled' if enabled else 'disabled'}.")
    plan = ActionPlan(
        action="user.enable" if enabled else "user.disable",
        title=f"{'Enable' if enabled else 'Disable'} account", target_type="user",
        target_id=user.id, target_name=user.full_label,
        requests=[PlannedRequest("PATCH", f"/users/{segment(user.id)}", {"accountEnabled": enabled},
                                 "Enable account" if enabled else "Disable account")],
        suggested_roles=ROLES_USER_EDIT,
    )
    if not enabled:
        plan.warnings.append("Disabling doesn't end sessions that are already signed in; "
                             "revoke sessions as well if this is an incident.")
    return plan


def plan_revoke_sessions(user: UserSummary) -> ActionPlan:
    return ActionPlan(
        action="user.revoke_sessions", title="Revoke all sign-in sessions", target_type="user",
        target_id=user.id, target_name=user.full_label,
        requests=[PlannedRequest("POST", f"/users/{segment(user.id)}/revokeSignInSessions", None,
                                 "Revoke sign-in sessions")],
        warnings=["Signs the user out everywhere; they must sign in again. Access tokens already "
                  "issued can stay valid for up to an hour unless the app supports continuous "
                  "access evaluation."],
        suggested_roles=ROLES_SESSIONS,
    )


def plan_reset_password(
    user: UserSummary, new_password: str | None = None, *, target_is_admin: bool = False
) -> ActionPlan:
    """``new_password=None`` lets Entra generate one (cloud-only accounts)."""
    if user.on_prem_synced and new_password is None:
        raise PlanError("This account is synced from on-premises AD, so Entra can't generate a "
                        "password for it. Supply one (password writeback must be enabled).")
    if new_password is not None:
        problems = password_problems(new_password, user.upn)
        if problems:
            raise PlanError("Password rejected: " + "; ".join(problems) + ".")
    plan = ActionPlan(
        action="user.reset_password", title="Reset password", target_type="user",
        target_id=user.id, target_name=user.full_label,
        requests=[PlannedRequest(
            "POST", f"/users/{segment(user.id)}/authentication/methods/{PASSWORD_METHOD_ID}/resetPassword",
            {"newPassword": new_password} if new_password is not None else {},
            "Reset password", secret_keys=("newPassword",))],
        details=["New password: " + ("(you supplied one)" if new_password is not None
                                     else "(generated by Entra, shown once afterwards)")],
        warnings=["The user must change this password at their next sign-in."],
        suggested_roles=ROLES_PASSWORD_ADMIN_TARGET if target_is_admin else ROLES_PASSWORD,
    )
    if target_is_admin:
        plan.warnings.append("This user holds admin roles, so only a Privileged Authentication "
                             "Administrator or Global Administrator can reset the password.")
    return plan


def plan_set_certificate_user_ids(
    user: UserSummary, new_ids: list[str], old_ids: list[str]
) -> ActionPlan:
    """Replace the user's certificateUserIds list (Graph only supports replacing the whole list)."""
    added = [x for x in new_ids if x not in old_ids]
    removed = [x for x in old_ids if x not in new_ids]
    if not added and not removed:
        raise PlanError("No change: the certificate user IDs are already as requested.")
    plan = ActionPlan(
        action="user.certificate_user_ids", title="Update certificate user IDs", target_type="user",
        target_id=user.id, target_name=user.full_label,
        requests=[PlannedRequest("PATCH", f"/users/{segment(user.id)}",
                                 {"authorizationInfo": {"certificateUserIds": list(new_ids)}},
                                 f"Set certificateUserIds ({len(new_ids)} entries)")],
        details=[f"+ {x}" for x in added] + [f"- {x}" for x in removed],
        suggested_roles=ROLES_CERT_IDS_SYNCED if user.on_prem_synced else ROLES_CERT_IDS,
    )
    if user.on_prem_synced:
        plan.warnings.append("Synced account: Entra Connect manages this value, so the change may be "
                             "overwritten on the next sync.")
    if not new_ids:
        plan.warnings.append("This removes ALL certificate user IDs: certificate sign-in will stop "
                             "working for this user.")
    return plan


# --------------------------------------------------------------------------- #
# Plan builders: groups
# --------------------------------------------------------------------------- #

def _guard_group(group: GroupSummary, *, membership: bool) -> None:
    if group.on_prem_synced:
        raise PlanError(f"'{group.label}' is synced from on-premises AD; change it there.")
    if group.is_exchange_managed:
        raise PlanError(f"'{group.label}' is a {group.kind_label.lower()} group, managed in Exchange; "
                        "Graph can't change it. Use the Exchange admin center.")
    if membership and group.is_dynamic:
        raise PlanError(f"'{group.label}' has dynamic membership; edit its rule instead of its members.")


def _ref_body(base: str, object_id: str) -> dict[str, Any]:
    return {"@odata.id": f"{base.rstrip('/')}/directoryObjects/{object_id}"}


def _group_plan(action: str, title: str, group: GroupSummary, requests: list[PlannedRequest],
                roles: tuple[str, ...], details: list[str]) -> ActionPlan:
    plan = ActionPlan(action=action, title=title, target_type="group", target_id=group.id,
                      target_name=group.label, requests=requests, details=details, suggested_roles=roles)
    if group.is_role_assignable:
        plan.warnings.append("Role-assignable group: changing it needs Privileged Role Administrator "
                             "or Global Administrator.")
        plan.suggested_roles = ROLES_ROLE_GROUPS
    return plan


def _is_group(member: Any) -> bool:
    return isinstance(member, GroupSummary) or getattr(member, "kind", None) == "group"


def plan_add_group_members(group: GroupSummary, users: list[Any],
                           base: str = DEFAULT_GRAPH_BASE) -> ActionPlan:
    """``users`` are the objects to add: anything with ``id`` and ``label`` (users, or groups to nest).
    Only a security group can contain groups, and only security groups: a Microsoft 365 group holds users
    only and can't be nested (Graph answers a bare 400)."""
    _guard_group(group, membership=True)
    if not users:
        raise PlanError("No users given.")
    nested = [m for m in users if _is_group(m)]
    if nested and "Unified" in group.group_types:
        raise PlanError(f"'{group.label}' is a Microsoft 365 group: it can only have users as members, not groups.")
    unnestable = [m.label for m in nested if isinstance(m, GroupSummary) and "Unified" in m.group_types]
    if unnestable:
        raise PlanError("Microsoft 365 groups can't be members of another group: " + ", ".join(unnestable))
    if any(m.id == group.id for m in nested):
        raise PlanError("A group can't be a member of itself.")
    return _group_plan(
        "group.add_members", f"Add {len(users)} member(s) to {group.label}", group,
        [PlannedRequest("POST", f"/groups/{segment(group.id)}/members/$ref", _ref_body(base, u.id),
                        f"Add {u.label}") for u in users],
        ROLES_GROUP_MEMBERS, [f"+ {u.label}" for u in users])


def plan_remove_group_members(group: GroupSummary, users: list[Any]) -> ActionPlan:
    _guard_group(group, membership=True)
    if not users:
        raise PlanError("No users given.")
    return _group_plan(
        "group.remove_members", f"Remove {len(users)} member(s) from {group.label}", group,
        [PlannedRequest("DELETE", f"/groups/{segment(group.id)}/members/{segment(u.id)}/$ref", None,
                        f"Remove {u.label}") for u in users],
        ROLES_GROUP_MEMBERS, [f"- {u.label}" for u in users])


def plan_add_group_owners(group: GroupSummary, users: list[UserSummary],
                          base: str = DEFAULT_GRAPH_BASE) -> ActionPlan:
    _guard_group(group, membership=False)
    if not users:
        raise PlanError("No users given.")
    return _group_plan(
        "group.add_owners", f"Add {len(users)} owner(s) to {group.label}", group,
        [PlannedRequest("POST", f"/groups/{segment(group.id)}/owners/$ref", _ref_body(base, u.id),
                        f"Add owner {u.label}") for u in users],
        ROLES_GROUP_OWNERS, [f"+ owner {u.label}" for u in users])


def plan_remove_group_owners(group: GroupSummary, users: list[Any]) -> ActionPlan:
    _guard_group(group, membership=False)
    if not users:
        raise PlanError("No users given.")
    plan = _group_plan(
        "group.remove_owners", f"Remove {len(users)} owner(s) from {group.label}", group,
        [PlannedRequest("DELETE", f"/groups/{segment(group.id)}/owners/{segment(u.id)}/$ref", None,
                        f"Remove owner {u.label}") for u in users],
        ROLES_GROUP_OWNERS, [f"- owner {u.label}" for u in users])
    plan.warnings.append("If this removes the last owner, the group becomes unowned.")
    return plan


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #

def _fill(value: Any, new_id: str) -> Any:
    """Replace NEW_ID in a path or (nested) body."""
    if isinstance(value, str):
        return value.replace(NEW_ID, new_id)
    if isinstance(value, dict):
        return {k: _fill(v, new_id) for k, v in value.items()}
    if isinstance(value, list):
        return [_fill(v, new_id) for v in value]
    return value


def _not_replicated_yet(exc: GraphError) -> bool:
    text = str(exc).lower()
    return isinstance(exc, GraphNotFoundError) or (exc.status_code == 400 and "exist" in text and "already" not in text)


def _already_applied(request: PlannedRequest, exc: GraphError) -> bool:
    """Idempotence: adding someone already in the group, or removing someone who isn't.
    Never for a request that creates an object: "already exists" there is a real failure."""
    if request.capture_id:
        return False
    if request.method == "POST" and exc.status_code == 400 and "already exist" in str(exc).lower():
        return True
    return request.method == "DELETE" and exc.status_code == 404


def _await_operation(
    graph: GraphClient, url: str, *, sleep: Callable[[float], None], timeout: float,
    clock: Callable[[], float],
) -> tuple[str, str]:
    """Poll a long-running operation (password reset) until it succeeds, fails or times out."""
    deadline = clock() + timeout
    while True:
        body = graph.get(url)
        status = str(body.get("status", "")).lower()
        if status in ("succeeded", "failed"):
            return status, str(body.get("statusDetail") or "")
        if clock() >= deadline:
            return "timeout", ""
        sleep(2)


def execute_plan(
    graph: GraphClient,
    plan: ActionPlan,
    *,
    actor: str = "",
    dry_run: bool = False,
    log_path: Any = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    poll_timeout: float = 60.0,
) -> ActionResult:
    if dry_run:
        return ActionResult("dry_run", "Nothing was sent.",
                            [f"would send: {r.description or r.path} ({r.method})" for r in plan.requests])

    result = ActionResult("ok")
    done = failed = 0
    new_id: str | None = None

    def send(request: PlannedRequest) -> Any:
        uses_new = NEW_ID in request.path or NEW_ID in str(request.json)
        if not uses_new:
            return graph.request(request.method, request.path, json=request.json)
        path, body = _fill(request.path, new_id or ""), _fill(request.json, new_id or "")
        for attempt in range(REPLICATION_ATTEMPTS):
            try:
                return graph.request(request.method, path, json=body)
            except GraphError as exc:      # the new object isn't known everywhere yet: nothing was applied
                if not _not_replicated_yet(exc) or attempt == REPLICATION_ATTEMPTS - 1:
                    raise
                sleep(REPLICATION_WAIT)

    for request in plan.requests:
        try:
            response = send(request)
        except GraphPermissionError as exc:
            if plan.continue_on_error and done > 0 and not request.capture_id:
                failed += 1
                result.error = exc
                result.lines.append(f"{request.description}: NOT PERMITTED ({exc})")
                continue
            result.status, result.error = ("denied" if done == 0 else "partial"), exc
            result.message = f"Not permitted: {exc}"
            break
        except GraphError as exc:
            if _already_applied(request, exc):
                result.lines.append(f"{request.description}: already in that state")
                done += 1
                continue
            if plan.continue_on_error and not request.capture_id:
                failed += 1
                result.error = exc
                result.lines.append(f"{request.description}: FAILED ({exc})")
                continue
            result.status, result.error = ("failed" if done == 0 else "partial"), exc
            result.message = f"{request.description} failed: {exc}"
            break

        done += 1
        result.lines.append(f"{request.description}: done")
        for key in request.reveal:
            value = response.body.get(key) if isinstance(response.body, dict) else None
            if value:
                result.secrets[key] = str(value)
        if request.capture_id:
            new_id = str(response.body.get("id") or "")
            if not new_id:
                result.status, result.message = "partial", f"{request.description}: Graph returned no id; stopped."
                break
        if request.path.endswith("/resetPassword"):
            generated = str(response.body.get("newPassword") or "")
            if generated:
                result.secrets["password"] = generated
            if response.location:
                state, detail = _await_operation(graph, response.location, sleep=sleep,
                                                 timeout=poll_timeout, clock=clock)
                if state == "failed" and plan.continue_on_error:
                    done, failed = done - 1, failed + 1
                    result.secrets.pop("password", None)
                    result.lines[-1] = f"{request.description}: FAILED ({detail or 'no detail'})"
                elif state == "failed":
                    result.status, result.message = "failed", f"Password reset failed: {detail or 'no detail'}"
                    break
                if state == "timeout":
                    result.lines.append("Password reset is still running; check again shortly.")
    else:
        result.message = "Done."
        if failed:
            result.status = "partial" if done else "failed"
            result.message = (f"{done} of {len(plan.requests)} steps done; {failed} could not be done "
                              "(marked below).")

    if result.status == "ok" and plan.action == "user.reset_password" and "password" not in result.secrets:
        result.lines.append("Graph did not return the new password; if you didn't supply one, "
                            "reset again with --local to generate it here.")
    _record(plan, result, actor, log_path)
    return result


def _record(plan: ActionPlan, result: ActionResult, actor: str, log_path: Any) -> None:
    """Best effort: a logging problem must never turn a successful change into an error."""
    try:
        audit_log.record({
            "actor": actor, "action": plan.action, "title": plan.title,
            "target": {"type": plan.target_type, "id": plan.target_id, "name": plan.target_name},
            "requests": plan.log_requests(), "status": result.status, "message": result.message,
        }, path=log_path)
    except OSError:
        result.lines.append("(warning: could not write the local action log)")


# --------------------------------------------------------------------------- #
# Administrative units
# --------------------------------------------------------------------------- #

def _au_plan(action: str, title: str, unit: AdminUnit, requests: list[PlannedRequest],
             details: list[str]) -> ActionPlan:
    return ActionPlan(action=action, title=title, target_type="administrative unit", target_id=unit.id,
                      target_name=unit.label, requests=requests, details=details,
                      suggested_roles=ROLES_ADMIN_UNITS)


def _au_manual_membership(unit: AdminUnit) -> None:
    if unit.is_dynamic:
        raise PlanError(f"{unit.label} has dynamic membership: its members come from its rule. Change the rule, "
                        "or switch it to assigned membership first.")


def _restricted_group_problem(member: AuMember) -> str | None:
    """Restricted-management AUs only take plain cloud security groups (Graph rejects the rest)."""
    if member.kind != "group":
        return None
    if member.unified or member.mail_enabled or not member.security_enabled or member.synced:
        return f"{member.label} (only cloud security groups that aren't mail-enabled can be added)"
    return None


def plan_add_au_members(unit: AdminUnit, members: list[AuMember], base: str = DEFAULT_GRAPH_BASE) -> ActionPlan:
    _au_manual_membership(unit)
    if not members:
        raise PlanError("Nothing to add.")
    if unit.restricted:
        problems = [p for p in (_restricted_group_problem(m) for m in members) if p]
        if problems:
            raise PlanError(f"{unit.label} is a restricted management unit and can't take: " + "; ".join(problems))
    plan = _au_plan(
        "admin_unit.add_members", f"Add {len(members)} member(s) to {unit.label}", unit,
        [PlannedRequest("POST", f"/directory/administrativeUnits/{segment(unit.id)}/members/$ref",
                        _ref_body(base, m.id), f"Add {m.kind} {m.label}") for m in members],
        [f"+ {m.kind}: {m.label}" for m in members])
    if unit.restricted:
        plan.warnings.append("Restricted management unit: once added, tenant-wide admins can no longer manage these "
                             "objects; only admins assigned roles scoped to this unit can.")
    return plan


def plan_remove_au_members(unit: AdminUnit, members: list[AuMember]) -> ActionPlan:
    _au_manual_membership(unit)
    if not members:
        raise PlanError("Nothing to remove.")
    plan = _au_plan(
        "admin_unit.remove_members", f"Remove {len(members)} member(s) from {unit.label}", unit,
        [PlannedRequest("DELETE", f"/directory/administrativeUnits/{segment(unit.id)}/members/{segment(m.id)}/$ref",
                        None, f"Remove {m.kind} {m.label}") for m in members],
        [f"- {m.kind}: {m.label}" for m in members])
    plan.warnings.append("Admins whose roles are scoped to this unit lose control of the removed objects.")
    return plan


def _au_current(unit: AdminUnit) -> dict[str, Any]:
    return {"displayName": unit.display_name, "description": unit.description,
            "membershipType": (unit.membership_type or "assigned").lower(), "membershipRule": unit.membership_rule,
            "membershipRuleProcessingState": unit.processing_state}


def plan_update_admin_unit(unit: AdminUnit, changes: Mapping[str, Any]) -> ActionPlan:
    unknown = set(changes) - set(EDITABLE_AU_FIELDS)
    if unknown:
        raise PlanError("These settings can't be changed here: " + ", ".join(sorted(unknown))
                        + (" (restricted management is fixed when the unit is created)"
                           if "isMemberManagementRestricted" in unknown else ""))
    current = _au_current(unit)
    wanted = dict(changes)
    if "membershipType" in wanted and wanted["membershipType"] is not None:
        wanted["membershipType"] = str(wanted["membershipType"]).strip().lower()
        if wanted["membershipType"] not in ("assigned", "dynamic"):
            raise PlanError("Membership type must be assigned or dynamic.")
    if "membershipRuleProcessingState" in wanted and wanted["membershipRuleProcessingState"] not in (None, "On", "Paused"):
        raise PlanError("Rule processing must be On or Paused.")
    for key in ("displayName", "description", "membershipRule"):
        if isinstance(wanted.get(key), str):
            wanted[key] = wanted[key].strip() or None
    effective = {k: v for k, v in wanted.items() if (current.get(k) or None) != (v or None)}
    if not effective:
        raise PlanError("Nothing to change: the unit already has those settings.")
    if "displayName" in effective and not effective["displayName"]:
        raise PlanError("An administrative unit needs a name.")
    if len(effective.get("displayName") or "") > 256:
        raise PlanError("The name can be at most 256 characters.")
    final = {**current, **effective}
    if final["membershipType"] == "dynamic" and not final.get("membershipRule"):
        raise PlanError("Dynamic membership needs a membership rule.")
    if final["membershipType"] == "dynamic" and not final.get("membershipRuleProcessingState"):
        effective["membershipRuleProcessingState"] = "On"     # a new rule does nothing until processing is on
    plan = _au_plan(
        "admin_unit.update", f"Change settings of {unit.label}", unit,
        [PlannedRequest("PATCH", f"/directory/administrativeUnits/{segment(unit.id)}", dict(effective),
                        "Update settings")],
        [f"{k}: {_show(current.get(k))} -> {_show(v)}" for k, v in effective.items()])
    if effective.get("membershipType") == "dynamic":
        plan.warnings.append("Switching to dynamic membership replaces the current members with whoever matches "
                             "the rule (needs Entra ID P1).")
    elif effective.get("membershipType") == "assigned":
        plan.warnings.append("Switching to assigned membership stops the rule; members are then managed by hand.")
    if "membershipRule" in effective and final["membershipType"] == "dynamic":
        plan.warnings.append("A new rule re-evaluates every user and device; check it before applying.")
    return plan

