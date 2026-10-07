"""Load everything useful about one identity in a single call.

The core attributes are mandatory; every extra (sign-in activity, groups, roles, auth methods,
certificate IDs, manager) is fetched separately and degrades to a warning if the signed-in
account or licence can't read it, so one missing permission never hides the rest.
"""

from __future__ import annotations

import itertools
import logging
from datetime import datetime
from typing import Any, Callable, TypeVar

from ..graph.client import (
    GraphAuthError,
    GraphClient,
    GraphError,
    GraphNotFoundError,
    GraphRetryExhaustedError,
)
from ..models import GROUP_KIND_LABELS, classify_group
from .models import DirRef, GroupSummary, UserProfile
from .odata import literal, segment

log = logging.getLogger(__name__)
T = TypeVar("T")

CORE_SELECT = [
    "id", "displayName", "givenName", "surname", "userPrincipalName", "mail", "mailNickname",
    "userType", "accountEnabled", "jobTitle", "department", "companyName", "officeLocation",
    "employeeId", "mobilePhone", "usageLocation", "createdDateTime", "lastPasswordChangeDateTime",
    "onPremisesSyncEnabled", "onPremisesSamAccountName", "externalUserState", "assignedLicenses",
    "proxyAddresses", "otherMails",
]

AUTH_METHOD_NAMES = {
    "passwordAuthenticationMethod": "Password",
    "microsoftAuthenticatorAuthenticationMethod": "Microsoft Authenticator",
    "passwordlessMicrosoftAuthenticatorAuthenticationMethod": "Authenticator (passwordless)",
    "phoneAuthenticationMethod": "Phone (SMS/voice)",
    "fido2AuthenticationMethod": "FIDO2 security key",
    "windowsHelloForBusinessAuthenticationMethod": "Windows Hello for Business",
    "emailAuthenticationMethod": "Email",
    "softwareOathAuthenticationMethod": "Authenticator app (TOTP)",
    "hardwareOathAuthenticationMethod": "Hardware OATH token",
    "temporaryAccessPassAuthenticationMethod": "Temporary Access Pass",
    "platformCredentialAuthenticationMethod": "Platform credential",
}


def _soft(label: str, fn: Callable[[], T], default: T, warnings: list[str]) -> T:
    """Run one optional lookup; a permission/licence problem becomes a warning."""
    try:
        return fn()
    except (GraphAuthError, GraphRetryExhaustedError):
        raise
    except GraphNotFoundError:
        return default
    except GraphError as exc:
        warnings.append(f"{label}: unavailable ({exc})")
        return default


def _to_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _dirref(item: dict[str, Any]) -> DirRef:
    odata_type = str(item.get("@odata.type", "")).rsplit(".", 1)[-1]
    name = item.get("displayName")
    if odata_type == "group":
        kind = classify_group(item.get("groupTypes") or [], bool(item.get("mailEnabled")),
                              bool(item.get("securityEnabled")))
        return DirRef(id=item["id"], name=name, kind="group", detail=GROUP_KIND_LABELS[kind])
    mapping = {"directoryRole": "role", "administrativeUnit": "admin_unit",
               "application": "application", "servicePrincipal": "service_principal"}
    return DirRef(id=item["id"], name=name, kind=mapping.get(odata_type, "object"))


def _method_name(item: dict[str, Any]) -> str:
    raw = str(item.get("@odata.type", "")).rsplit(".", 1)[-1]
    return AUTH_METHOD_NAMES.get(raw, raw.removesuffix("AuthenticationMethod") or "Unknown")


def load_user_profile(graph: GraphClient, user_id: str) -> UserProfile:
    uid = segment(user_id)
    base = f"/users/{uid}"
    warnings: list[str] = []
    raw = graph.get(base, select=CORE_SELECT)

    # -- sign-in activity (needs Entra ID P1/P2 + AuditLog.Read.All) ------------------------
    activity = _soft("sign-in activity", lambda: graph.get(base, select=["signInActivity"]).get(
        "signInActivity") or {}, None, warnings)
    sign_in_available = activity is not None
    stamps = [_to_dt(v) for v in (activity or {}).values() if isinstance(v, str)]
    last_sign_in = max((s for s in stamps if s), default=None)

    cert_ids = _soft("certificate user IDs", lambda: list(
        (graph.get(base, select=["authorizationInfo"]).get("authorizationInfo") or {}).get(
            "certificateUserIds") or []), [], warnings)

    manager = _soft("manager", lambda: (graph.get(f"{base}/manager", select=["displayName", "userPrincipalName"])
                                        .get("displayName")), None, warnings)

    memberships = _soft("group memberships", lambda: graph.get_all(
        f"{base}/memberOf", select=["id", "displayName", "groupTypes", "mailEnabled", "securityEnabled"]),
        None, warnings)
    owned = _soft("owned objects", lambda: graph.get_all(
        f"{base}/ownedObjects", select=["id", "displayName"]), None, warnings)

    def role_names(path: str) -> list[str]:
        items = graph.get_all(path, filter=f"principalId eq {literal(raw['id'])}", expand="roleDefinition")
        return sorted({(i.get("roleDefinition") or {}).get("displayName") or i.get("roleDefinitionId", "?")
                       for i in items})

    roles_active = _soft("active roles", lambda: role_names("/roleManagement/directory/roleAssignments"),
                         None, warnings)
    roles_eligible = _soft("eligible roles (PIM)", lambda: role_names(
        "/roleManagement/directory/roleEligibilitySchedules"), None, warnings)

    methods = _soft("authentication methods", lambda: sorted(
        {_method_name(m) for m in graph.get_all(f"{base}/authentication/methods")}), None, warnings)

    return UserProfile(
        id=raw["id"], upn=raw.get("userPrincipalName"), display_name=raw.get("displayName"),
        given_name=raw.get("givenName"), surname=raw.get("surname"), mail=raw.get("mail"),
        mail_nickname=raw.get("mailNickname"), user_type=raw.get("userType"),
        account_enabled=raw.get("accountEnabled"), job_title=raw.get("jobTitle"),
        department=raw.get("department"), company=raw.get("companyName"), office=raw.get("officeLocation"),
        employee_id=raw.get("employeeId"), mobile_phone=raw.get("mobilePhone"),
        usage_location=raw.get("usageLocation"), created_at=raw.get("createdDateTime"),
        last_password_change=raw.get("lastPasswordChangeDateTime"), last_sign_in=last_sign_in,
        sign_in_available=sign_in_available, on_prem_synced=bool(raw.get("onPremisesSyncEnabled")),
        on_prem_sam_account=raw.get("onPremisesSamAccountName"),
        external_user_state=raw.get("externalUserState"),
        license_count=len(raw.get("assignedLicenses") or []),
        proxy_addresses=sorted(raw.get("proxyAddresses") or []), other_mails=raw.get("otherMails") or [],
        manager=manager, cert_user_ids=cert_ids, auth_methods=methods,
        groups=None if memberships is None else [_dirref(m) for m in memberships],
        owned=None if owned is None else [_dirref(o) for o in owned],
        roles_active=roles_active, roles_eligible=roles_eligible, warnings=warnings,
    )


def get_certificate_user_ids(graph: GraphClient, user_id: str) -> list[str]:
    body = graph.get(f"/users/{segment(user_id)}", select=["authorizationInfo"])
    return list((body.get("authorizationInfo") or {}).get("certificateUserIds") or [])


def profile_current_values(profile: UserProfile) -> dict[str, Any]:
    """The editable attributes as they are now (keys match ``actions.EDITABLE_USER_FIELDS``)."""
    return {
        "displayName": profile.display_name, "givenName": profile.given_name, "surname": profile.surname,
        "jobTitle": profile.job_title, "department": profile.department, "officeLocation": profile.office,
        "companyName": profile.company, "employeeId": profile.employee_id,
        "mobilePhone": profile.mobile_phone, "usageLocation": profile.usage_location,
    }


def holds_admin_roles(profile: UserProfile) -> bool:
    return bool(profile.roles_active or profile.roles_eligible)


def list_group_people(graph: GraphClient, group_id: str, edge: str, limit: int = 100) -> tuple[list[DirRef], bool]:
    """Direct ``members`` or ``owners`` of a group (up to ``limit``) and whether it was cut off."""
    if edge not in ("members", "owners"):
        raise ValueError("edge must be 'members' or 'owners'")
    pages = graph.get_paged(f"/groups/{segment(group_id)}/{edge}",
                            select=["id", "displayName", "userPrincipalName"], top=min(limit + 1, 999))
    items = list(itertools.islice(pages, limit + 1))
    refs = [DirRef(id=i["id"], name=i.get("userPrincipalName") or i.get("displayName"),
                   kind=str(i.get("@odata.type", "")).rsplit(".", 1)[-1] or "object") for i in items[:limit]]
    return refs, len(items) > limit


def group_detail(graph: GraphClient, group: GroupSummary, limit: int = 50) -> dict[str, Any]:
    """Owners and members for the group view (members capped; exact size is not computed)."""
    owners, owners_more = list_group_people(graph, group.id, "owners", limit)
    members, members_more = list_group_people(graph, group.id, "members", limit)
    return {"owners": owners, "owners_truncated": owners_more,
            "members": members, "members_truncated": members_more}
