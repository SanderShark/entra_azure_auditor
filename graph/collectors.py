"""Collectors: fetch tenant data through ``GraphClient`` and parse it into models.

Two layers:

* ``parse_*`` functions are pure (raw Graph dict -> model). Unit-test them with
  recorded, anonymised JSON.
* ``TenantCollector`` does the fetching. Optional data sources that fail with
  403/404 (missing permission or licence) are skipped with a warning instead of
  aborting the whole audit; the matching ``TenantSnapshot`` field becomes
  ``None`` so checks can tell "unavailable" from "empty".
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Iterable, TypeVar

from ..models import (
    Application,
    ConditionalAccessPolicy,
    Credential,
    GroupInfo,
    MfaRegistration,
    NamedLocation,
    RoleAssignment,
    RoleDefinition,
    ServicePrincipal,
    TenantSnapshot,
    User,
)
from .client import GraphClient, GraphError, GraphNotFoundError, GraphPermissionError

T = TypeVar("T")

MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
DEFAULT_BETA_URL = "https://graph.microsoft.com/beta"

_USER_SELECT = [
    "id", "displayName", "userPrincipalName", "mail", "userType",
    "accountEnabled", "createdDateTime", "onPremisesSyncEnabled",
]
_PRINCIPAL_TYPES = {
    "#microsoft.graph.user": "user",
    "#microsoft.graph.servicePrincipal": "servicePrincipal",
    "#microsoft.graph.group": "group",
}


# --------------------------------------------------------------------------- #
# Pure parsers
# --------------------------------------------------------------------------- #

def parse_user(raw: dict[str, Any]) -> User:
    activity = raw.get("signInActivity") or {}
    return User(
        id=raw["id"],
        display_name=raw.get("displayName"),
        user_principal_name=raw.get("userPrincipalName"),
        mail=raw.get("mail"),
        user_type=raw.get("userType"),
        account_enabled=raw.get("accountEnabled"),
        created_at=raw.get("createdDateTime"),
        on_prem_synced=bool(raw.get("onPremisesSyncEnabled")),
        last_sign_in=activity.get("lastSignInDateTime"),
        last_non_interactive_sign_in=activity.get("lastNonInteractiveSignInDateTime"),
        last_successful_sign_in=activity.get("lastSuccessfulSignInDateTime"),
    )


def parse_role_definition(raw: dict[str, Any]) -> RoleDefinition:
    return RoleDefinition(
        id=raw["id"],
        display_name=raw.get("displayName") or raw["id"],
        is_built_in=raw.get("isBuiltIn", True),
        is_privileged=raw.get("isPrivileged"),
    )


def parse_role_assignment(
    raw: dict[str, Any], defs: dict[str, RoleDefinition], *, state: str
) -> RoleAssignment:
    """Handles roleAssignments, *ScheduleInstances and eligibilitySchedules alike."""
    principal = raw.get("principal") or {}
    role = defs.get(raw["roleDefinitionId"])
    schedule = raw.get("scheduleInfo") or {}
    end = raw.get("endDateTime") or (schedule.get("expiration") or {}).get("endDateTime")
    return RoleAssignment(
        principal_id=raw["principalId"],
        principal_type=_PRINCIPAL_TYPES.get(principal.get("@odata.type", ""), "unknown"),
        principal_display_name=principal.get("displayName"),
        principal_upn=principal.get("userPrincipalName"),
        role_id=raw["roleDefinitionId"],
        role_name=role.display_name if role else raw["roleDefinitionId"],
        is_privileged_role=role.is_privileged if role else None,
        state=state,
        activated_via_pim=raw.get("assignmentType") == "Activated",
        end_date_time=end,
        directory_scope_id=raw.get("directoryScopeId", "/"),
    )


def parse_mfa_registration(raw: dict[str, Any]) -> MfaRegistration:
    return MfaRegistration(
        user_id=raw["id"],
        user_principal_name=raw.get("userPrincipalName"),
        is_admin=bool(raw.get("isAdmin")),
        is_mfa_registered=bool(raw.get("isMfaRegistered")),
        is_mfa_capable=bool(raw.get("isMfaCapable")),
        is_passwordless_capable=bool(raw.get("isPasswordlessCapable")),
        methods_registered=raw.get("methodsRegistered") or [],
        default_mfa_method=raw.get("defaultMfaMethod"),
    )


def _as_list(value: Any) -> list[str]:
    """Graph sometimes returns comma-separated strings where lists are expected."""
    if not value:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return list(value)


def _guest_section(section: dict[str, Any] | None) -> tuple[bool, list[str]]:
    if not section:
        return False, []
    return True, _as_list(section.get("guestOrExternalUserTypes"))


def parse_ca_policy(raw: dict[str, Any]) -> ConditionalAccessPolicy:
    conditions = raw.get("conditions") or {}
    users = conditions.get("users") or {}
    apps = conditions.get("applications") or {}
    platforms = conditions.get("platforms") or {}
    locations = conditions.get("locations") or {}
    device_filter = (conditions.get("devices") or {}).get("deviceFilter") or {}
    workload = conditions.get("clientApplications") or {}
    flows = (conditions.get("authenticationFlows") or {}).get("transferMethods")
    grant = raw.get("grantControls") or {}
    strength = grant.get("authenticationStrength") or {}
    inc_guests, inc_guest_types = _guest_section(users.get("includeGuestsOrExternalUsers"))
    exc_guests, exc_guest_types = _guest_section(users.get("excludeGuestsOrExternalUsers"))

    return ConditionalAccessPolicy(
        id=raw["id"],
        display_name=raw.get("displayName") or raw["id"],
        state=raw.get("state", "disabled"),
        created_at=raw.get("createdDateTime"),
        modified_at=raw.get("modifiedDateTime"),
        include_users=users.get("includeUsers") or [],
        exclude_users=users.get("excludeUsers") or [],
        include_groups=users.get("includeGroups") or [],
        exclude_groups=users.get("excludeGroups") or [],
        include_roles=users.get("includeRoles") or [],
        exclude_roles=users.get("excludeRoles") or [],
        includes_guests_or_external=inc_guests,
        include_guest_types=inc_guest_types,
        excludes_guests_or_external=exc_guests,
        exclude_guest_types=exc_guest_types,
        include_service_principals=workload.get("includeServicePrincipals") or [],
        exclude_service_principals=workload.get("excludeServicePrincipals") or [],
        include_applications=apps.get("includeApplications") or [],
        exclude_applications=apps.get("excludeApplications") or [],
        include_user_actions=apps.get("includeUserActions") or [],
        include_auth_contexts=apps.get("includeAuthenticationContextClassReferences") or [],
        client_app_types=conditions.get("clientAppTypes") or [],
        include_platforms=platforms.get("includePlatforms") or [],
        exclude_platforms=platforms.get("excludePlatforms") or [],
        include_locations=locations.get("includeLocations") or [],
        exclude_locations=locations.get("excludeLocations") or [],
        device_filter_mode=device_filter.get("mode"),
        device_filter_rule=device_filter.get("rule"),
        sign_in_risk_levels=_as_list(conditions.get("signInRiskLevels")),
        user_risk_levels=_as_list(conditions.get("userRiskLevels")),
        service_principal_risk_levels=_as_list(conditions.get("servicePrincipalRiskLevels")),
        insider_risk_levels=_as_list(conditions.get("insiderRiskLevels")),
        authentication_flows=_as_list(flows),
        grant_controls=grant.get("builtInControls") or [],
        grant_operator=grant.get("operator"),
        authentication_strength_id=strength.get("id"),
        authentication_strength_name=strength.get("displayName"),
        terms_of_use=grant.get("termsOfUse") or [],
        custom_controls=grant.get("customAuthenticationFactors") or [],
        session_controls=raw.get("sessionControls") or {},
        raw=raw,
    )


def parse_named_location(raw: dict[str, Any]) -> NamedLocation:
    odata_type = raw.get("@odata.type", "")
    if odata_type.endswith("ipNamedLocation"):
        kind = "ip"
    elif odata_type.endswith("countryNamedLocation"):
        kind = "country"
    else:
        kind = "unknown"
    return NamedLocation(
        id=raw["id"],
        display_name=raw.get("displayName") or raw["id"],
        kind=kind,
        is_trusted=raw.get("isTrusted") if kind == "ip" else None,
        countries=raw.get("countriesAndRegions") or [],
        ip_range_count=len(raw.get("ipRanges") or []),
    )


def parse_credentials(raw: dict[str, Any]) -> list[Credential]:
    creds = [
        Credential(
            kind="secret", key_id=c.get("keyId"), display_name=c.get("displayName"),
            start=c.get("startDateTime"), end=c.get("endDateTime"),
        )
        for c in raw.get("passwordCredentials") or []
    ]
    creds += [
        Credential(
            kind="certificate", key_id=c.get("keyId"), display_name=c.get("displayName"),
            start=c.get("startDateTime"), end=c.get("endDateTime"),
        )
        for c in raw.get("keyCredentials") or []
    ]
    return creds


def _owner_count(raw: dict[str, Any]) -> int | None:
    owners = raw.get("owners")
    return len(owners) if owners is not None else None  # None = not expanded/unknown


def parse_application(raw: dict[str, Any]) -> Application:
    return Application(
        id=raw["id"],
        app_id=raw["appId"],
        display_name=raw.get("displayName"),
        created_at=raw.get("createdDateTime"),
        sign_in_audience=raw.get("signInAudience"),
        credentials=parse_credentials(raw),
        owner_count=_owner_count(raw),
    )


def parse_service_principal(raw: dict[str, Any]) -> ServicePrincipal:
    return ServicePrincipal(
        id=raw["id"],
        app_id=raw.get("appId"),
        display_name=raw.get("displayName"),
        service_principal_type=raw.get("servicePrincipalType"),
        account_enabled=raw.get("accountEnabled"),
        created_at=raw.get("createdDateTime"),
        app_owner_organization_id=raw.get("appOwnerOrganizationId"),
        credentials=parse_credentials(raw),
        owner_count=_owner_count(raw),
    )


_SP_ACTIVITY_KEYS = (
    "lastSignInActivity",
    "delegatedClientSignInActivity",
    "delegatedResourceSignInActivity",
    "applicationAuthenticationClientSignInActivity",
    "applicationAuthenticationResourceSignInActivity",
)


def latest_sp_sign_in(raw: dict[str, Any]) -> datetime | None:
    """Newest sign-in across all activity types in a servicePrincipalSignInActivity."""
    stamps = [
        (raw.get(key) or {}).get("lastSignInDateTime") for key in _SP_ACTIVITY_KEYS
    ]
    parsed = [
        datetime.fromisoformat(s.replace("Z", "+00:00")) for s in stamps if s
    ]
    return max(parsed) if parsed else None


# --------------------------------------------------------------------------- #
# Collector
# --------------------------------------------------------------------------- #

class TenantCollector:
    def __init__(
        self,
        graph: GraphClient,
        *,
        beta_base_url: str = DEFAULT_BETA_URL,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self._graph = graph
        self._beta = beta_base_url.rstrip("/")
        self._progress = progress or (lambda _msg: None)
        self.warnings: list[str] = []
        self.sign_in_data_available = True
        self.eligible_roles_available = True
        self.sp_sign_in_data_available = False
        self._groups_denied = False

    # -- helpers ------------------------------------------------------------ #

    def _safe(
        self,
        label: str,
        fn: Callable[[], T],
        default: T | None,
        *,
        catch: tuple[type[GraphError], ...] = (GraphPermissionError, GraphNotFoundError),
    ) -> T | None:
        """Run ``fn``; on a permission/licence problem, warn and return ``default``."""
        try:
            return fn()
        except catch as exc:
            self.warnings.append(f"{label}: skipped ({exc})")
            return default

    # -- users -------------------------------------------------------------- #

    def users(self) -> list[User]:
        """All users. Includes signInActivity when the tenant has Entra ID P1/P2."""
        try:
            raw = self._graph.get_all(
                "/users", select=_USER_SELECT + ["signInActivity"], top=999
            )
            self.sign_in_data_available = True
        except GraphPermissionError as exc:
            # signInActivity needs P1/P2 (or AuditLog.Read.All): retry without it.
            self.sign_in_data_available = False
            self.warnings.append(
                f"users: sign-in activity unavailable, inactive-account checks disabled ({exc})"
            )
            raw = self._graph.get_all("/users", select=_USER_SELECT, top=999)
        return [parse_user(r) for r in raw]

    # -- roles -------------------------------------------------------------- #

    def role_definitions(self) -> list[RoleDefinition] | None:
        return self._safe(
            "role definitions",
            lambda: [
                parse_role_definition(r)
                for r in self._graph.get_all(
                    "/roleManagement/directory/roleDefinitions",
                    select=["id", "displayName", "isBuiltIn", "isPrivileged"],
                )
            ],
            None,
        )

    def role_assignments(
        self, definitions: list[RoleDefinition]
    ) -> list[RoleAssignment] | None:
        defs = {d.id: d for d in definitions}
        base = "/roleManagement/directory"

        def active_via_pim() -> list[dict[str, Any]]:
            # Instances tell us permanent vs time-bound vs PIM-activated (needs P2).
            return self._graph.get_all(
                f"{base}/roleAssignmentScheduleInstances", expand="principal"
            )

        def active_plain() -> list[dict[str, Any]]:
            return self._graph.get_all(f"{base}/roleAssignments", expand="principal")

        try:
            raw_active = active_via_pim()
        except GraphError:
            # No PIM/P2 (or permission missing): fall back to plain assignments,
            # which can't distinguish permanent from time-bound.
            self.warnings.append(
                "role assignments: PIM schedule data unavailable; using plain assignments "
                "(all treated as active; permanent vs time-bound can't be distinguished)"
            )
            raw_active = self._safe("role assignments", active_plain, None)
            if raw_active is None:
                return None

        assignments = [parse_role_assignment(r, defs, state="active") for r in raw_active]

        raw_eligible = self._safe(
            "eligible role assignments (PIM)",
            lambda: self._graph.get_all(
                f"{base}/roleEligibilitySchedules", expand="principal"
            ),
            None,
        )
        if raw_eligible is None:
            self.eligible_roles_available = False
        else:
            assignments += [
                parse_role_assignment(r, defs, state="eligible") for r in raw_eligible
            ]

        return assignments + self._group_inherited(assignments)

    def _group_inherited(self, assignments: Iterable[RoleAssignment]) -> list[RoleAssignment]:
        """Users/SPs who hold a role only through a role-assignable group."""
        cache: dict[str, list[dict[str, Any]]] = {}
        inherited: list[RoleAssignment] = []

        for a in assignments:
            if a.principal_type != "group":
                continue
            gid = a.principal_id
            if gid not in cache:
                cache[gid] = (
                    self._safe(
                        f"members of group {a.principal_display_name or gid}",
                        lambda gid=gid: self._graph.get_all(
                            f"/groups/{gid}/transitiveMembers",
                            select=["id", "displayName", "userPrincipalName"],
                        ),
                        [],
                    )
                    or []
                )
            for member in cache[gid]:
                mtype = _PRINCIPAL_TYPES.get(member.get("@odata.type", ""))
                if mtype in (None, "group"):  # skip nested group objects themselves
                    continue
                inherited.append(
                    a.model_copy(
                        update={
                            "principal_id": member["id"],
                            "principal_type": mtype,
                            "principal_display_name": member.get("displayName"),
                            "principal_upn": member.get("userPrincipalName"),
                            "via_group_id": gid,
                        }
                    )
                )
        return inherited

    # -- MFA & Conditional Access ------------------------------------------- #

    def mfa_registrations(self) -> list[MfaRegistration] | None:
        return self._safe(
            "MFA registration details",
            lambda: [
                parse_mfa_registration(r)
                for r in self._graph.get_all(
                    "/reports/authenticationMethods/userRegistrationDetails", top=999
                )
            ],
            None,
        )

    def ca_policies(self) -> list[ConditionalAccessPolicy] | None:
        return self._safe(
            "conditional access policies",
            lambda: [
                parse_ca_policy(r)
                for r in self._graph.get_all("/identity/conditionalAccess/policies")
            ],
            None,
        )

    def security_defaults_enabled(self) -> bool | None:
        def fetch() -> bool:
            body = self._graph.get("/policies/identitySecurityDefaultsEnforcementPolicy")
            return bool(body.get("isEnabled"))

        return self._safe("security defaults", fetch, None)

    def named_locations(self) -> list[NamedLocation] | None:
        return self._safe(
            "named locations",
            lambda: [
                parse_named_location(r)
                for r in self._graph.get_all("/identity/conditionalAccess/namedLocations")
            ],
            None,
        )

    _GROUP_COUNT_PAGES = 3  # members are counted up to ~3 pages (2,997) then reported as "N+"

    def ca_groups(self, policies: list[ConditionalAccessPolicy]) -> list[GroupInfo]:
        """Resolve groups referenced by CA policies to names; size the excluded ones."""
        excluded = {g for p in policies for g in p.exclude_groups}
        included = {g for p in policies for g in p.include_groups} - excluded
        infos = (self._group_info(gid, count_members=gid in excluded)
                 for gid in sorted(excluded | included))
        return [i for i in infos if i is not None]

    def _group_info(self, group_id: str, *, count_members: bool) -> GroupInfo | None:
        if self._groups_denied:
            return None
        try:
            raw = self._graph.get(
                f"/groups/{group_id}", select=["id", "displayName", "isAssignableToRole"]
            )
        except GraphNotFoundError:
            return GroupInfo(id=group_id, exists=False)
        except GraphPermissionError as exc:
            self._groups_denied = True
            self.warnings.append(
                f"conditional access groups: names/sizes skipped, needs Group.Read.All ({exc})"
            )
            return None

        info = GroupInfo(
            id=group_id,
            display_name=raw.get("displayName"),
            is_role_assignable=raw.get("isAssignableToRole"),
        )
        if count_members:
            cap = self._GROUP_COUNT_PAGES * 999
            count = sum(
                1
                for _ in self._graph.get_paged(
                    f"/groups/{group_id}/transitiveMembers",
                    select=["id"], top=999, max_pages=self._GROUP_COUNT_PAGES,
                )
            )
            info.member_count = count
            info.member_count_is_lower_bound = count >= cap
        return info

    # -- applications & service principals ---------------------------------- #

    def applications(self) -> list[Application] | None:
        return self._safe(
            "applications",
            lambda: [
                parse_application(r)
                for r in self._graph.get_all(
                    "/applications",
                    select=[
                        "id", "appId", "displayName", "createdDateTime",
                        "signInAudience", "passwordCredentials", "keyCredentials",
                    ],
                    expand="owners($select=id)",
                    top=999,
                )
            ],
            None,
        )

    def service_principals(self) -> list[ServicePrincipal] | None:
        sps = self._safe(
            "service principals",
            lambda: [
                parse_service_principal(r)
                for r in self._graph.get_all(
                    "/servicePrincipals",
                    select=[
                        "id", "appId", "displayName", "servicePrincipalType",
                        "accountEnabled", "createdDateTime", "appOwnerOrganizationId",
                        "passwordCredentials", "keyCredentials",
                    ],
                    expand="owners($select=id)",
                    top=999,
                )
            ],
            None,
        )
        if sps is None:
            return None

        grants = self._graph_app_role_grants()
        sign_ins = self._sp_sign_ins()
        for sp in sps:
            sp.graph_app_roles = grants.get(sp.id, [])
            if sp.app_id in sign_ins:
                sp.last_sign_in = sign_ins[sp.app_id]
        return sps

    def _graph_app_role_grants(self) -> dict[str, list[str]]:
        """Microsoft Graph application permissions held by each service principal.

        One paged call against Graph's own service principal (appRoleAssignedTo)
        instead of N calls, one per app. Covers Graph permissions only, not
        roles on other resources such as Exchange or SharePoint.
        """

        def fetch() -> dict[str, list[str]]:
            resource = self._graph.get_all(
                "/servicePrincipals",
                filter=f"appId eq '{MS_GRAPH_APP_ID}'",
                select=["id", "appRoles"],
            )
            if not resource:
                return {}
            role_names = {r["id"]: r["value"] for r in resource[0].get("appRoles", [])}
            grants: dict[str, list[str]] = {}
            for a in self._graph.get_paged(
                f"/servicePrincipals/{resource[0]['id']}/appRoleAssignedTo", top=999
            ):
                if a.get("principalType") != "ServicePrincipal":
                    continue
                name = role_names.get(a.get("appRoleId"))
                if name:
                    grants.setdefault(a["principalId"], []).append(name)
            return grants

        return self._safe("Graph app role grants", fetch, {}) or {}

    def _sp_sign_ins(self) -> dict[str, datetime]:
        """Last sign-in per appId. Beta endpoint; needs AuditLog.Read.All + P1/P2."""

        def fetch() -> dict[str, datetime]:
            out: dict[str, datetime] = {}
            for r in self._graph.get_paged(
                f"{self._beta}/reports/servicePrincipalSignInActivities", top=999
            ):
                latest = latest_sp_sign_in(r)
                if latest and r.get("appId"):
                    out[r["appId"]] = latest
            return out

        # Beta can 400/403/404 depending on tenant; any GraphError degrades gracefully.
        result = self._safe("service principal sign-in activity (beta)", fetch, None,
                            catch=(GraphError,))
        self.sp_sign_in_data_available = result is not None
        return result or {}

    # -- everything --------------------------------------------------------- #

    def collect(self, tenant_id: str) -> TenantSnapshot:
        p = self._progress

        p("Users")
        users = self.users()

        p("Directory roles")
        definitions = self.role_definitions()
        assignments = self.role_assignments(definitions) if definitions is not None else None
        if definitions is None:
            self.warnings.append("role assignments: skipped (role definitions unavailable)")

        p("MFA registration")
        mfa = self.mfa_registrations()

        p("Conditional Access")
        ca = self.ca_policies()
        locations = self.named_locations() if ca is not None else None
        ca_groups = self.ca_groups(ca) if ca else None
        defaults = self.security_defaults_enabled()

        p("Applications")
        apps = self.applications()

        p("Service principals")
        sps = self.service_principals()

        return TenantSnapshot(
            tenant_id=tenant_id,
            collected_at=datetime.now(timezone.utc),
            users=users,
            sign_in_data_available=self.sign_in_data_available,
            role_definitions=definitions,
            role_assignments=assignments,
            eligible_roles_available=self.eligible_roles_available,
            mfa_registrations=mfa,
            ca_policies=ca,
            named_locations=locations,
            ca_groups=ca_groups,
            security_defaults_enabled=defaults,
            applications=apps,
            service_principals=sps,
            sp_sign_in_data_available=self.sp_sign_in_data_available,
            warnings=self.warnings,
        )