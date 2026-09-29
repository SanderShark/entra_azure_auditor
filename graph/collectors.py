"""Plain data models for what the collectors read from Microsoft Graph.

Checks operate on these, never on raw Graph JSON, so they stay pure and easy to
unit test. (The ``Finding`` model will join these later.)

Convention: on ``TenantSnapshot``, ``None`` means "could not be collected"
(missing permission or licence), while an empty list means "collected, and
there is genuinely nothing". Checks must treat the two differently.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal"""Plain data models for what the collectors read from Microsoft Graph.

Checks operate on these, never on raw Graph JSON, so they stay pure and easy to
unit test. (The ``Finding`` model will join these later.)

Convention: on ``TenantSnapshot``, ``None`` means "could not be collected"
(missing permission or licence), while an empty list means "collected, and
there is genuinely nothing". Checks must treat the two differently.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

MICROSOFT_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"  # owner of first-party apps


def _latest(*values: datetime | None) -> datetime | None:
    present = [v for v in values if v is not None]
    return max(present) if present else None


# ------------------------------------------------------------------ users --

class User(BaseModel):
    id: str
    display_name: str | None = None
    user_principal_name: str | None = None
    mail: str | None = None
    user_type: str | None = None  # "Member" | "Guest"
    account_enabled: bool | None = None
    created_at: datetime | None = None
    on_prem_synced: bool = False
    last_sign_in: datetime | None = None                 # interactive
    last_non_interactive_sign_in: datetime | None = None
    last_successful_sign_in: datetime | None = None

    @property
    def is_guest(self) -> bool:
        return (self.user_type or "").lower() == "guest"

    @property
    def last_activity(self) -> datetime | None:
        """Most recent sign-in of any kind (None = never signed in / unknown)."""
        return _latest(
            self.last_sign_in, self.last_non_interactive_sign_in, self.last_successful_sign_in
        )


# ------------------------------------------------------------------ roles --

class RoleDefinition(BaseModel):
    id: str
    display_name: str
    is_built_in: bool = True
    is_privileged: bool | None = None  # Microsoft's own "privileged role" flag


class RoleAssignment(BaseModel):
    principal_id: str
    principal_type: Literal["user", "servicePrincipal", "group", "unknown"] = "unknown"
    principal_display_name: str | None = None
    principal_upn: str | None = None
    role_id: str
    role_name: str
    is_privileged_role: bool | None = None
    state: Literal["active", "eligible"] = "active"
    activated_via_pim: bool = False       # a temporary activation of an eligible role
    end_date_time: datetime | None = None
    directory_scope_id: str = "/"
    via_group_id: str | None = None       # set when inherited through a role-assignable group

    @property
    def is_permanent(self) -> bool:
        """Standing access: active, not a PIM activation, and never expires."""
        return self.state == "active" and not self.activated_via_pim and self.end_date_time is None


# -------------------------------------------------------------------- MFA --

class MfaRegistration(BaseModel):
    user_id: str
    user_principal_name: str | None = None
    is_admin: bool = False
    is_mfa_registered: bool = False
    is_mfa_capable: bool = False
    is_passwordless_capable: bool = False
    methods_registered: list[str] = Field(default_factory=list)
    default_mfa_method: str | None = None


# ------------------------------------------------- Conditional Access -----

class ConditionalAccessPolicy(BaseModel):
    id: str
    display_name: str
    state: str  # enabled | disabled | enabledForReportingButNotEnforced
    include_users: list[str] = Field(default_factory=list)   # ids, "All", "GuestsOrExternalUsers", "None"
    exclude_users: list[str] = Field(default_factory=list)
    include_groups: list[str] = Field(default_factory=list)
    exclude_groups: list[str] = Field(default_factory=list)
    include_roles: list[str] = Field(default_factory=list)   # role template ids
    exclude_roles: list[str] = Field(default_factory=list)
    includes_guests_or_external: bool = False
    include_applications: list[str] = Field(default_factory=list)
    exclude_applications: list[str] = Field(default_factory=list)
    client_app_types: list[str] = Field(default_factory=list)
    sign_in_risk_levels: list[str] = Field(default_factory=list)
    user_risk_levels: list[str] = Field(default_factory=list)
    grant_controls: list[str] = Field(default_factory=list)  # "mfa", "block", ...
    grant_operator: str | None = None                        # "AND" | "OR"
    authentication_strength_id: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    @property
    def is_enabled(self) -> bool:
        return self.state == "enabled"

    @property
    def is_report_only(self) -> bool:
        return self.state == "enabledForReportingButNotEnforced"

    @property
    def requires_mfa(self) -> bool:
        return "mfa" in self.grant_controls or self.authentication_strength_id is not None

    @property
    def blocks_access(self) -> bool:
        return "block" in self.grant_controls


# ------------------------------------------------ apps & service principals

class Credential(BaseModel):
    kind: Literal["secret", "certificate"]
    key_id: str | None = None
    display_name: str | None = None
    start: datetime | None = None
    end: datetime | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.end is not None and self.end < now


class Application(BaseModel):
    """App *registration* (where secrets/certs usually live)."""
    id: str
    app_id: str
    display_name: str | None = None
    created_at: datetime | None = None
    sign_in_audience: str | None = None
    credentials: list[Credential] = Field(default_factory=list)
    owner_count: int | None = None


class ServicePrincipal(BaseModel):
    """Enterprise app / managed identity in this tenant."""
    id: str
    app_id: str | None = None
    display_name: str | None = None
    service_principal_type: str | None = None  # Application | ManagedIdentity | Legacy | SocialIdp
    account_enabled: bool | None = None
    created_at: datetime | None = None
    app_owner_organization_id: str | None = None
    credentials: list[Credential] = Field(default_factory=list)
    owner_count: int | None = None
    last_sign_in: datetime | None = None                       # None = never / unknown
    graph_app_roles: list[str] = Field(default_factory=list)   # e.g. "Directory.ReadWrite.All"

    @property
    def is_microsoft_first_party(self) -> bool:
        return self.app_owner_organization_id == MICROSOFT_TENANT_ID


# --------------------------------------------------------------- snapshot --

class TenantSnapshot(BaseModel):
    tenant_id: str
    collected_at: datetime
    users: list[User] = Field(default_factory=list)
    sign_in_data_available: bool = True        # False without Entra ID P1/P2
    role_definitions: list[RoleDefinition] | None = None
    role_assignments: list[RoleAssignment] | None = None
    eligible_roles_available: bool = True      # False without PIM (P2)
    mfa_registrations: list[MfaRegistration] | None = None
    ca_policies: list[ConditionalAccessPolicy] | None = None
    security_defaults_enabled: bool | None = None
    applications: list[Application] | None = None
    service_principals: list[ServicePrincipal] | None = None
    sp_sign_in_data_available: bool = False
    warnings: list[str] = Field(default_factory=list)

from pydantic import BaseModel, Field

MICROSOFT_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"  # owner of first-party apps


def _latest(*values: datetime | None) -> datetime | None:
    present = [v for v in values if v is not None]
    return max(present) if present else None


# ------------------------------------------------------------------ users --

class User(BaseModel):
    id: str
    display_name: str | None = None
    user_principal_name: str | None = None
    mail: str | None = None
    user_type: str | None = None  # "Member" | "Guest"
    account_enabled: bool | None = None
    created_at: datetime | None = None
    on_prem_synced: bool = False
    last_sign_in: datetime | None = None                 # interactive
    last_non_interactive_sign_in: datetime | None = None
    last_successful_sign_in: datetime | None = None

    @property
    def is_guest(self) -> bool:
        return (self.user_type or "").lower() == "guest"

    @property
    def last_activity(self) -> datetime | None:
        """Most recent sign-in of any kind (None = never signed in / unknown)."""
        return _latest(
            self.last_sign_in, self.last_non_interactive_sign_in, self.last_successful_sign_in
        )


# ------------------------------------------------------------------ roles --

class RoleDefinition(BaseModel):
    id: str
    display_name: str
    is_built_in: bool = True
    is_privileged: bool | None = None  # Microsoft's own "privileged role" flag


class RoleAssignment(BaseModel):
    principal_id: str
    principal_type: Literal["user", "servicePrincipal", "group", "unknown"] = "unknown"
    principal_display_name: str | None = None
    principal_upn: str | None = None
    role_id: str
    role_name: str
    is_privileged_role: bool | None = None
    state: Literal["active", "eligible"] = "active"
    activated_via_pim: bool = False       # a temporary activation of an eligible role
    end_date_time: datetime | None = None
    directory_scope_id: str = "/"
    via_group_id: str | None = None       # set when inherited through a role-assignable group

    @property
    def is_permanent(self) -> bool:
        """Standing access: active, not a PIM activation, and never expires."""
        return self.state == "active" and not self.activated_via_pim and self.end_date_time is None


# -------------------------------------------------------------------- MFA --

class MfaRegistration(BaseModel):
    user_id: str
    user_principal_name: str | None = None
    is_admin: bool = False
    is_mfa_registered: bool = False
    is_mfa_capable: bool = False
    is_passwordless_capable: bool = False
    methods_registered: list[str] = Field(default_factory=list)
    default_mfa_method: str | None = None


# ------------------------------------------------- Conditional Access -----

class ConditionalAccessPolicy(BaseModel):
    id: str
    display_name: str
    state: str  # enabled | disabled | enabledForReportingButNotEnforced
    include_users: list[str] = Field(default_factory=list)   # ids, "All", "GuestsOrExternalUsers", "None"
    exclude_users: list[str] = Field(default_factory=list)
    include_groups: list[str] = Field(default_factory=list)
    exclude_groups: list[str] = Field(default_factory=list)
    include_roles: list[str] = Field(default_factory=list)   # role template ids
    exclude_roles: list[str] = Field(default_factory=list)
    includes_guests_or_external: bool = False
    include_applications: list[str] = Field(default_factory=list)
    exclude_applications: list[str] = Field(default_factory=list)
    client_app_types: list[str] = Field(default_factory=list)
    sign_in_risk_levels: list[str] = Field(default_factory=list)
    user_risk_levels: list[str] = Field(default_factory=list)
    grant_controls: list[str] = Field(default_factory=list)  # "mfa", "block", ...
    grant_operator: str | None = None                        # "AND" | "OR"
    authentication_strength_id: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    @property
    def is_enabled(self) -> bool:
        return self.state == "enabled"

    @property
    def is_report_only(self) -> bool:
        return self.state == "enabledForReportingButNotEnforced"

    @property
    def requires_mfa(self) -> bool:
        return "mfa" in self.grant_controls or self.authentication_strength_id is not None

    @property
    def blocks_access(self) -> bool:
        return "block" in self.grant_controls


# ------------------------------------------------ apps & service principals

class Credential(BaseModel):
    kind: Literal["secret", "certificate"]
    key_id: str | None = None
    display_name: str | None = None
    start: datetime | None = None
    end: datetime | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.end is not None and self.end < now


class Application(BaseModel):
    """App *registration* (where secrets/certs usually live)."""
    id: str
    app_id: str
    display_name: str | None = None
    created_at: datetime | None = None
    sign_in_audience: str | None = None
    credentials: list[Credential] = Field(default_factory=list)
    owner_count: int | None = None


class ServicePrincipal(BaseModel):
    """Enterprise app / managed identity in this tenant."""
    id: str
    app_id: str | None = None
    display_name: str | None = None
    service_principal_type: str | None = None  # Application | ManagedIdentity | Legacy | SocialIdp
    account_enabled: bool | None = None
    created_at: datetime | None = None
    app_owner_organization_id: str | None = None
    credentials: list[Credential] = Field(default_factory=list)
    owner_count: int | None = None
    last_sign_in: datetime | None = None                       # None = never / unknown
    graph_app_roles: list[str] = Field(default_factory=list)   # e.g. "Directory.ReadWrite.All"

    @property
    def is_microsoft_first_party(self) -> bool:
        return self.app_owner_organization_id == MICROSOFT_TENANT_ID


# --------------------------------------------------------------- snapshot --

class TenantSnapshot(BaseModel):
    tenant_id: str
    collected_at: datetime
    users: list[User] = Field(default_factory=list)
    sign_in_data_available: bool = True        # False without Entra ID P1/P2
    role_definitions: list[RoleDefinition] | None = None
    role_assignments: list[RoleAssignment] | None = None
    eligible_roles_available: bool = True      # False without PIM (P2)
    mfa_registrations: list[MfaRegistration] | None = None
    ca_policies: list[ConditionalAccessPolicy] | None = None
    security_defaults_enabled: bool | None = None
    applications: list[Application] | None = None
    service_principals: list[ServicePrincipal] | None = None
    sp_sign_in_data_available: bool = False
    warnings: list[str] = Field(default_factory=list)