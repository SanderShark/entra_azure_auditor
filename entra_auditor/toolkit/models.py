"""Models for the identity toolkit."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from ..models import GROUP_KIND_LABELS, classify_group


class UserSummary(BaseModel):
    id: str
    upn: str | None = None
    display_name: str | None = None
    mail: str | None = None
    user_type: str | None = None
    account_enabled: bool | None = None
    job_title: str | None = None
    department: str | None = None
    employee_id: str | None = None
    on_prem_synced: bool = False
    matched_by: str = ""

    @property
    def label(self) -> str:
        return self.upn or self.mail or self.display_name or self.id

    @property
    def is_guest(self) -> bool:
        return (self.user_type or "").lower() == "guest"


class GroupSummary(BaseModel):
    id: str
    display_name: str | None = None
    mail: str | None = None
    description: str | None = None
    security_enabled: bool = False
    mail_enabled: bool = False
    group_types: list[str] = Field(default_factory=list)
    on_prem_synced: bool = False
    is_role_assignable: bool | None = None
    membership_rule: str | None = None

    @property
    def label(self) -> str:
        return self.display_name or self.mail or self.id

    @property
    def kind(self) -> str:
        return classify_group(self.group_types, self.mail_enabled, self.security_enabled)

    @property
    def kind_label(self) -> str:
        return GROUP_KIND_LABELS[self.kind]

    @property
    def is_dynamic(self) -> bool:
        return "DynamicMembership" in self.group_types

    @property
    def is_exchange_managed(self) -> bool:
        return self.kind in ("mail_enabled_security", "distribution")


class AppSummary(BaseModel):
    id: str
    app_id: str | None = None
    display_name: str | None = None
    service_principal_type: str | None = None
    account_enabled: bool | None = None

    @property
    def label(self) -> str:
        return self.display_name or self.app_id or self.id


class DirRef(BaseModel):
    """A directory object a user belongs to or owns."""
    id: str
    name: str | None = None
    kind: str = "object"   # group | role | admin_unit | application | service_principal | object
    detail: str | None = None

    @property
    def label(self) -> str:
        base = self.name or self.id
        return f"{base} ({self.detail})" if self.detail else base


class UserProfile(BaseModel):
    id: str
    upn: str | None = None
    display_name: str | None = None
    given_name: str | None = None
    surname: str | None = None
    mail: str | None = None
    mail_nickname: str | None = None
    user_type: str | None = None
    account_enabled: bool | None = None
    job_title: str | None = None
    department: str | None = None
    company: str | None = None
    office: str | None = None
    employee_id: str | None = None
    mobile_phone: str | None = None
    usage_location: str | None = None
    created_at: datetime | None = None
    last_password_change: datetime | None = None
    last_sign_in: datetime | None = None
    sign_in_available: bool = True
    on_prem_synced: bool = False
    on_prem_sam_account: str | None = None
    external_user_state: str | None = None
    license_count: int = 0
    proxy_addresses: list[str] = Field(default_factory=list)
    other_mails: list[str] = Field(default_factory=list)
    manager: str | None = None
    cert_user_ids: list[str] = Field(default_factory=list)
    auth_methods: list[str] | None = None      # None = could not be read
    groups: list[DirRef] | None = None
    owned: list[DirRef] | None = None
    roles_active: list[str] | None = None
    roles_eligible: list[str] | None = None
    warnings: list[str] = Field(default_factory=list)

    @property
    def is_guest(self) -> bool:
        return (self.user_type or "").lower() == "guest"

    @property
    def label(self) -> str:
        return self.upn or self.mail or self.display_name or self.id
