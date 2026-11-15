"""Licences: what the tenant has bought, what one user holds and where each licence comes from.

A user gets a licence directly or through a group (group-based licensing). Only direct assignments can be
changed on the user; an inherited one goes away by leaving the group. Changes are planned in
toolkit/actions.py (``plan_change_licences``).

Endpoints (Microsoft Graph v1.0):
    GET  /subscribedSkus                                              Directory.Read.All
    GET  /users/{id}?$select=assignedLicenses,licenseAssignmentStates,usageLocation
    POST /users/{id}/assignLicense   {addLicenses: [{skuId, disabledPlans}], removeLicenses: [skuId]}
         delegated User.ReadWrite.All (or LicenseAssignment.ReadWrite.All); License Administrator or
         User Administrator. A licence can only be assigned to a user with a usage location.

NOT VERIFIED AGAINST A LIVE TENANT (built from the Graph docs and tested against a fake). See CLAUDE.md.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel

from ..graph.client import GraphAuthError, GraphError, GraphRetryExhaustedError
from .odata import segment

# Friendly names for common products. The part number is always shown too, so an unknown or renamed
# product is still identifiable.
FRIENDLY = {
    "SPE_E3": "Microsoft 365 E3", "SPE_E5": "Microsoft 365 E5", "SPE_F1": "Microsoft 365 F3",
    "SPB": "Microsoft 365 Business Premium", "O365_BUSINESS_PREMIUM": "Microsoft 365 Business Standard",
    "O365_BUSINESS_ESSENTIALS": "Microsoft 365 Business Basic", "STANDARDPACK": "Office 365 E1",
    "ENTERPRISEPACK": "Office 365 E3", "ENTERPRISEPREMIUM": "Office 365 E5", "DESKLESSPACK": "Office 365 F3",
    "EMS": "Enterprise Mobility + Security E3", "EMSPREMIUM": "Enterprise Mobility + Security E5",
    "AAD_PREMIUM": "Microsoft Entra ID P1", "AAD_PREMIUM_P2": "Microsoft Entra ID P2",
    "EXCHANGESTANDARD": "Exchange Online (Plan 1)", "EXCHANGEENTERPRISE": "Exchange Online (Plan 2)",
    "POWER_BI_STANDARD": "Power BI (free)", "POWER_BI_PRO": "Power BI Pro", "FLOW_FREE": "Power Automate (free)",
    "VISIOCLIENT": "Visio Plan 2", "PROJECTPROFESSIONAL": "Project Plan 3", "MCOEV": "Teams Phone Standard",
    "INTUNE_A": "Microsoft Intune Plan 1", "Microsoft_365_Copilot": "Microsoft 365 Copilot",
}


class Sku(BaseModel):
    """One product the tenant subscribes to."""
    sku_id: str
    part_number: Optional[str] = None
    total: Optional[int] = None         # units bought and usable
    used: Optional[int] = None
    status: Optional[str] = None        # Enabled | Warning | Suspended | Deleted | LockedOut
    applies_to: Optional[str] = None    # User | Company

    @property
    def name(self) -> str:
        friendly = FRIENDLY.get(self.part_number or "")
        return f"{friendly} ({self.part_number})" if friendly else self.part_number or self.sku_id

    @property
    def available(self) -> Optional[int]:
        return None if self.total is None or self.used is None else max(self.total - self.used, 0)

    @property
    def assignable(self) -> bool:
        return (self.status or "Enabled") in ("Enabled", "Warning") and (self.applies_to or "User") == "User"

    @property
    def usage(self) -> str:
        if self.available is None:
            return "availability unknown"
        return f"{self.available:,} of {self.total:,} free"


class UserLicence(BaseModel):
    sku_id: str
    name: str
    direct: bool = False
    groups: list[str] = []              # names of the groups it is inherited from
    problems: list[str] = []            # assignment errors (e.g. no licences left in the group's pool)

    @property
    def source(self) -> str:
        parts = (["direct"] if self.direct else []) + [f"from group {g}" for g in self.groups]
        return ", ".join(parts) or "direct"

    @property
    def label(self) -> str:
        return f"{self.name}  -  {self.source}" + (f"  (! {'; '.join(self.problems)})" if self.problems else "")


class LicenceReport(BaseModel):
    """None = could not be read (unknown is not empty)."""
    user_id: str
    usage_location: Optional[str] = None
    licences: Optional[list[UserLicence]] = None
    skus: Optional[list[Sku]] = None
    warnings: list[str] = []


def _sku(raw: dict[str, Any]) -> Sku:
    return Sku(sku_id=str(raw["skuId"]), part_number=raw.get("skuPartNumber"),
               total=(raw.get("prepaidUnits") or {}).get("enabled"), used=raw.get("consumedUnits"),
               status=raw.get("capabilityStatus"), applies_to=raw.get("appliesTo"))


def list_skus(graph: Any) -> list[Sku]:
    """The tenant's subscriptions, sorted by name. Raises on failure."""
    return sorted((_sku(r) for r in graph.get_all("/subscribedSkus")), key=lambda s: s.name.casefold())


def load_user_licences(graph: Any, user_id: str) -> LicenceReport:
    report = LicenceReport(user_id=user_id)

    def soft(label: str, fn: Any) -> Any:
        try:
            return fn()
        except GraphError as exc:
            if isinstance(exc, (GraphAuthError, GraphRetryExhaustedError)):
                raise
            report.warnings.append(f"{label} couldn't be read ({exc}).")
            return None

    report.skus = soft("The tenant's subscriptions", lambda: list_skus(graph))
    names = {s.sku_id: s.name for s in report.skus or []}
    raw = soft("The user's licences", lambda: graph.get(
        f"/users/{segment(user_id)}", select=["assignedLicenses", "licenseAssignmentStates", "usageLocation"]))
    if raw is None:
        return report
    report.usage_location = raw.get("usageLocation")

    group_names: dict[str, str] = {}

    def group_name(group_id: str) -> str:
        if group_id not in group_names:
            try:
                group_names[group_id] = graph.get(f"/groups/{segment(group_id)}",
                                                  select=["id", "displayName"]).get("displayName") or group_id
            except GraphError as exc:
                if isinstance(exc, (GraphAuthError, GraphRetryExhaustedError)):
                    raise
                group_names[group_id] = group_id
        return group_names[group_id]

    found: dict[str, UserLicence] = {}
    states = raw.get("licenseAssignmentStates")
    for state in states or []:
        sku_id = str(state.get("skuId"))
        licence = found.setdefault(sku_id, UserLicence(sku_id=sku_id, name=names.get(sku_id, sku_id)))
        group_id = state.get("assignedByGroup")
        if group_id:
            licence.groups.append(group_name(str(group_id)))
        else:
            licence.direct = True
        if str(state.get("state") or "Active").lower() == "error":
            licence.problems.append(str(state.get("error") or "assignment error"))
    for assigned in raw.get("assignedLicenses") or []:      # no states returned: everything listed is in effect
        sku_id = str(assigned.get("skuId"))
        if sku_id not in found:
            found[sku_id] = UserLicence(sku_id=sku_id, name=names.get(sku_id, sku_id), direct=states is None or not states)
    report.licences = sorted(found.values(), key=lambda lic: lic.name.casefold())
    return report
