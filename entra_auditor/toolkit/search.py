"""Find identities by UPN, email (primary, other and proxy addresses), object ID, name,
employee ID or mail nickname.

``by="auto"`` picks sensible strategies from the shape of the text:
    GUID            -> object id
    contains '@'    -> UPN / primary mail, then proxy addresses and other mails, then prefix
    anything else   -> mail nickname / employee id (exact), then name search
and stops at the first strategy that finds something. Every typed value is escaped
(``odata.literal`` / ``search_term``) so a quote in the text can't change the query.
"""

from __future__ import annotations

import itertools
import logging
from typing import Any, Callable, Iterable

from ..graph.client import (
    GraphAuthError,
    GraphClient,
    GraphError,
    GraphNotFoundError,
    GraphRetryExhaustedError,
)
from .models import AppSummary, GroupSummary, UserSummary
from .odata import clean_query, is_guid, literal, looks_like_email, search_term, segment

log = logging.getLogger(__name__)

USER_SELECT = [
    "id", "displayName", "userPrincipalName", "mail", "userType", "accountEnabled", "jobTitle",
    "department", "employeeId", "onPremisesSyncEnabled",
]
GROUP_SELECT = [
    "id", "displayName", "mail", "description", "securityEnabled", "mailEnabled", "groupTypes",
    "onPremisesSyncEnabled", "isAssignableToRole", "membershipRule",
]
USER_STRATEGIES = ("auto", "upn", "mail", "id", "name", "alias", "employee", "proxy")


class IdentityNotFound(LookupError):
    pass


class AmbiguousIdentity(LookupError):
    def __init__(self, query: str, candidates: list):
        super().__init__(f"'{query}' matches {len(candidates)} identities")
        self.query, self.candidates = query, candidates


def _user(raw: dict[str, Any], matched_by: str) -> UserSummary:
    return UserSummary(
        id=raw["id"], upn=raw.get("userPrincipalName"), display_name=raw.get("displayName"),
        mail=raw.get("mail"), user_type=raw.get("userType"), account_enabled=raw.get("accountEnabled"),
        job_title=raw.get("jobTitle"), department=raw.get("department"), employee_id=raw.get("employeeId"),
        on_prem_synced=bool(raw.get("onPremisesSyncEnabled")), matched_by=matched_by,
    )


def _group(raw: dict[str, Any]) -> GroupSummary:
    return GroupSummary(
        id=raw["id"], display_name=raw.get("displayName"), mail=raw.get("mail"),
        description=raw.get("description"), security_enabled=bool(raw.get("securityEnabled")),
        mail_enabled=bool(raw.get("mailEnabled")), group_types=raw.get("groupTypes") or [],
        on_prem_synced=bool(raw.get("onPremisesSyncEnabled")),
        is_role_assignable=raw.get("isAssignableToRole"), membership_rule=raw.get("membershipRule"),
    )


def _soft(fn: Callable[[], list]) -> list:
    """Run one search strategy; a rejected query (400) just means 'no results from this one'.
    Permission, auth and throttling problems still surface."""
    try:
        return fn()
    except (GraphAuthError, GraphRetryExhaustedError):
        raise
    except GraphNotFoundError:
        return []
    except GraphError as exc:
        if exc.status_code == 403:
            raise
        log.debug("search strategy failed: %s", exc)
        return []


def _query_users(graph: GraphClient, limit: int, matched_by: str, *, flt: str | None = None,
                 search: str | None = None, advanced: bool = False) -> list[UserSummary]:
    params = {"$search": search} if search else None
    pages = graph.get_paged(
        "/users", select=USER_SELECT, filter=flt, top=min(limit, 999),
        count=advanced or bool(search), params=params,
    )
    return [_user(r, matched_by) for r in itertools.islice(pages, limit)]


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #

def find_users(graph: GraphClient, query: str, by: str = "auto", limit: int = 25) -> list[UserSummary]:
    q = clean_query(query)
    by = by.lower()
    if by not in USER_STRATEGIES:
        raise ValueError(f"Unknown search type '{by}'. Choose one of: {', '.join(USER_STRATEGIES)}")
    lit = literal(q)

    def by_id() -> list[UserSummary]:
        return [_user(graph.get(f"/users/{segment(q)}", select=USER_SELECT), "id")]

    def upn_or_mail() -> list[UserSummary]:
        return _query_users(graph, limit, "upn/mail",
                            flt=f"userPrincipalName eq {lit} or mail eq {lit}")

    def upn_only() -> list[UserSummary]:
        return _query_users(graph, limit, "upn", flt=f"userPrincipalName eq {lit}")

    def mail_only() -> list[UserSummary]:
        return _query_users(graph, limit, "mail", flt=f"mail eq {lit}")

    def proxy() -> list[UserSummary]:  # alias addresses (advanced query)
        flt = (f"proxyAddresses/any(p:p eq {literal('smtp:' + q)}) "
               f"or proxyAddresses/any(p:p eq {literal('SMTP:' + q)})")
        return _query_users(graph, limit, "proxy address", flt=flt, advanced=True)

    def other_mail() -> list[UserSummary]:
        return _query_users(graph, limit, "other mail",
                            flt=f"otherMails/any(c:c eq {lit})", advanced=True)

    def alias_or_employee() -> list[UserSummary]:
        return _query_users(graph, limit, "alias/employee id",
                            flt=f"mailNickname eq {lit} or employeeId eq {lit}")

    def alias_only() -> list[UserSummary]:
        return _query_users(graph, limit, "alias", flt=f"mailNickname eq {lit}")

    def employee_only() -> list[UserSummary]:
        return _query_users(graph, limit, "employee id", flt=f"employeeId eq {lit}")

    def name_search() -> list[UserSummary]:
        t = search_term(q)
        return _query_users(
            graph, limit, "name",
            search=f'"displayName:{t}" OR "userPrincipalName:{t}" OR "mail:{t}" OR "givenName:{t}" OR "surname:{t}"')

    def prefix() -> list[UserSummary]:
        return _query_users(
            graph, limit, "prefix",
            flt=f"startswith(userPrincipalName,{lit}) or startswith(mail,{lit}) or startswith(displayName,{lit})",
            advanced=True)

    if by == "auto":
        if is_guid(q):
            plan: list[Callable] = [by_id]
        elif looks_like_email(q):
            plan = [upn_or_mail, proxy, other_mail, prefix]
        else:
            # Plain text ("bob", "E100", "ng"): an exact alias/employee-id hit must NOT hide other
            # people with a similar name, so combine both and let the caller choose. (This tool
            # edits people; silently picking the first hit would be dangerous.)
            return _dedupe(_soft(alias_or_employee) + _soft(name_search))
    else:
        plan = {
            "id": [by_id], "upn": [upn_only], "mail": [mail_only, proxy, other_mail],
            "alias": [alias_only], "employee": [employee_only], "proxy": [proxy], "name": [name_search],
        }[by]

    for strategy in plan:
        found = _soft(strategy)
        if found:
            return _dedupe(found)
    return []


def _dedupe(items: Iterable) -> list:
    seen, out = set(), []
    for item in items:
        if item.id not in seen:
            seen.add(item.id)
            out.append(item)
    return out


def resolve_user(graph: GraphClient, ident: str, by: str = "auto") -> UserSummary:
    """Exactly one user, or raise ``IdentityNotFound`` / ``AmbiguousIdentity``."""
    matches = find_users(graph, ident, by=by, limit=10)
    if not matches:
        raise IdentityNotFound(f"No user found for '{ident}'.")
    if len(matches) == 1:
        return matches[0]
    lowered = ident.strip().lower()
    exact = [m for m in matches if lowered in ((m.upn or "").lower(), (m.mail or "").lower(), m.id.lower())]
    if len(exact) == 1:
        return exact[0]
    raise AmbiguousIdentity(ident, matches)


# --------------------------------------------------------------------------- #
# Groups and apps
# --------------------------------------------------------------------------- #

def find_groups(graph: GraphClient, query: str, limit: int = 25) -> list[GroupSummary]:
    q = clean_query(query)
    lit = literal(q)

    def query_groups(flt: str | None = None, search: str | None = None, advanced: bool = False):
        params = {"$search": search} if search else None
        pages = graph.get_paged("/groups", select=GROUP_SELECT, filter=flt, top=min(limit, 999),
                                count=advanced or bool(search), params=params)
        return [_group(r) for r in itertools.islice(pages, limit)]

    if is_guid(q):
        return _soft(lambda: [_group(graph.get(f"/groups/{segment(q)}", select=GROUP_SELECT))])
    plans: list[Callable] = []
    if looks_like_email(q):
        plans.append(lambda: query_groups(flt=f"mail eq {lit}"))
    plans += [
        lambda: query_groups(flt=f"displayName eq {lit}"),
        lambda: query_groups(flt=f"startswith(displayName,{lit})"),
        lambda: query_groups(search=f'"displayName:{search_term(q)}"'),
    ]
    for plan in plans:
        found = _soft(plan)
        if found:
            return _dedupe(found)
    return []


def resolve_group(graph: GraphClient, ident: str) -> GroupSummary:
    matches = find_groups(graph, ident, limit=10)
    if not matches:
        raise IdentityNotFound(f"No group found for '{ident}'.")
    if len(matches) == 1:
        return matches[0]
    lowered = ident.strip().lower()
    exact = [m for m in matches if lowered in ((m.display_name or "").lower(), (m.mail or "").lower(), m.id.lower())]
    if len(exact) == 1:
        return exact[0]
    raise AmbiguousIdentity(ident, matches)


def get_user(graph: GraphClient, user_id: str) -> UserSummary:
    """One user by object id (direct lookup, no searching)."""
    try:
        return _user(graph.get(f"/users/{segment(user_id)}", select=USER_SELECT), "id")
    except GraphNotFoundError as exc:
        raise IdentityNotFound(f"No user with id '{user_id}'.") from exc


def get_group(graph: GraphClient, group_id: str) -> GroupSummary:
    """One group by object id (direct lookup, no searching)."""
    try:
        return _group(graph.get(f"/groups/{segment(group_id)}", select=GROUP_SELECT))
    except GraphNotFoundError as exc:
        raise IdentityNotFound(f"No group with id '{group_id}'.") from exc


def find_apps(graph: GraphClient, query: str, limit: int = 25) -> list[AppSummary]:
    """Service principals (enterprise apps / managed identities) by name, app id or object id."""
    q = clean_query(query)
    lit = literal(q)
    flt = (f"appId eq {lit} or id eq {lit}" if is_guid(q) else f"startswith(displayName,{lit})")
    select = ["id", "appId", "displayName", "servicePrincipalType", "accountEnabled"]

    def run() -> list[AppSummary]:
        pages = graph.get_paged("/servicePrincipals", select=select, filter=flt, top=min(limit, 999))
        return [
            AppSummary(id=r["id"], app_id=r.get("appId"), display_name=r.get("displayName"),
                       service_principal_type=r.get("servicePrincipalType"),
                       account_enabled=r.get("accountEnabled"))
            for r in itertools.islice(pages, limit)
        ]
    return _soft(run)
