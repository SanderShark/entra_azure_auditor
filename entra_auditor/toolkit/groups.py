"""What is in a group: members, owners and what the group itself belongs to (for the Groups page).

Reads only; membership and owner changes are planned in toolkit/actions.py (``plan_add_group_members`` ...).
Each part degrades on its own: a part that can't be read is None with the reason (unknown is not empty).

Endpoints (Microsoft Graph v1.0): GET /groups/{id}/members, /owners, /memberOf  (Directory.Read.All).
Members can be users, groups, devices, service principals and contacts in a security group; a Microsoft 365
group only holds users (docs: "Add members").
"""

from __future__ import annotations

import itertools
from typing import Any, Optional

from pydantic import BaseModel

from ..graph.client import GraphAuthError, GraphError, GraphRetryExhaustedError
from .odata import segment

PEOPLE_SELECT = ["id", "displayName", "userPrincipalName", "mail", "accountEnabled"]
PEOPLE_LIMIT = 5000          # rows shown per list; a bigger group says so instead of loading for minutes
KINDS = {"user": "user", "group": "group", "device": "device", "serviceprincipal": "app",
         "orgcontact": "contact", "administrativeunit": "unit", "directoryrole": "role"}
KIND_ORDER = {"user": 0, "group": 1, "device": 2, "app": 3, "contact": 4, "unit": 5, "role": 6}


class GroupPerson(BaseModel):
    """A member, an owner, or something the group belongs to."""
    id: str
    kind: str = "object"            # user | group | device | app | contact | unit | role | object
    name: Optional[str] = None
    detail: Optional[str] = None    # UPN or mail
    enabled: Optional[bool] = None  # users and devices

    @property
    def label(self) -> str:
        return self.name or self.detail or self.id


class GroupContents(BaseModel):
    """None = could not be read; the matching ``*_error`` says why."""
    members: Optional[list[GroupPerson]] = None
    members_truncated: bool = False
    members_error: Optional[str] = None
    owners: Optional[list[GroupPerson]] = None
    owners_error: Optional[str] = None
    parents: Optional[list[GroupPerson]] = None      # groups, administrative units and roles it is in
    parents_error: Optional[str] = None


def _person(raw: dict[str, Any]) -> GroupPerson:
    kind = KINDS.get(str(raw.get("@odata.type", "")).rsplit(".", 1)[-1].lower(), "object")
    return GroupPerson(id=raw["id"], kind=kind, name=raw.get("displayName"),
                       detail=raw.get("userPrincipalName") or raw.get("mail"), enabled=raw.get("accountEnabled"))


def _sorted(people: list[GroupPerson]) -> list[GroupPerson]:
    return sorted(people, key=lambda p: (KIND_ORDER.get(p.kind, 9), p.label.casefold(), p.id))


def load_group_people(graph: Any, group_id: str, edge: str, limit: int = PEOPLE_LIMIT) -> tuple[list[GroupPerson], bool]:
    """Direct ``members`` or ``owners`` (up to ``limit``), sorted, and whether the list was cut off."""
    if edge not in ("members", "owners"):
        raise ValueError("edge must be 'members' or 'owners'")
    pages = graph.get_paged(f"/groups/{segment(group_id)}/{edge}", select=PEOPLE_SELECT, top=999)
    raw = list(itertools.islice(pages, limit + 1))
    return _sorted([_person(r) for r in raw[:limit]]), len(raw) > limit


def load_group_contents(graph: Any, group_id: str, limit: int = PEOPLE_LIMIT) -> GroupContents:
    contents = GroupContents()

    def soft(fn: Any) -> tuple[Any, Optional[str]]:
        try:
            return fn(), None
        except GraphError as exc:
            if isinstance(exc, (GraphAuthError, GraphRetryExhaustedError)):
                raise
            return None, str(exc)

    found, contents.members_error = soft(lambda: load_group_people(graph, group_id, "members", limit))
    if found is not None:
        contents.members, contents.members_truncated = found
    found, contents.owners_error = soft(lambda: load_group_people(graph, group_id, "owners", limit))
    if found is not None:
        contents.owners = found[0]
    found, contents.parents_error = soft(lambda: graph.get_all(
        f"/groups/{segment(group_id)}/memberOf", select=["id", "displayName"]))
    if found is not None:
        contents.parents = _sorted([_person(r) for r in found])
    return contents
