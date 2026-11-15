"""Load a whole directory listing once (all pages, few properties) so a UI can filter it locally.

Asking Graph on every keystroke is slow and throttled; one pass with ``$select`` and ``$top=999`` is
about one request per thousand users. A failed load raises (never returns a partial or empty list:
unknown is not empty).
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .models import DeviceSummary, GroupSummary, UserSummary
from .search import GROUP_SELECT, USER_SELECT, _group, _user

PAGE_SIZE = 999   # the largest page Graph allows for /users


class LoadCancelled(Exception):
    """The caller asked the load to stop (e.g. the user switched tenant or closed the window)."""


def load_users(
    graph: Any,
    *,
    on_progress: Optional[Callable[[int], None]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
    page_size: int = PAGE_SIZE,
) -> list[UserSummary]:
    """Every user in the tenant, sorted by display name. Reports the running count once per page."""
    users: list[UserSummary] = []
    for raw in graph.get_paged("/users", select=USER_SELECT, top=page_size):
        users.append(_user(raw, ""))
        if len(users) % page_size == 0:
            if should_cancel is not None and should_cancel():
                raise LoadCancelled()
            if on_progress is not None:
                on_progress(len(users))
    if should_cancel is not None and should_cancel():
        raise LoadCancelled()
    if on_progress is not None:
        on_progress(len(users))
    users.sort(key=lambda u: ((u.display_name or u.label).casefold(), u.label.casefold()))
    return users


def load_groups(graph: Any, *, page_size: int = PAGE_SIZE) -> list[GroupSummary]:
    """Every group in the tenant (few properties), sorted by name. Raises on failure, like load_users."""
    groups = [_group(raw) for raw in graph.get_paged("/groups", select=GROUP_SELECT, top=page_size)]
    groups.sort(key=lambda g: (g.label.casefold(), g.id))
    return groups


DEVICE_SELECT = ["id", "deviceId", "displayName", "operatingSystem", "operatingSystemVersion", "accountEnabled",
                 "trustType", "approximateLastSignInDateTime"]


def _device(raw: dict[str, Any]) -> DeviceSummary:
    return DeviceSummary(
        id=raw["id"], device_id=raw.get("deviceId"), display_name=raw.get("displayName"),
        operating_system=raw.get("operatingSystem"), os_version=raw.get("operatingSystemVersion"),
        account_enabled=raw.get("accountEnabled"), trust_type=raw.get("trustType"),
        last_sign_in=raw.get("approximateLastSignInDateTime"))


def load_devices(graph: Any, *, page_size: int = PAGE_SIZE) -> list[DeviceSummary]:
    """Every device object (Device.Read.All or Directory.Read.All), sorted by name. Raises on failure."""
    devices = [_device(raw) for raw in graph.get_paged("/devices", select=DEVICE_SELECT, top=page_size)]
    devices.sort(key=lambda d: (d.label.casefold(), d.id))
    return devices
