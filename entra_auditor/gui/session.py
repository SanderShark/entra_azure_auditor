"""A signed-in tenant, and how to get one. No widgets here.

``GuiSession`` has what ``toolkit.flow.ChangeFlow`` needs (``graph``, ``identity``, ``user_mode``,
``refresh()``). Sign-in is two steps so the dialog can cancel a device-code wait:
``SignInService.create_provider`` (instant) then ``SignInService.open_session`` (blocks; run it on a worker).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..auth import AuthMode, DeviceCode, UserTokenProvider, toolkit_scopes
from ..graph.client import GraphClient
from ..tenants import TenantConfig, user_settings

log = logging.getLogger(__name__)

BROWSER_TIMEOUT = 300.0   # seconds before a browser sign-in nobody finishes gives up


@dataclass
class GuiSession:
    tenant: TenantConfig
    graph: Any
    provider: Any
    identity: str
    last_refresh_error: Optional[str] = field(default=None, repr=False)

    @property
    def user_mode(self) -> bool:
        return True            # the desktop app only signs in as a user (PIM needs a person)

    def refresh(self) -> None:
        """Fetch a fresh token (a role activated moments ago may not be in the cached one)."""
        refresh = getattr(self.provider, "refresh", None)
        if refresh is None:
            return
        try:
            refresh()
            self.last_refresh_error = None
        except Exception as exc:  # noqa: BLE001 - a failed refresh must not hide the change's real result
            self.last_refresh_error = str(exc)
            log.warning("token refresh failed: %s", exc)

    def close(self) -> None:
        close = getattr(self.graph, "close", None)
        if close is not None:
            close()


class SignInService:
    """The real sign-in: MSAL user sign-in with this tenant's own token cache."""

    def create_provider(self, tenant: TenantConfig, mode: AuthMode,
                        on_device_code: Callable[[DeviceCode], None]) -> UserTokenProvider:
        settings = user_settings(tenant, mode, toolkit_scopes())
        return UserTokenProvider(settings, on_device_code=on_device_code, interactive_timeout=BROWSER_TIMEOUT)

    def open_session(self, tenant: TenantConfig, provider: Any) -> GuiSession:
        provider.get_token()     # silent from the cache when possible, else the interactive sign-in
        return GuiSession(tenant, GraphClient(provider), provider, provider.identity())

    def sign_out(self, provider: Any) -> None:
        provider.logout()
