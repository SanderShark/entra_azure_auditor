"""Shared pieces for the desktop-app tests. Import only from test modules that already did
``pytest.importorskip("PySide6")``."""

from __future__ import annotations

from entra_auditor.tenants import TenantConfig
from tests.fakes import FakeTenant

TENANT = TenantConfig("Contoso", "11111111-2222-3333-4444-555555555555", "client-1")


class FakeProvider:
    def __init__(self):
        self.refreshes = 0

    def refresh(self):
        self.refreshes += 1

    def identity(self):
        return "user:me@contoso.com"


class FakeSession:
    """What the GUI needs from a signed-in session, over the permission-enforcing FakeTenant."""

    def __init__(self, tenant: FakeTenant | None = None):
        self.tenant = TENANT
        self.graph = tenant or FakeTenant()
        self.provider = FakeProvider()
        self.identity = "user:me@contoso.com"
        self.user_mode = True
        self.closed = False

    def refresh(self):
        self.provider.refresh()

    def close(self):
        self.closed = True

