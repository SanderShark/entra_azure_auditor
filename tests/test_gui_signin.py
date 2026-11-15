"""The sign-in dialog, with a fake sign-in service (no MSAL, no network)."""

import threading

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QDialog  # noqa: E402

from entra_auditor.auth import AuthenticationError, AuthMode, DeviceCode  # noqa: E402
from entra_auditor.gui.signin import SignInDialog  # noqa: E402
from entra_auditor.tenants import TenantConfig  # noqa: E402
from tests.gui_support import TENANT, FakeSession  # noqa: E402

CODE = DeviceCode("ABC123", "https://microsoft.com/devicelogin", "Go to ... and enter ABC123")


class WaitingProvider:
    """Shows a device code, then waits until the test releases it or the dialog cancels."""

    def __init__(self, on_device_code, *, show_code=True, fail=None):
        self.on_device_code, self.show_code, self.fail = on_device_code, show_code, fail
        self.release, self.cancelled = threading.Event(), False

    def get_token(self):
        if self.fail:
            raise self.fail
        if self.show_code:
            self.on_device_code(CODE)
        self.release.wait(5)
        if self.cancelled:
            raise AuthenticationError("Sign-in was cancelled.")
        return "token"

    def cancel_sign_in(self):
        self.cancelled = True
        self.release.set()


class FakeService:
    def __init__(self, **provider_kw):
        self.provider_kw, self.providers, self.modes, self.sessions = provider_kw, [], [], []

    def create_provider(self, tenant, mode, on_device_code):
        self.modes.append(mode)
        provider = WaitingProvider(on_device_code, **self.provider_kw)
        self.providers.append(provider)
        return provider

    def open_session(self, tenant, provider):
        provider.get_token()
        session = FakeSession()
        self.sessions.append(session)
        return session


def make(qtbot, runner, service, tenants=(TENANT,), **kw):
    dialog = SignInDialog(list(tenants), runner, service=service, **kw)
    qtbot.addWidget(dialog)
    dialog.show()
    return dialog


def test_the_device_code_is_shown_and_signing_in_accepts_the_dialog(qtbot, runner):
    service = FakeService()
    dialog = make(qtbot, runner, service)
    dialog.sign_in_button.click()
    qtbot.waitUntil(lambda: dialog.code_panel.isVisible())
    assert dialog.code_label.text() == "ABC123" and not dialog.sign_in_button.isEnabled()
    assert service.modes == [AuthMode.DEVICE_CODE]
    service.providers[0].release.set()
    qtbot.waitUntil(lambda: dialog.result() == QDialog.DialogCode.Accepted)
    assert dialog.session is service.sessions[0]


def test_copy_code_puts_the_code_on_the_clipboard(qtbot, runner):
    from PySide6.QtGui import QGuiApplication

    service = FakeService()
    dialog = make(qtbot, runner, service)
    dialog.sign_in_button.click()
    qtbot.waitUntil(lambda: dialog.code_panel.isVisible())
    dialog.copy_button.click()
    assert QGuiApplication.clipboard().text() == "ABC123"
    service.providers[0].release.set()


def test_cancelling_while_waiting_stops_the_sign_in(qtbot, runner):
    service = FakeService()
    dialog = make(qtbot, runner, service)
    dialog.sign_in_button.click()
    qtbot.waitUntil(lambda: dialog.code_panel.isVisible())
    dialog.cancel_button.click()
    assert dialog.result() == QDialog.DialogCode.Rejected and service.providers[0].cancelled
    runner.wait()
    qtbot.wait(20)
    assert dialog.session is None


def test_a_session_that_finishes_after_cancel_is_closed_not_used(qtbot, runner):
    service = FakeService()
    dialog = make(qtbot, runner, service)
    dialog.sign_in_button.click()
    qtbot.waitUntil(lambda: dialog.code_panel.isVisible())
    provider = service.providers[0]
    provider.cancel_sign_in = lambda: None          # a provider that ignores the cancel...
    dialog.reject()
    provider.release.set()                          # ...and signs in anyway
    qtbot.waitUntil(lambda: bool(service.sessions))
    qtbot.waitUntil(lambda: service.sessions[0].closed)
    assert dialog.session is None


def test_a_failed_sign_in_is_shown_and_can_be_retried(qtbot, runner):
    service = FakeService(fail=AuthenticationError("AADSTS7000218: public client flows are disabled"))
    dialog = make(qtbot, runner, service)
    dialog.sign_in_button.click()
    qtbot.waitUntil(lambda: dialog.sign_in_button.isEnabled())
    assert "AADSTS7000218" in dialog.status.text() and dialog.result() != QDialog.DialogCode.Accepted
    service.provider_kw = {"show_code": False}
    dialog.sign_in_button.click()
    service.providers[-1].release.set()
    qtbot.waitUntil(lambda: dialog.session is not None)


def test_browser_sign_in_is_offered_and_says_it_gives_up(qtbot, runner):
    service = FakeService(show_code=False)
    dialog = make(qtbot, runner, service)
    dialog.browser_radio.setChecked(True)
    dialog.sign_in_button.click()
    assert service.modes == [AuthMode.BROWSER] and "browser" in dialog.status.text()
    assert not dialog.code_panel.isVisible()
    service.providers[0].release.set()
    qtbot.waitUntil(lambda: dialog.session is not None)


def test_the_chosen_tenant_is_used(qtbot, runner):
    other = TenantConfig("Fabrikam", "fabrikam.onmicrosoft.com", "client-2")
    seen = []

    class Recording(FakeService):
        def create_provider(self, tenant, mode, on_device_code):
            seen.append(tenant)
            return super().create_provider(tenant, mode, on_device_code)

    service = Recording(show_code=False)
    dialog = make(qtbot, runner, service, tenants=(TENANT, other))
    dialog.tenant_box.setCurrentIndex(1)
    dialog.sign_in_button.click()
    service.providers[0].release.set()
    qtbot.waitUntil(lambda: dialog.session is not None)
    assert seen == [other]


def test_without_tenants_it_explains_how_to_add_one(qtbot, runner):
    dialog = make(qtbot, runner, FakeService(), tenants=())
    assert not dialog.sign_in_button.isEnabled() and "tenants.json" in dialog.status.text()


def test_a_broken_tenants_file_is_shown_instead_of_crashing(qtbot, runner):
    dialog = make(qtbot, runner, FakeService(), config_error="tenants.json, tenant 1: 'client_id' is missing or empty.")
    assert not dialog.sign_in_button.isEnabled() and "client_id" in dialog.status.text()
