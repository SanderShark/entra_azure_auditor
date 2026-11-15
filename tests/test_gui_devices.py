"""The Devices page against the FakeTenant: recovery secrets are shown once, on request, after a confirmation."""

import base64

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QMessageBox  # noqa: E402

from entra_auditor.gui.devices_page import SecretDialog  # noqa: E402
from entra_auditor.gui.main_window import MainWindow  # noqa: E402
from entra_auditor.toolkit import audit_log  # noqa: E402
from tests.fakes import FakeTenant  # noqa: E402
from tests.gui_support import FakeSession  # noqa: E402

KEY = "123456-231453-873456-213546-654678-765689-123456-324565"


def device_tenant():
    t = FakeTenant()
    t.bitlocker = {"k-new": {"deviceId": "hw-1111", "volumeType": "1", "createdDateTime": "2026-03-01T00:00:00Z", "key": KEY}}
    t.laps = {"hw-1111": [{"accountName": "LocalAdmin", "backupDateTime": "2026-06-01T00:00:00Z",
                           "passwordBase64": base64.b64encode("N3w*Pw(2)".encode("utf-16-le")).decode()}]}
    return t


@pytest.fixture
def page(qtbot, runner, monkeypatch):
    def make(tenant=None, answer=QMessageBox.StandardButton.Yes):
        asked = []
        monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: (asked.append(a[2]), answer)[1])
        win = MainWindow(FakeSession(tenant or device_tenant()), runner, change_sleep=lambda s: None)
        qtbot.addWidget(win)
        win.show()
        win.show_section("Devices")
        devices = win.devices_page
        qtbot.waitUntil(lambda: devices.loaded)
        devices.asked = asked
        return devices
    return make


def pick(qtbot, devices, name="SEA-LT-001"):
    device = next(d for d in devices.devices if d.label == name)
    assert devices.select_device(device.id)
    return device


def test_devices_load_when_the_page_is_opened_and_filter_as_you_type(qtbot, page):
    devices = page()
    assert devices.device_names() == ["OLD-PC", "Pixel 8", "SEA-LT-001"] and devices.status.text() == "3 devices"
    devices.filter_edit.setText("windows disabled")
    assert devices.device_names() == ["OLD-PC"] and devices.status.text() == "1 of 3 devices"
    devices.filter_edit.setText("hw-2222")                      # the hardware id counts too
    assert devices.device_names() == ["Pixel 8"]
    assert not devices.keys_button.isEnabled()                  # nothing selected yet


def test_selecting_a_device_shows_its_properties_and_reads_no_secret(qtbot, page):
    devices = page()
    calls = len(devices.window.session.graph.calls)
    pick(qtbot, devices)
    assert devices.props["Join type"].text() == "Entra joined" and devices.props["Device id"].text() == "hw-1111"
    assert devices.keys_button.isEnabled() and not devices.reveal_button.isEnabled()
    assert len(devices.window.session.graph.calls) == calls and devices.key_list.count() == 0


def test_a_bitlocker_key_is_found_then_revealed_once_after_a_confirmation(qtbot, page):
    devices = page()
    pick(qtbot, devices)
    devices.keys_button.click()
    qtbot.waitUntil(lambda: devices.key_list.count() == 1)
    assert devices.key_list.item(0).text().startswith("operating system drive, backed up 2026-03-01")
    assert KEY not in devices.key_list.item(0).text() and devices.asked == []
    devices.reveal_button.click()
    qtbot.waitUntil(lambda: isinstance(devices.dialog, SecretDialog))
    assert "Entra records that you read it" in devices.asked[0]
    assert devices.dialog.secret_labels[0].text() == KEY
    devices.dialog.accept()
    qtbot.waitUntil(lambda: devices.dialog is None)
    log = audit_log.default_log_path().read_text()
    assert "device.reveal_bitlocker_key" in log and KEY not in log
    assert KEY not in devices.recovery_status.text() and KEY not in devices.key_list.item(0).text()


def test_the_laps_password_is_shown_once(qtbot, page):
    devices = page()
    pick(qtbot, devices)
    devices.laps_button.click()
    qtbot.waitUntil(lambda: isinstance(devices.dialog, SecretDialog))
    assert devices.dialog.secret_labels[0].text() == "N3w*Pw(2)"
    devices.dialog.accept()
    assert "N3w" not in audit_log.default_log_path().read_text()


def test_declining_the_confirmation_reads_nothing(qtbot, page):
    devices = page(answer=QMessageBox.StandardButton.No)
    pick(qtbot, devices)
    calls = len(devices.window.session.graph.calls)
    devices.laps_button.click()
    assert devices.dialog is None and len(devices.window.session.graph.calls) == calls and not devices.busy


def test_refusals_and_missing_secrets_are_explained_on_the_page(qtbot, page):
    tenant = device_tenant()
    devices = page(tenant)
    pick(qtbot, devices, "Pixel 8")
    devices.keys_button.click()
    qtbot.waitUntil(lambda: "No BitLocker recovery key is backed up" in devices.recovery_status.text())
    devices.laps_button.click()
    qtbot.waitUntil(lambda: "No local administrator password is backed up" in devices.recovery_status.text())
    tenant.secrets_denied = True
    pick(qtbot, devices)
    devices.keys_button.click()
    qtbot.waitUntil(lambda: "BitlockerKey.Read.All" in devices.recovery_status.text())
    assert devices.dialog is None and devices.keys_button.isEnabled()


def test_an_answer_for_a_device_no_longer_selected_is_dropped(qtbot, page):
    devices = page()
    pick(qtbot, devices)
    devices.keys_button.click()
    pick(qtbot, devices, "Pixel 8")                             # moved on before the keys arrived
    qtbot.waitUntil(lambda: not devices.window.runner.busy)
    assert devices.key_list.count() == 0 and devices.props["Name"].text() == "Pixel 8"
