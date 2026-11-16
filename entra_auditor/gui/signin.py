"""Sign-in dialog: pick a tenant and a method, then sign in without freezing the window.

Device code shows the code with "Copy code" and "Open sign-in page" buttons, and can be cancelled while
it waits. Browser sign-in opens the system browser; it can't be interrupted from here, so it gives up
after a few minutes. A cached sign-in for the tenant is used silently.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from PySide6.QtCore import Qt, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QButtonGroup,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from ..auth import AuthMode, DeviceCode
from ..tenants import TenantConfig, tenants_file
from .session import BROWSER_TIMEOUT, GuiSession, SignInService
from .tasks import TaskRunner

EXAMPLE = '{"tenants": [{"name": "Contoso", "tenant_id": "<tenant id>", "client_id": "<app id>"}]}'


class SignInDialog(QDialog):
    device_code_received = Signal(object)   # emitted from the worker; received on the UI thread

    def __init__(self, tenants: Sequence[TenantConfig], runner: TaskRunner, *,
                 service: Optional[SignInService] = None, config_error: Optional[str] = None,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Sign in")
        self.setMinimumWidth(460)
        self.tenants = list(tenants)
        self.runner = runner
        self.service = service or SignInService()
        self.session: Optional[GuiSession] = None
        self._provider: Any = None
        self._attempt = 0
        self.device_code: Optional[DeviceCode] = None

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.tenant_box = QComboBox()
        for tenant in self.tenants:
            self.tenant_box.addItem(tenant.name, tenant)
        self.tenant_box.currentIndexChanged.connect(self._tenant_changed)
        form.addRow("Tenant", self.tenant_box)

        method = QWidget()
        row = QHBoxLayout(method)
        row.setContentsMargins(0, 0, 0, 0)
        self.device_radio = QRadioButton("Device code")
        self.browser_radio = QRadioButton("Browser")
        self.device_radio.setChecked(True)
        self.device_radio.setToolTip("Enter a short code at microsoft.com/devicelogin. Works everywhere.")
        self.browser_radio.setToolTip("Sign in in your browser. The app registration needs the "
                                      "http://localhost redirect URI (Mobile and desktop platform).")
        group = QButtonGroup(self)
        group.addButton(self.device_radio)
        group.addButton(self.browser_radio)
        row.addWidget(self.device_radio)
        row.addWidget(self.browser_radio)
        row.addStretch()
        form.addRow("Method", method)
        self.read_only_box = QCheckBox("Read-only: look, don't change anything")
        self.read_only_box.setToolTip("Every change and every role activation is refused for this session. "
                                      "Recommended for a first look at a production tenant.")
        form.addRow("", self.read_only_box)
        layout.addLayout(form)

        # device-code panel (hidden until a code arrives)
        self.code_panel = QWidget()
        code_layout = QVBoxLayout(self.code_panel)
        code_layout.setContentsMargins(0, 8, 0, 0)
        code_layout.addWidget(QLabel("Open the sign-in page and enter this code:"))
        self.code_label = QLabel()
        font = QFont(self.code_label.font())
        font.setPointSize(font.pointSize() + 8)
        font.setBold(True)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.code_label.setFont(font)
        self.code_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        code_layout.addWidget(self.code_label)
        buttons_row = QHBoxLayout()
        self.copy_button = QPushButton("Copy code")
        self.open_button = QPushButton("Open sign-in page")
        self.copy_button.clicked.connect(self._copy_code)
        self.open_button.clicked.connect(self._open_page)
        buttons_row.addWidget(self.copy_button)
        buttons_row.addWidget(self.open_button)
        buttons_row.addStretch()
        code_layout.addLayout(buttons_row)
        self.code_panel.hide()
        layout.addWidget(self.code_panel)

        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.status)
        self._tenant_changed()

        self.buttons = QDialogButtonBox()
        self.sign_in_button = self.buttons.addButton("Sign in", QDialogButtonBox.ButtonRole.AcceptRole)
        self.cancel_button = self.buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.sign_in_button.setDefault(True)
        self.sign_in_button.clicked.connect(self.start_sign_in)
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.buttons)

        self.device_code_received.connect(self._show_device_code)

        if config_error:
            self._no_tenants(config_error)
        elif not self.tenants:
            self._no_tenants(f"No tenants are set up. Create {tenants_file()} like this:\n{EXAMPLE}\n"
                             "or set AZURE_TENANT_ID and AZURE_CLIENT_ID in .env.")

    # -- state --------------------------------------------------------------- #

    def _no_tenants(self, message: str) -> None:
        self.status.setText(message)
        self.status.setStyleSheet("color: #c62828;")
        self.sign_in_button.setEnabled(False)
        self.tenant_box.setEnabled(False)

    @property
    def signing_in(self) -> bool:
        return self._provider is not None

    def _set_busy(self, busy: bool) -> None:
        self.sign_in_button.setEnabled(not busy)
        self.tenant_box.setEnabled(not busy)
        self.device_radio.setEnabled(not busy)
        self.browser_radio.setEnabled(not busy)
        self.read_only_box.setEnabled(not busy)

    # -- sign-in --------------------------------------------------------------- #

    @Slot()
    def start_sign_in(self) -> None:
        tenant: TenantConfig = self.tenant_box.currentData()
        if tenant is None or self.signing_in:
            return
        mode = AuthMode.DEVICE_CODE if self.device_radio.isChecked() else AuthMode.BROWSER
        self._attempt += 1
        attempt = self._attempt
        self.code_panel.hide()
        self.device_code = None
        self.status.setStyleSheet("")
        try:
            provider = self.service.create_provider(tenant, mode, self.device_code_received.emit)
        except Exception as exc:  # noqa: BLE001 - a bad configuration is shown, not raised
            self._failed(attempt, exc)
            return
        self._provider = provider
        self._set_busy(True)
        self.status.setText(f"Signing in to {tenant.name}..." if mode is AuthMode.DEVICE_CODE else
                            f"Finish signing in to {tenant.name} in your browser. This gives up after "
                            f"{int(BROWSER_TIMEOUT // 60)} minutes.")
        self.runner.submit(lambda: self.service.open_session(tenant, provider),
                           lambda session: self._signed_in(attempt, session),
                           lambda exc: self._failed(attempt, exc), owner=self)

    @Slot(object)
    def _show_device_code(self, code: DeviceCode) -> None:
        if not self.signing_in:
            return
        self.device_code = code
        self.code_label.setText(code.user_code)
        self.code_panel.show()
        self.status.setText("Waiting for you to finish signing in...")

    def _copy_code(self) -> None:
        if self.device_code:
            QGuiApplication.clipboard().setText(self.device_code.user_code)

    def _open_page(self) -> None:
        if self.device_code:
            QDesktopServices.openUrl(QUrl(self.device_code.verification_uri))

    def _tenant_changed(self, _index: int = 0) -> None:
        tenant = self.tenant_box.currentData()
        self.read_only_box.setChecked(bool(getattr(tenant, "read_only", False)))

    def _signed_in(self, attempt: int, session: GuiSession) -> None:
        if attempt != self._attempt:
            session.close()     # the dialog was cancelled while this was finishing
            return
        self._provider = None
        session.read_only = self.read_only_box.isChecked()
        self.session = session
        self.accept()

    def _failed(self, attempt: int, exc: BaseException) -> None:
        if attempt != self._attempt:
            return
        self._provider = None
        self._set_busy(False)
        self.code_panel.hide()
        self.status.setStyleSheet("color: #c62828;")
        self.status.setText(f"Sign-in failed: {exc}")

    def reject(self) -> None:
        provider, self._provider = self._provider, None
        self._attempt += 1      # any result still on its way is ignored
        if provider is not None:
            cancel = getattr(provider, "cancel_sign_in", None)
            if cancel is not None:
                cancel()
        super().reject()
