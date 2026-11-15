"""Devices page: every device object on the left (loaded once, filtered as you type), the selected device's
properties and its recovery secrets on the right.

Recovery secrets (BitLocker recovery keys, the Windows LAPS local-administrator password) are read only
when asked for, after a confirmation, shown once in a dialog and never logged or kept: closing the dialog
forgets them. Entra's audit log and the local action log both record that they were read.

NOT VERIFIED AGAINST A LIVE TENANT. See CLAUDE.md.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGridLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..toolkit.devices import (
    DeviceSecretError,
    RecoveryKey,
    list_bitlocker_keys,
    reveal_bitlocker_key,
    reveal_laps,
)
from ..toolkit.directory import load_devices
from ..toolkit.models import DeviceSummary

COLUMNS = ("Name", "Operating system", "Join type", "Account", "Last sign-in")


def _label() -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class SecretDialog(QDialog):
    """Shows secrets once. ``rows`` are (what it is, the secret). Nothing here is logged or stored."""

    def __init__(self, title: str, rows: list[tuple[str, str]], note: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        self.secret_labels: list[QLabel] = []
        self.copy_buttons: list[QPushButton] = []
        for row, (what, secret) in enumerate(rows):
            grid.addWidget(QLabel(what), row, 0)
            value = _label()
            value.setWordWrap(False)
            value.setText(secret)
            font = QFont(value.font())
            font.setStyleHint(QFont.StyleHint.Monospace)
            font.setFamily("monospace")
            font.setBold(row == 0)
            value.setFont(font)
            grid.addWidget(value, row, 1)
            copy = QPushButton("Copy")
            copy.clicked.connect(lambda _checked=False, text=secret: QGuiApplication.clipboard().setText(text))
            grid.addWidget(copy, row, 2)
            self.secret_labels.append(value)
            self.copy_buttons.append(copy)
        layout.addLayout(grid)
        hint = QLabel(note)
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #666;")
        layout.addWidget(hint)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.accept)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class DevicesPage(QWidget):
    def __init__(self, window: Any, *, loader: Callable[[Any], list[DeviceSummary]] = load_devices) -> None:
        super().__init__()
        self.window = window
        self._loader = loader
        self.devices: list[DeviceSummary] = []
        self.device: Optional[DeviceSummary] = None
        self.keys: Optional[list[RecoveryKey]] = None
        self.loaded = False
        self.loading = False
        self.busy = False
        self._generation = 0
        self.dialog: Optional[QDialog] = None

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter: name, operating system, join type, device id...")
        self.filter_edit.setClearButtonEnabled(True)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(list(COLUMNS))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column, width in ((1, 190), (2, 110), (3, 80), (4, 100)):
            self.table.setColumnWidth(column, width)
        self.status = QLabel()
        self.status.setWordWrap(True)
        left_layout.addWidget(self.filter_edit)
        left_layout.addWidget(self.table)
        left_layout.addWidget(self.status)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        form = QFormLayout()
        self.props: dict[str, QLabel] = {}
        for name in ("Name", "Operating system", "Join type", "Account", "Last sign-in", "Device id", "Object id"):
            self.props[name] = _label()
            form.addRow(f"{name}:", self.props[name])
        right_layout.addLayout(form)
        right_layout.addWidget(QLabel("<b>Recovery</b>"))
        self.keys_button = QPushButton("Find BitLocker recovery keys")
        self.key_list = QListWidget()
        self.key_list.setWordWrap(True)
        self.key_list.setMaximumHeight(110)
        self.reveal_button = QPushButton("Show selected key...")
        self.laps_button = QPushButton("Show local administrator password (LAPS)...")
        for widget in (self.keys_button, self.key_list, self.reveal_button, self.laps_button):
            right_layout.addWidget(widget)
        self.recovery_status = _label()
        right_layout.addWidget(self.recovery_status)
        note = QLabel("Keys and passwords are shown once and never saved. Entra's audit log and the local action log "
                      "record that you read them.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #666;")
        right_layout.addWidget(note)
        right_layout.addStretch()

        splitter = QSplitter()
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([780, 470])
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)

        self.filter_edit.textChanged.connect(self._filter)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.key_list.itemSelectionChanged.connect(self._update_buttons)
        self.keys_button.clicked.connect(self.find_keys)
        self.reveal_button.clicked.connect(self.reveal_key)
        self.laps_button.clicked.connect(self.reveal_laps_password)
        self._show_device(None)

    # -- the list ------------------------------------------------------------------------------------ #

    def activate_page(self) -> None:
        if not self.loaded:
            self.reload()

    def reload(self) -> None:
        if self.loading:
            return
        self.loading = True
        self.status.setText("Loading devices...")
        graph = self.window.session.graph
        self.window.runner.submit(lambda: self._loader(graph), self._loaded, self._failed, owner=self)

    def _loaded(self, devices: list[DeviceSummary]) -> None:
        self.loading, self.loaded = False, True
        selected = self.device.id if self.device else None
        self.devices = devices
        self.table.blockSignals(True)
        self.table.setRowCount(len(devices))
        for row, device in enumerate(devices):
            for col, value in enumerate(self._cells(device)):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, device)
                self.table.setItem(row, col, item)
        self.table.blockSignals(False)
        self._filter()
        if not (selected and self.select_device(selected)):
            self.table.clearSelection()
            self._show_device(None)

    @staticmethod
    def _cells(device: DeviceSummary) -> tuple[str, ...]:
        account = "?" if device.account_enabled is None else "Enabled" if device.account_enabled else "Disabled"
        seen = f"{device.last_sign_in:%Y-%m-%d}" if device.last_sign_in else "-"
        return (device.label, device.os_label, device.join_type, account, seen)

    def _failed(self, exc: BaseException) -> None:
        self.loading = False
        self.status.setText(f"Couldn't load devices: {exc}")

    def _filter(self, _text: str = "") -> None:
        terms = self.filter_edit.text().casefold().split()
        shown = 0
        for row in range(self.table.rowCount()):
            device: DeviceSummary = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            hay = " ".join((*self._cells(device), device.device_id or "", device.id)).casefold()
            hidden = not all(t in hay for t in terms)
            self.table.setRowHidden(row, hidden)
            shown += not hidden
        if self.loaded:
            total = len(self.devices)
            self.status.setText(f"{total:,} devices" if shown == total else f"{shown:,} of {total:,} devices")

    def device_names(self) -> list[str]:
        return [self.table.item(r, 0).text() for r in range(self.table.rowCount()) if not self.table.isRowHidden(r)]

    def select_device(self, device_id: str) -> bool:
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).data(Qt.ItemDataRole.UserRole).id == device_id:
                self.table.selectRow(row)
                return True
        return False

    def _selection_changed(self) -> None:
        items = self.table.selectedItems()
        self._show_device(items[0].data(Qt.ItemDataRole.UserRole) if items else None)

    # -- one device ------------------------------------------------------------------------------------ #

    def _show_device(self, device: Optional[DeviceSummary]) -> None:
        self._generation += 1           # an answer for the previous device is dropped
        self.device, self.keys, self.busy = device, None, False
        self.key_list.clear()
        self.recovery_status.setText("")
        for label in self.props.values():
            label.setText("")
        if device is not None:
            cells = self._cells(device)
            for name, value in zip(COLUMNS, cells):
                self.props[name].setText(value)
            self.props["Device id"].setText(device.device_id or "-")
            self.props["Object id"].setText(device.id)
        self._update_buttons()

    def _update_buttons(self) -> None:
        ready = self.device is not None and not self.busy
        self.keys_button.setEnabled(ready)
        self.laps_button.setEnabled(ready)
        self.reveal_button.setEnabled(ready and bool(self.key_list.selectedItems()))

    def _run(self, message: str, work: Callable[[], Any], done: Callable[[Any], None]) -> None:
        self.busy = True
        self.recovery_status.setText(message)
        self._update_buttons()
        generation = self._generation

        def finished(result: Any) -> None:
            if generation != self._generation:
                return
            self.busy = False
            self.recovery_status.setText("")
            done(result)
            self._update_buttons()

        def failed(exc: BaseException) -> None:
            if generation != self._generation:
                return
            self.busy = False
            hint = getattr(exc, "hint", "")
            self.recovery_status.setText(f"{exc}" + (f"\n{hint}" if hint else ""))
            self._update_buttons()

        self.window.runner.submit(work, finished, failed, owner=self)

    def find_keys(self) -> None:
        if self.device is None or self.busy:
            return
        device, graph = self.device, self.window.session.graph

        def done(keys: list[RecoveryKey]) -> None:
            self.keys = keys
            self.key_list.clear()
            for key in keys:
                item = QListWidgetItem(key.label)
                item.setData(Qt.ItemDataRole.UserRole, key)
                self.key_list.addItem(item)
            if keys:
                self.key_list.setCurrentRow(0)
            else:
                self.recovery_status.setText("No BitLocker recovery key is backed up to Entra for this device.")

        self._run("Looking for BitLocker keys...", lambda: list_bitlocker_keys(graph, device), done)

    def _confirm(self, what: str) -> bool:
        answer = QMessageBox.question(
            self, "Read a recovery secret",
            f"Show {what} for {self.device.label if self.device else '?'}?\n\nEntra records that you read it.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        return answer == QMessageBox.StandardButton.Yes

    def _show_secret(self, title: str, rows: list[tuple[str, str]], note: str) -> None:
        dialog = SecretDialog(title, rows, note, self)
        self.dialog = dialog
        dialog.finished.connect(lambda _code: setattr(self, "dialog", None))
        dialog.open()

    def reveal_key(self) -> None:
        items = self.key_list.selectedItems()
        if self.device is None or self.busy or not items or not self._confirm("the BitLocker recovery key"):
            return
        device, key, graph, actor = self.device, items[0].data(Qt.ItemDataRole.UserRole), self.window.session.graph, self.window.session.identity
        self._run("Reading the key...", lambda: reveal_bitlocker_key(graph, device, key, actor=actor),
                  lambda value: self._show_secret(f"BitLocker recovery key: {device.label}",
                                                  [(key.volume.capitalize(), value)],
                                                  f"Key id {key.id}. Not saved anywhere: closing this window forgets it."))

    def reveal_laps_password(self) -> None:
        if self.device is None or self.busy or not self._confirm("the local administrator password"):
            return
        device, graph, actor = self.device, self.window.session.graph, self.window.session.identity

        def done(found: list[Any]) -> None:
            rows = [(f"{c.account}" + (f" ({c.backed_up:%Y-%m-%d})" if c.backed_up else ""), c.password) for c in found]
            self._show_secret(f"Local administrator password: {device.label}", rows,
                              "Newest first. Windows LAPS rotates the password after use, according to its policy. "
                              "Not saved anywhere: closing this window forgets it.")

        self._run("Reading the password...", lambda: reveal_laps(graph, device, actor=actor), done)


__all__ = ["DevicesPage", "SecretDialog", "DeviceSecretError"]
