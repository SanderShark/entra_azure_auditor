"""Roles / PIM page: your directory roles and your PIM group memberships/ownerships, with activate and
deactivate. Activation waits until it takes effect and refreshes the token, like the change flow does.

NOT VERIFIED AGAINST A LIVE TENANT (PIM activation never has been; group PIM is new). See CLAUDE.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..graph.client import GraphError
from ..toolkit.flow import RecordingReporter, activate_and_wait
from ..toolkit.group_pim import GroupPimService
from ..toolkit.pim import PimError, PimService

ERROR_STYLE = "color: #c62828;"
LEVEL_STYLE = {"warning": "color: #b26a00;", "error": ERROR_STYLE, "success": "color: #2e7d32;", "info": ""}


@dataclass
class Row:
    kind: str                 # role | group
    target: Any               # PimRole | GroupAccess
    state: str                # eligible | active (activated) | active (standing)

    @property
    def can_activate(self) -> bool:
        return self.state == "eligible"

    @property
    def can_deactivate(self) -> bool:
        return self.state == "active (activated)"


def _until(value: Any, eligible: bool) -> str:
    if value is None:
        return "-" if eligible else "no end"
    return (f"eligibility ends {value:%Y-%m-%d}" if eligible else f"{value:%Y-%m-%d %H:%M} UTC")


def _rows(eligible: list, active: list, kind: str) -> list[Row]:
    key = (lambda t: t.key) if kind == "group" else (lambda t: (t.role_id, t.scope))
    active_keys = {key(a) for a in active}
    rows = [Row(kind, a, "active (activated)" if a.activated else "active (standing)") for a in active]
    rows += [Row(kind, e, "eligible") for e in eligible if key(e) not in active_keys]
    return rows


def load_pim_state(graph: Any) -> dict[str, Any]:
    """Roles and groups, each read on its own so one missing permission doesn't hide the other."""
    state: dict[str, Any] = {"roles": None, "groups": None, "role_error": None, "group_error": None}
    try:
        roles = PimService(graph)
        state["roles"] = _rows(roles.eligible(), roles.active(), "role")
    except (PimError, GraphError) as exc:
        state["role_error"] = f"Your directory roles couldn't be read: {exc}"
    try:
        groups = GroupPimService(graph)
        state["groups"] = _rows(groups.eligible(), groups.active(with_roles=True), "group")
    except PimError as exc:
        state["group_error"] = f"{exc} {exc.hint}".strip()
    except GraphError as exc:
        state["group_error"] = f"Your PIM groups couldn't be read: {exc}"
    return state


class ActivateDialog(QDialog):
    def __init__(self, name: str, parent: Optional[QWidget] = None, *, minutes: int = 60) -> None:
        super().__init__(parent)
        self.setWindowTitle("Activate")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        name_label = QLabel(name)
        name_label.setTextFormat(Qt.TextFormat.PlainText)
        name_label.setWordWrap(True)
        form = QFormLayout()
        form.addRow("Activate", name_label)
        self.minutes = QSpinBox()
        self.minutes.setRange(15, 24 * 60)
        self.minutes.setSingleStep(15)
        self.minutes.setValue(minutes)
        self.minutes.setSuffix(" minutes")
        form.addRow("For", self.minutes)
        layout.addLayout(form)
        layout.addWidget(QLabel("Justification (ticket or task):"))
        self.text = QPlainTextEdit()
        self.text.setMaximumHeight(90)
        layout.addWidget(self.text)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("Activate")
        self.ok_button.setEnabled(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.text.textChanged.connect(lambda: self.ok_button.setEnabled(bool(self.reason)))
        layout.addWidget(buttons)

    @property
    def reason(self) -> str:
        return self.text.toPlainText().strip()


def _table(headers: tuple[str, ...]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(list(headers))
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.verticalHeader().hide()
    header = table.horizontalHeader()
    for column in range(1, len(headers)):
        header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
    header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
    return table


class RolesPage(QWidget):
    def __init__(self, window: Any) -> None:
        super().__init__()
        self.window = window
        self.loaded = False
        self.loading = False
        self.busy = False
        self.rows: dict[str, list[Row]] = {"role": [], "group": []}
        self.dialog: Optional[QDialog] = None

        layout = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.reload_button = QPushButton("Reload")
        self.activate_button = QPushButton("Activate...")
        self.deactivate_button = QPushButton("Deactivate")
        for button in (self.reload_button, self.activate_button, self.deactivate_button):
            bar.addWidget(button)
        bar.addStretch()
        layout.addLayout(bar)

        layout.addWidget(QLabel("<b>Directory roles</b>"))
        self.roles_table = _table(("Role", "State", "Until"))
        layout.addWidget(self.roles_table)
        self.roles_error = QLabel()
        self.roles_error.setWordWrap(True)
        self.roles_error.setStyleSheet(ERROR_STYLE)
        layout.addWidget(self.roles_error)

        layout.addWidget(QLabel("<b>Groups (PIM for Groups)</b> - a membership gives you the roles its group holds"))
        self.groups_table = _table(("Group", "Access", "State", "Grants roles", "Until"))
        layout.addWidget(self.groups_table)
        self.groups_error = QLabel()
        self.groups_error.setWordWrap(True)
        self.groups_error.setStyleSheet(ERROR_STYLE)
        layout.addWidget(self.groups_error)

        self.message = QLabel()
        self.message.setWordWrap(True)
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.message)

        self.reload_button.clicked.connect(self.reload)
        self.activate_button.clicked.connect(self.activate_selected)
        self.deactivate_button.clicked.connect(self.deactivate_selected)
        self.roles_table.itemSelectionChanged.connect(lambda: self._selected_in(self.roles_table))
        self.groups_table.itemSelectionChanged.connect(lambda: self._selected_in(self.groups_table))
        self._update_buttons()

    # -- loading ---------------------------------------------------------------------------- #

    def activate_page(self) -> None:
        if not self.loaded:
            self.reload()

    def reload(self) -> None:
        if self.loading:
            return
        self.loading = True
        self.reload_button.setEnabled(False)
        graph = self.window.session.graph
        self.window.runner.submit(lambda: load_pim_state(graph), self._loaded, self._load_failed, owner=self)

    def _loaded(self, state: dict[str, Any]) -> None:
        self.loading, self.loaded = False, True
        self.reload_button.setEnabled(True)
        self.rows = {"role": state["roles"] or [], "group": state["groups"] or []}
        self._fill(self.roles_table, self.rows["role"], lambda r: (r.target.label, r.state, _until(
            r.target.ends, r.state == "eligible")), state["roles"] is None, "You have no eligible or active roles.")
        self._fill(self.groups_table, self.rows["group"], lambda r: (
            r.target.group_name, r.target.access, r.state, ", ".join(r.target.roles) or "-",
            _until(r.target.ends, r.state == "eligible")), state["groups"] is None, "You have no PIM group assignments.")
        self.roles_error.setText(state["role_error"] or "")
        self.groups_error.setText(state["group_error"] or "")
        self._update_buttons()

    def _load_failed(self, exc: BaseException) -> None:
        self.loading = False
        self.reload_button.setEnabled(True)
        self.message.setText(f"Couldn't load your PIM roles: {exc}")

    def _fill(self, table: QTableWidget, rows: list[Row], cells: Any, unknown: bool, empty: str) -> None:
        table.clearSelection()
        table.setRowCount(0)
        if unknown:
            return      # the error label says why; an empty table here would wrongly read as "none"
        if not rows:
            table.setRowCount(1)
            item = QTableWidgetItem(empty)
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            table.setItem(0, 0, item)
            return
        table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, value in enumerate(cells(row)):
                table.setItem(r, c, QTableWidgetItem(str(value)))

    # -- selection ------------------------------------------------------------------------------ #

    def _selected_in(self, table: QTableWidget) -> None:
        other = self.groups_table if table is self.roles_table else self.roles_table
        if table.selectedItems():
            other.blockSignals(True)
            other.clearSelection()
            other.blockSignals(False)
        self._update_buttons()

    def selected(self) -> Optional[Row]:
        for kind, table in (("role", self.roles_table), ("group", self.groups_table)):
            items = table.selectedItems()
            if items and items[0].row() < len(self.rows[kind]):
                return self.rows[kind][items[0].row()]
        return None

    def select(self, kind: str, name: str) -> bool:
        table = self.roles_table if kind == "role" else self.groups_table
        for index, row in enumerate(self.rows[kind]):
            if name in row.target.name:
                table.selectRow(index)
                return True
        return False

    def _update_buttons(self) -> None:
        row = self.selected()
        self.activate_button.setEnabled(bool(row and row.can_activate and not self.busy))
        self.deactivate_button.setEnabled(bool(row and row.can_deactivate and not self.busy))

    # -- activate / deactivate -------------------------------------------------------------------- #

    def _service(self, row: Row) -> Any:
        graph = self.window.session.graph
        return GroupPimService(graph) if row.kind == "group" else PimService(graph)

    def activate_selected(self) -> None:
        row = self.selected()
        if row is None or not row.can_activate or self.busy:
            return
        dialog = ActivateDialog(row.target.label, self)
        self.dialog = dialog

        def answered(code: int) -> None:
            self.dialog = None
            if code == QDialog.DialogCode.Accepted:
                self._activate(row, dialog.reason, dialog.minutes.value())

        dialog.finished.connect(answered)
        dialog.open()

    def _activate(self, row: Row, reason: str, minutes: int) -> None:
        self._set_busy(True, f"Activating {row.target.name}...")
        session, service, reporter = self.window.session, self._service(row), RecordingReporter()
        self.window.runner.submit(
            lambda: (activate_and_wait(session, service, row.target, reason, minutes, reporter), reporter),
            self._activated, self._action_failed, owner=self)

    def _activated(self, outcome: tuple[bool, RecordingReporter]) -> None:
        ok, reporter = outcome
        self._set_busy(False, "\n".join(n.text for n in reporter.notices))
        self.message.setStyleSheet(LEVEL_STYLE["success"] if ok else LEVEL_STYLE["error"])
        self.reload()

    def deactivate_selected(self) -> None:
        row = self.selected()
        if row is None or not row.can_deactivate or self.busy:
            return
        answer = QMessageBox.question(self, "Deactivate", f"Deactivate {row.target.name} now?",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                      QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._set_busy(True, f"Deactivating {row.target.name}...")
        session, service, target = self.window.session, self._service(row), row.target

        def work() -> None:            # worker thread: Graph and the token refresh both hit the network
            service.deactivate(target)
            session.refresh()          # drop the role from the token

        self.window.runner.submit(work, lambda _r: self._deactivated(target), self._action_failed, owner=self)

    def _deactivated(self, target: Any) -> None:
        self._set_busy(False, f"{target.name} was deactivated.")
        self.message.setStyleSheet(LEVEL_STYLE["success"])
        self.reload()

    def _action_failed(self, exc: BaseException) -> None:
        hint = getattr(exc, "hint", "")
        self._set_busy(False, f"{exc}" + (f"\n{hint}" if hint else ""))
        self.message.setStyleSheet(ERROR_STYLE)

    def _set_busy(self, busy: bool, text: str) -> None:
        self.busy = busy
        self.message.setStyleSheet("")
        self.message.setText(text)
        self._update_buttons()
