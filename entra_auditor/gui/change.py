"""Every tenant change as dialogs: preview -> confirm -> (PIM elevation -> justification -> retry) -> result.

``ChangeController`` drives ``toolkit.flow.ChangeFlow`` (the same flow the terminal uses). Each flow
step that touches Graph runs on a worker; the answer dialogs run on the UI thread. While a step runs, a
busy dialog shows what the flow is doing.

NOT VERIFIED AGAINST A LIVE TENANT: the PIM elevation dialogs (role choice, justification, wait, retry)
are tested against the fake tenant only. See CLAUDE.md.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Mapping, Optional

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QProgressDialog,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..toolkit.actions import ActionPlan, ActionResult
from ..toolkit.flow import ChangeFlow, Done, NeedsConfirmation, NeedsElevation, NeedsJustification, Notice, Step
from .tasks import TaskRunner

WARNING_STYLE = "color: #b26a00;"
ERROR_STYLE = "color: #c62828;"
OK_STYLE = "color: #2e7d32;"
LEVEL_STYLE = {"warning": WARNING_STYLE, "error": ERROR_STYLE, "success": OK_STYLE, "info": ""}
STATUS_STYLE = {"ok": OK_STYLE, "dry_run": WARNING_STYLE, "skipped": WARNING_STYLE, "partial": WARNING_STYLE}


def _label(text: str, style: str = "", *, wrap: bool = True) -> QLabel:
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)    # names may contain markup-like text
    label.setWordWrap(wrap)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    if style:
        label.setStyleSheet(style)
    return label


# --------------------------------------------------------------------------- #
# Dialogs (each answers one flow step)
# --------------------------------------------------------------------------- #

class PlanDialog(QDialog):
    """NeedsConfirmation: show exactly what will be sent, and ask."""

    def __init__(self, plan: ActionPlan, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm change")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        heading = _label("About to change your tenant")
        font = QFont(heading.font())
        font.setBold(True)
        heading.setFont(font)
        layout.addWidget(heading)
        form = QFormLayout()
        form.addRow("Change", _label(plan.title))
        form.addRow("Target", _label(f"{plan.target_type}: {plan.target_name}"))
        if plan.details:
            form.addRow("Details", _label("\n".join(plan.details)))
        if plan.suggested_roles:
            form.addRow("Needs one of", _label(", ".join(plan.suggested_roles)))
        layout.addLayout(form)

        self.requests = QTableWidget(len(plan.requests), 3)
        self.requests.setHorizontalHeaderLabels(["Method", "Path", "Body"])
        self.requests.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.requests.verticalHeader().hide()
        self.requests.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.requests.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for row, request in enumerate(plan.requests):
            body = request.redacted_json()          # secrets never reach the screen in a preview
            for col, value in enumerate((request.method, request.path, "-" if body is None else str(body))):
                self.requests.setItem(row, col, QTableWidgetItem(value))
        # The preview must show everything that will be sent: wrap long bodies, never elide them.
        self.requests.setWordWrap(True)
        self.requests.setTextElideMode(Qt.TextElideMode.ElideNone)
        self.requests.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._fit_requests()
        layout.addWidget(_label("Graph requests"))
        layout.addWidget(self.requests)

        self.warnings = [_label(f"! {w}", WARNING_STYLE) for w in plan.warnings]
        for warning in self.warnings:
            layout.addWidget(warning)

        buttons = QDialogButtonBox()
        self.apply_button = buttons.addButton("Apply change", QDialogButtonBox.ButtonRole.AcceptRole)
        self.cancel_button = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        # Like the terminal, the safe answer is the default: Enter must never apply a change. Qt makes the
        # first accept button the default when a dialog is shown, so turn that off and re-assert on show.
        self.apply_button.setAutoDefault(False)
        self.apply_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(buttons)
        self.cancel_button.setDefault(True)

    def _fit_requests(self) -> None:
        """Row heights depend on the column widths, which are only final once the dialog is laid out."""
        self.requests.resizeRowsToContents()
        height = self.requests.horizontalHeader().height() + 2 * self.requests.frameWidth()
        height += sum(self.requests.rowHeight(r) for r in range(self.requests.rowCount()))
        self.requests.setFixedHeight(min(height, 400))

    def showEvent(self, event: Any) -> None:  # noqa: N802 - Qt's name
        super().showEvent(event)
        self._fit_requests()
        layout = self.layout()
        layout.activate()
        self.resize(self.width(), max(self.height(), layout.totalHeightForWidth(self.width())
                                      if layout.hasHeightForWidth() else layout.sizeHint().height()))
        self.apply_button.setDefault(False)
        self.cancel_button.setDefault(True)
        self.cancel_button.setFocus()


class ElevationDialog(QDialog):
    """NeedsElevation: Entra said "forbidden"; offer the eligible roles that can do it."""

    def __init__(self, step: NeedsElevation, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("More permissions needed")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.addWidget(_label("Entra says your current permissions aren't enough for this change. "
                                f"You can activate one of these with PIM for {step.minutes} minutes and try "
                                "again (a group membership gives you the roles the group holds):"))
        self.roles = QListWidget()
        for role in step.candidate_roles:
            item = QListWidgetItem(role.label)
            item.setData(Qt.ItemDataRole.UserRole, role)
            self.roles.addItem(item)
        self.roles.setCurrentRow(0)
        self.roles.setMaximumHeight(30 + 22 * len(step.candidate_roles))
        layout.addWidget(self.roles)
        buttons = QDialogButtonBox()
        self.activate_button = buttons.addButton("Activate and retry", QDialogButtonBox.ButtonRole.AcceptRole)
        self.skip_button = buttons.addButton("Don't activate", QDialogButtonBox.ButtonRole.RejectRole)
        self.activate_button.setDefault(True)
        self.activate_button.clicked.connect(self.accept)
        self.skip_button.clicked.connect(self.reject)
        self.roles.itemDoubleClicked.connect(lambda _item: self.accept())
        layout.addWidget(buttons)

    @property
    def chosen_role(self) -> Any:
        item = self.roles.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None


class JustificationDialog(QDialog):
    """NeedsJustification: PIM requires a reason; the OK button stays disabled until there is one."""

    def __init__(self, step: NeedsJustification, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Justification")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.addWidget(_label(f"Why are you activating {step.role.label}? (ticket or task)"))
        self.text = QPlainTextEdit()
        self.text.setPlaceholderText("e.g. INC-1234: re-enable account after leave")
        self.text.setMaximumHeight(90)
        layout.addWidget(self.text)
        buttons = QDialogButtonBox()
        self.ok_button = buttons.addButton(f"Activate for {step.minutes} minutes", QDialogButtonBox.ButtonRole.AcceptRole)
        self.cancel_button = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.ok_button.setEnabled(False)
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        self.text.textChanged.connect(lambda: self.ok_button.setEnabled(bool(self.reason)))
        layout.addWidget(buttons)

    @property
    def reason(self) -> str:
        return self.text.toPlainText().strip()


class ResultDialog(QDialog):
    """Done: what happened. A password in the result is shown here once and never logged."""

    def __init__(self, done: Done, notices: list[Notice], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        result = done.result
        self.setWindowTitle("Change applied" if result.status == "ok" else "Change not applied")
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        self.status_label = _label(f"{result.status.upper()}: {result.message}", STATUS_STYLE.get(result.status, ERROR_STYLE))
        layout.addWidget(self.status_label)
        for line in result.lines:
            layout.addWidget(_label(f"  - {line}"))
        if done.activate_manually:
            layout.addWidget(_label("You can activate a role yourself in PIM and try again; this change needs one "
                                    "of: " + ", ".join(done.activate_manually) + "."))
        if notices:
            layout.addWidget(_label("What happened:"))
            for notice in notices:
                layout.addWidget(_label(notice.text, LEVEL_STYLE.get(notice.level, "")))

        self.password_label: Optional[QLabel] = None
        password = result.secrets.get("password")
        if password:
            layout.addWidget(_label("New password (shown once, never logged):", OK_STYLE))
            self.password_label = _label(password, wrap=False)
            font = QFont(self.password_label.font())
            font.setStyleHint(QFont.StyleHint.Monospace)
            font.setBold(True)
            self.password_label.setFont(font)
            layout.addWidget(self.password_label)
            copy = QPushButton("Copy password")
            copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(password))
            layout.addWidget(copy)
            layout.addWidget(_label("The user must change it at next sign-in. Share it over a secure channel."))

        layout.addStretch()       # extra height goes below the text, not between the lines
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.accept)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def showEvent(self, event: Any) -> None:  # noqa: N802 - Qt's name
        super().showEvent(event)
        self.resize(self.width(), self.heightForWidth(self.width()) if self.hasHeightForWidth()
                    else self.sizeHint().height())


# --------------------------------------------------------------------------- #
# Reporter: flow notices from the worker thread to the UI thread
# --------------------------------------------------------------------------- #

class QtReporter(QObject):
    noticed = Signal(object)        # Notice
    busy_changed = Signal(str)      # "" when the flow stops waiting

    def notice(self, notice: Notice) -> None:       # worker thread
        self.noticed.emit(notice)

    @contextmanager
    def busy(self, text: str) -> Iterator[None]:    # worker thread
        self.busy_changed.emit(text)
        try:
            yield
        finally:
            self.busy_changed.emit("")


# --------------------------------------------------------------------------- #
# The controller
# --------------------------------------------------------------------------- #

class ChangeController(QObject):
    """Runs one change from preview to result. ``finished`` carries the final ``Done``.

    ``dialog`` is the dialog currently waiting for the operator (None while a step is running)."""

    finished = Signal(object)

    def __init__(self, session: Any, plan: ActionPlan, runner: TaskRunner, parent_widget: Optional[QWidget] = None, *,
                 minutes: int = 60, extra_secrets: Optional[Mapping[str, str]] = None,
                 sleep: Callable[[float], None] = time.sleep, show_result: bool = True) -> None:
        super().__init__(parent_widget)
        self.runner = runner
        self.parent_widget = parent_widget
        self.reporter = QtReporter()
        self.reporter.noticed.connect(self._on_notice)
        self.reporter.busy_changed.connect(self._on_busy)
        self.flow = ChangeFlow(session, plan, minutes=minutes, extra_secrets=extra_secrets,
                               reporter=self.reporter, sleep=sleep)
        self.notices: list[Notice] = []
        self.dialog: Optional[QDialog] = None
        self.busy_dialog: Optional[QProgressDialog] = None
        self.done: Optional[Done] = None
        self.show_result = show_result

    def start(self) -> None:
        self._run(self.flow.start, "Preparing the change...")

    @property
    def running(self) -> bool:
        return self.busy_dialog is not None

    # -- running steps ------------------------------------------------------- #

    def _run(self, fn: Callable[[], Step], text: str) -> None:
        self._show_busy(text)
        self.runner.submit(fn, self._on_step, self._on_error, owner=self)

    def _show_busy(self, text: str) -> None:
        if self.busy_dialog is None:
            dialog = QProgressDialog(text, "", 0, 0, self.parent_widget)
            dialog.setWindowTitle("Working")
            dialog.setCancelButton(None)            # a write that has started can't be called back
            dialog.setWindowModality(Qt.WindowModality.WindowModal)
            dialog.setMinimumDuration(0)
            dialog.setAutoClose(False)
            dialog.setAutoReset(False)
            self.busy_dialog = dialog
            dialog.show()
        self.busy_dialog.setLabelText(text)

    def _hide_busy(self) -> None:
        if self.busy_dialog is not None:
            self.busy_dialog.close()
            self.busy_dialog.deleteLater()
            self.busy_dialog = None

    @Slot(object)
    def _on_notice(self, notice: Notice) -> None:
        self.notices.append(notice)
        if self.busy_dialog is not None:
            self.busy_dialog.setLabelText(notice.text)

    @Slot(str)
    def _on_busy(self, text: str) -> None:
        if self.busy_dialog is not None and text:
            self.busy_dialog.setLabelText(text)

    def _on_error(self, exc: BaseException) -> None:
        # execute_plan turns Graph errors into results, so this is a bug or a lost connection.
        self._hide_busy()
        self._finish(Done(ActionResult("failed", f"The change could not be completed: {exc}")))

    # -- answering steps ----------------------------------------------------- #

    def _on_step(self, step: Step) -> None:
        self._hide_busy()
        if isinstance(step, NeedsConfirmation):
            self._ask(PlanDialog(step.plan, self.parent_widget),
                      lambda d: self._run(lambda: self.flow.confirm(True), "Applying the change..."),
                      lambda d: self._on_step(self.flow.confirm(False)))
        elif isinstance(step, NeedsElevation):
            self._ask(ElevationDialog(step, self.parent_widget),
                      lambda d: self._on_step(self.flow.choose_role(d.chosen_role)),
                      lambda d: self._on_step(self.flow.choose_role(None)))
        elif isinstance(step, NeedsJustification):
            self._ask(JustificationDialog(step, self.parent_widget),
                      lambda d: self._justify(d.reason, step.role.name),     # read the widget HERE, on the UI thread
                      lambda d: self._on_step(self.flow.justify(None)))
        elif isinstance(step, Done):
            self._finish(step)

    def _justify(self, reason: str, role_name: str) -> None:
        """`reason` is plain text by now: the worker must never read it from the dialog, which is deleted
        as soon as it closes (that crashed, or failed the change, now and then)."""
        self._run(lambda: self.flow.justify(reason), f"Activating {role_name}...")

    def _ask(self, dialog: QDialog, on_accept: Callable[[Any], None], on_reject: Callable[[Any], None]) -> None:
        self.dialog = dialog
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        def answered(code: int) -> None:
            if self.dialog is not dialog:
                return
            self.dialog = None
            (on_accept if code == QDialog.DialogCode.Accepted else on_reject)(dialog)

        dialog.finished.connect(answered)
        dialog.open()       # window-modal, non-blocking: the event loop (and the workers) keep running

    def _finish(self, done: Done) -> None:
        self.done = done
        if self.show_result and not done.cancelled:
            result_dialog = ResultDialog(done, self.notices, self.parent_widget)
            result_dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            self.dialog = result_dialog
            result_dialog.finished.connect(lambda _code: self._closed(result_dialog))
            result_dialog.open()
        self.finished.emit(done)

    def _closed(self, dialog: QDialog) -> None:
        if self.dialog is dialog:
            self.dialog = None
