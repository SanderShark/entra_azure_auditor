"""Tenant check page: what this sign-in can do here, and a report that is safe to share.

One click reads the token and tries one harmless read per feature (toolkit/diagnostics.py). Nothing is
written. "Copy report" puts a plain-text summary on the clipboard that names no user, tenant or object.
"""

from __future__ import annotations

from typing import Any, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..toolkit.diagnostics import Report, run_checks, session_token

COLUMNS = ("Feature", "Result", "Details", "Time")
COLOURS = {"OK": "#2e7d32", "DENIED": "#c62828", "NOT FOUND": "#b26a00", "UNSUPPORTED": "#b26a00", "ERROR": "#c62828"}


class CheckPage(QWidget):
    def __init__(self, window: Any) -> None:
        super().__init__()
        self.window = window
        self.report: Optional[Report] = None
        self.running = False

        layout = QVBoxLayout(self)
        intro = QLabel("Check what this sign-in can do in this tenant: the permissions in your token, your active "
                       "roles, and one harmless read per feature. Nothing is changed. The report names no user, "
                       "tenant or object, so it can be shared.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        bar = QHBoxLayout()
        self.run_button = QPushButton("Run checks")
        self.copy_button = QPushButton("Copy report")
        self.copy_button.setEnabled(False)
        bar.addWidget(self.run_button)
        bar.addWidget(self.copy_button)
        bar.addStretch()
        layout.addLayout(bar)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        self.summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.summary)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(list(COLUMNS))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, 1)
        self.run_button.clicked.connect(self.run)
        self.copy_button.clicked.connect(self.copy_report)

    def activate_page(self) -> None:
        if self.report is None and not self.running:
            self.run()

    def reload(self) -> None:
        self.run()

    def run(self) -> None:
        if self.running:
            return
        self.running = True
        self.run_button.setEnabled(False)
        self.summary.setText("Checking...")
        session = self.window.session
        read_only = bool(getattr(self.window, "read_only", False))
        self.window.runner.submit(lambda: run_checks(session.graph, session_token(session), read_only=read_only),
                                  self._done, self._failed, owner=self)

    def _done(self, report: Report) -> None:
        self.running = False
        self.run_button.setEnabled(True)
        self.report = report
        self.copy_button.setEnabled(True)
        passed = sum(1 for r in report.results if r.ok)
        lines = [f"{passed} of {len(report.results)} checks passed."]
        if report.token.error:
            lines.append(f"Your token couldn't be read ({report.token.error}).")
        else:
            roles = report.roles
            lines.append("Active roles in your token: " + (", ".join(roles) if roles else "none"))
            present, missing = report.optional_present or [], report.optional_missing or []
            lines.append("Optional permissions present: " + (", ".join(present) or "none")
                         + "; missing: " + (", ".join(missing) or "none"))
        self.summary.setText("\n".join(lines))
        self.table.setRowCount(len(report.results))
        for row, result in enumerate(report.results):
            values = (result.probe.feature, result.outcome,
                      result.detail if result.ok else f"{result.detail}  -  needs {result.probe.needs}",
                      f"{result.milliseconds} ms")
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 1:
                    item.setForeground(QColor(COLOURS.get(result.outcome, "#000000")))
                if col == 2:
                    item.setToolTip(value)
                self.table.setItem(row, col, item)

    def _failed(self, exc: BaseException) -> None:
        self.running = False
        self.run_button.setEnabled(True)
        self.summary.setText(f"The check could not run: {exc}")

    def copy_report(self) -> None:
        if self.report is not None:
            QGuiApplication.clipboard().setText(self.report.text())

    def outcomes(self) -> list[tuple[str, str]]:
        return [(self.table.item(r, 0).text(), self.table.item(r, 1).text()) for r in range(self.table.rowCount())]
