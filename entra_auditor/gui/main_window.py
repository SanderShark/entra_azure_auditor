"""Main window, ADUC style: navigation | list | property tabs.

The user directory loads once in the background (all pages, ``$select``, ``$top=999``) and is filtered
locally as you type. Changes go through ``ChangeController`` (preview, confirm, PIM, result).
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

from PySide6.QtCore import QItemSelectionModel, QModelIndex, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QSplitter,
    QTableView,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..toolkit.actions import PlanError, plan_set_enabled
from ..toolkit.directory import LoadCancelled, load_users
from ..toolkit.models import UserSummary
from ..toolkit.search import get_user
from .change import ChangeController
from .session import GuiSession
from .tasks import TaskRunner
from .user_detail import UserDetail
from .user_model import USER_ROLE, UserFilterProxy, UserTableModel

FILTER_DELAY_MS = 150
SECTIONS = ("Users", "Groups", "Roles / PIM", "Audit", "Action log")
LATER = "Coming in a later milestone."


class MainWindow(QMainWindow):
    load_progress = Signal(int)          # emitted from the loading worker

    def __init__(self, session: GuiSession, runner: TaskRunner, *,
                 loader: Callable[..., list[UserSummary]] = load_users,
                 change_sleep: Callable[[float], None] = time.sleep) -> None:
        super().__init__()
        self.session = session
        self.runner = runner
        self._loader = loader
        self._change_sleep = change_sleep
        self._closing = False
        self._load_generation = 0
        self.loading = False
        self.change: Optional[ChangeController] = None
        self.setWindowTitle(f"Entra toolkit - {session.tenant.name}")
        self.resize(1280, 760)

        # -- navigation -------------------------------------------------------- #
        self.nav = QListWidget()
        for name in SECTIONS:
            item = QListWidgetItem(name)
            if name != "Users":
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
                item.setToolTip(LATER)
            self.nav.addItem(item)
        self.nav.setCurrentRow(0)

        # -- list ---------------------------------------------------------------- #
        self.model = UserTableModel(self)
        self.proxy = UserFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter: name, UPN, mail, title, department, employee id...")
        self.filter_edit.setClearButtonEnabled(True)
        self.count_label = QLabel()
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((170, 220, 65, 75, 130)):
            self.table.setColumnWidth(column, width)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)

        middle = QWidget()
        middle_layout = QVBoxLayout(middle)
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.addWidget(self.filter_edit)
        middle_layout.addWidget(self.table)
        middle_layout.addWidget(self.count_label)

        # -- properties ----------------------------------------------------------- #
        self.detail = UserDetail(runner, lambda: self.session.graph)

        splitter = QSplitter()
        splitter.addWidget(self.nav)
        splitter.addWidget(middle)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 0)       # the navigation keeps its width; list and details share the rest
        splitter.setStretchFactor(1, 3)
        splitter.setStretchFactor(2, 2)
        splitter.setSizes([150, 760, 370])
        self.setCentralWidget(splitter)

        # -- actions --------------------------------------------------------------- #
        self.refresh_action = QAction("Reload directory", self)
        self.refresh_action.setShortcut(QKeySequence.StandardKey.Refresh)
        self.refresh_action.triggered.connect(self.load_directory)
        self.toggle_action = QAction("Disable account", self)
        self.toggle_action.setEnabled(False)
        self.toggle_action.triggered.connect(self.toggle_selected_account)
        toolbar = QToolBar("Actions")
        toolbar.setMovable(False)
        toolbar.addAction(self.refresh_action)
        toolbar.addSeparator()
        toolbar.addAction(self.toggle_action)
        self.addToolBar(toolbar)

        self.identity_label = QLabel(f"{session.identity.removeprefix('user:')}  |  {session.tenant.name}")
        self.statusBar().addPermanentWidget(self.identity_label)

        # -- wiring ---------------------------------------------------------------- #
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(FILTER_DELAY_MS)
        self._filter_timer.timeout.connect(self.apply_filter)
        self.filter_edit.textChanged.connect(lambda _text: self._filter_timer.start())
        self.table.selectionModel().currentRowChanged.connect(self._selection_changed)
        self.proxy.rowsInserted.connect(self._update_count)
        self.proxy.rowsRemoved.connect(self._update_count)
        self.proxy.modelReset.connect(self._update_count)
        self.proxy.layoutChanged.connect(self._update_count)
        self.load_progress.connect(self._on_progress)
        self._update_count()

    # -- directory ------------------------------------------------------------------ #

    @Slot()
    def load_directory(self) -> None:
        if self.loading:
            return
        self._load_generation += 1
        generation, graph = self._load_generation, self.session.graph
        self.loading = True
        self.refresh_action.setEnabled(False)
        self._load_started = time.perf_counter()
        self.statusBar().showMessage("Loading users...")
        self.runner.submit(
            lambda: self._loader(graph, on_progress=self.load_progress.emit,
                                 should_cancel=lambda: self._closing or generation != self._load_generation),
            lambda users: self._loaded(generation, users),
            lambda exc: self._load_failed(generation, exc))

    @Slot(int)
    def _on_progress(self, count: int) -> None:
        if self.loading:
            self.statusBar().showMessage(f"Loading users... {count:,}")

    def _loaded(self, generation: int, users: list[UserSummary]) -> None:
        if generation != self._load_generation or self._closing:
            return
        selected = self.selected_user()
        self.loading = False
        self.refresh_action.setEnabled(True)
        self.model.set_users(users)
        seconds = time.perf_counter() - self._load_started
        self.statusBar().showMessage(f"Loaded {len(users):,} users in {seconds:.1f} s", 10_000)
        if selected is not None:
            self.select_user(selected.id)
        self._update_count()

    def _load_failed(self, generation: int, exc: BaseException) -> None:
        if generation != self._load_generation or isinstance(exc, LoadCancelled):
            return
        self.loading = False
        self.refresh_action.setEnabled(True)
        self.statusBar().showMessage("Loading users failed.")
        QMessageBox.warning(self, "Could not load users",
                            f"The user list could not be loaded:\n\n{exc}\n\nThe list shown (if any) is from "
                            "before this attempt.")

    # -- filtering and selection --------------------------------------------------------- #

    @Slot()
    def apply_filter(self) -> None:
        self._filter_timer.stop()
        self.proxy.set_filter_text(self.filter_edit.text())
        self._update_count()

    def _update_count(self, *args: Any) -> None:
        total, shown = self.model.rowCount(), self.proxy.rowCount()
        if self.loading and total == 0:
            self.count_label.setText("Loading...")
        elif shown == total:
            self.count_label.setText(f"{total:,} users")
        else:
            self.count_label.setText(f"{shown:,} of {total:,} users")

    def selected_user(self) -> Optional[UserSummary]:
        index = self.table.selectionModel().currentIndex()
        return index.data(USER_ROLE) if index.isValid() else None

    def select_user(self, user_id: str) -> bool:
        for row in range(self.proxy.rowCount()):
            index = self.proxy.index(row, 0)
            user = index.data(USER_ROLE)
            if user is not None and user.id == user_id:
                self.table.selectionModel().setCurrentIndex(
                    index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
                self.table.scrollTo(index)
                return True
        return False

    @Slot(QModelIndex, QModelIndex)
    def _selection_changed(self, current: QModelIndex, previous: QModelIndex) -> None:
        user = current.data(USER_ROLE) if current.isValid() else None
        previous_user = previous.data(USER_ROLE) if previous.isValid() else None
        self._update_actions(user)
        if user is None or previous_user is None or user.id != previous_user.id or self.detail.user is None:
            self.detail.show_user(user)

    def _update_actions(self, user: Optional[UserSummary]) -> None:
        if user is None or user.account_enabled is None:
            self.toggle_action.setText("Disable account")
            self.toggle_action.setEnabled(False)
            return
        self.toggle_action.setText("Disable account" if user.account_enabled else "Enable account")
        self.toggle_action.setEnabled(self.change is None)

    def _context_menu(self, pos: Any) -> None:
        if self.selected_user() is None:
            return
        menu = QMenu(self)
        menu.addAction(self.toggle_action)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    # -- changes --------------------------------------------------------------------------- #

    @Slot()
    def toggle_selected_account(self) -> None:
        user = self.selected_user()
        if user is None or user.account_enabled is None or self.change is not None:
            return
        try:
            plan = plan_set_enabled(user, not user.account_enabled)
        except PlanError as exc:
            QMessageBox.information(self, "Nothing to change", str(exc))
            return
        self.start_change(plan, user)

    def start_change(self, plan: Any, user: Optional[UserSummary] = None) -> ChangeController:
        controller = ChangeController(self.session, plan, self.runner, self, sleep=self._change_sleep)
        self.change = controller
        self._update_actions(self.selected_user())
        controller.finished.connect(lambda done: self._change_finished(done, user))
        controller.start()
        return controller

    def _change_finished(self, done: Any, user: Optional[UserSummary]) -> None:
        self.change_done = done
        self.change = None
        if done.cancelled:
            self.statusBar().showMessage("Cancelled. Nothing was changed.", 10_000)
        else:
            self.statusBar().showMessage(f"{done.result.status.upper()}: {done.result.message}", 10_000)
        if user is not None and done.result.status in ("ok", "partial"):
            self._refresh_user(user.id)
        self._update_actions(self.selected_user())

    def _refresh_user(self, user_id: str) -> None:
        graph = self.session.graph
        self.runner.submit(lambda: get_user(graph, user_id), self._user_refreshed,
                           lambda exc: self.statusBar().showMessage(f"Could not re-read the user: {exc}", 10_000))

    def _user_refreshed(self, user: UserSummary) -> None:
        self.model.update_user(user)
        selected = self.selected_user()
        if selected is not None and selected.id == user.id:
            self._update_actions(user)
            self.detail.show_user(user)

    # -- shutdown --------------------------------------------------------------------------------- #

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt's name
        self._closing = True          # a running directory load stops at its next page
        super().closeEvent(event)
