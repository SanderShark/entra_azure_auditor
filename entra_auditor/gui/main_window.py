"""Main window, ADUC style: navigation | page. The Users page is list | property tabs; the
Administrative units page is units | members | settings; Roles / PIM shows your roles and PIM groups.

The user directory loads once in the background (all pages, ``$select``, ``$top=999``) and is filtered
locally as you type. Other pages load the first time they are shown. Every change goes through
``ChangeController`` (preview, confirm, PIM, result), one at a time.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

from PySide6.QtCore import QItemSelectionModel, QModelIndex, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QComboBox,
    QDialog,
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
    QStackedWidget,
    QTableView,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..toolkit.actions import PlanError, plan_set_enabled
from ..toolkit.leaver import LeaverFacts, gather_leaver_facts, plan_leaver
from ..toolkit.onboarding import Template, gather_template, plan_onboard
from ..toolkit.directory import USER_SCOPES
from ..toolkit.directory import LoadCancelled, load_users
from ..toolkit.models import UserSummary
from ..toolkit.search import get_user
from .admin_units_page import AdminUnitsPage
from .change import ChangeController
from .devices_page import DevicesPage
from .groups_page import GroupsPage
from .leaver import LeaverDialog
from .onboarding import NewUserDialog
from .roles_page import RolesPage
from .session import GuiSession
from .tasks import TaskRunner
from .user_detail import UserDetail
from .user_model import USER_ROLE, UserFilterProxy, UserTableModel

FILTER_DELAY_MS = 150
SECTIONS = ("Users", "Groups", "Devices", "Administrative units", "Roles / PIM", "Audit", "Action log")
READY = ("Users", "Groups", "Devices", "Administrative units", "Roles / PIM")
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
        self.switch_requested = False       # set by "Switch tenant...": the app signs in again after closing
        self._load_generation = 0
        self.loading = False
        self.change: Optional[ChangeController] = None
        self.setWindowTitle(f"Entra toolkit - {session.tenant.name}")
        self.resize(1280, 760)

        # -- navigation -------------------------------------------------------- #
        self.nav = QListWidget()
        for name in SECTIONS:
            item = QListWidgetItem(name)
            if name not in READY:
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
        self.scope_box = QComboBox()
        self.scope_box.setToolTip("Which user objects to load. In a tenant with many guests or cross-tenant-synced "
                                  "users, a narrower choice loads much faster.")
        for key, (label, _filter) in USER_SCOPES.items():
            self.scope_box.addItem(label, key)
        self.scope_box.setCurrentIndex(max(self.scope_box.findData(getattr(session.tenant, "user_scope", "all")), 0))
        self.hide_external_box = QCheckBox("Hide external (#EXT#)")
        self.hide_external_box.setToolTip("Leave out users whose sign-in name contains #EXT#: guests and users synced "
                                          "from other tenants. They are skipped while loading (their pages are "
                                          "still downloaded; a narrower choice on the left avoids that).")
        self.hide_external_box.setChecked(bool(getattr(session.tenant, "hide_external", False)))
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
        filter_row = QHBoxLayout()
        filter_row.addWidget(self.filter_edit, 1)
        filter_row.addWidget(self.scope_box)
        filter_row.addWidget(self.hide_external_box)
        middle_layout.addLayout(filter_row)
        middle_layout.addWidget(self.table)
        middle_layout.addWidget(self.count_label)

        # -- properties ----------------------------------------------------------- #
        self.detail = UserDetail(runner, lambda: self.session.graph)
        self.detail.group_opened.connect(self.show_group)
        self.detail.licences_tab.on_plan = lambda plan, user: self.start_change(plan, user)

        self.users_page = QSplitter()
        self.users_page.addWidget(middle)
        self.users_page.addWidget(self.detail)
        self.users_page.setStretchFactor(0, 3)
        self.users_page.setStretchFactor(1, 2)
        self.users_page.setSizes([760, 370])

        # -- pages ------------------------------------------------------------------- #
        self.groups_page = GroupsPage(self)
        self.devices_page = DevicesPage(self)
        self.admin_units_page = AdminUnitsPage(self)
        self.roles_page = RolesPage(self)
        self.pages: dict[str, QWidget] = {"Users": self.users_page, "Groups": self.groups_page,
                                          "Devices": self.devices_page,
                                          "Administrative units": self.admin_units_page,
                                          "Roles / PIM": self.roles_page}
        self.stack = QStackedWidget()
        for page in self.pages.values():
            self.stack.addWidget(page)

        splitter = QSplitter()
        splitter.addWidget(self.nav)
        splitter.addWidget(self.stack)
        splitter.setStretchFactor(0, 0)       # the navigation keeps its width; the page takes the rest
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([150, 1130])
        self.setCentralWidget(splitter)

        # -- actions --------------------------------------------------------------- #
        self.refresh_action = QAction("Reload directory", self)
        self.refresh_action.setShortcut(QKeySequence.StandardKey.Refresh)
        self.refresh_action.triggered.connect(self.reload_current_page)
        self.toggle_action = QAction("Disable account", self)
        self.toggle_action.setEnabled(False)
        self.toggle_action.triggered.connect(self.toggle_selected_account)
        toolbar = QToolBar("Actions")
        toolbar.setMovable(False)
        toolbar.addAction(self.refresh_action)
        toolbar.addSeparator()
        toolbar.addAction(self.toggle_action)
        self.offboard_action = QAction("Offboard...", self)
        self.offboard_action.setToolTip("Leaver workflow: disable, sign out, reset password, remove licences, "
                                        "groups and administrative units, in one previewed change.")
        self.offboard_action.setEnabled(False)
        self.offboard_action.triggered.connect(self.offboard_selected)
        toolbar.addAction(self.offboard_action)
        self.new_user_action = QAction("New user...", self)
        self.new_user_action.setToolTip("Create a user. Select an existing user first to copy their department, "
                                        "manager, licences and groups.")
        self.new_user_action.triggered.connect(self.new_user)
        toolbar.addAction(self.new_user_action)
        self.dialog: Optional[QDialog] = None
        self._gathering = False
        toolbar.addSeparator()
        self.switch_action = QAction("Switch tenant...", self)
        self.switch_action.setToolTip("Close this tenant and sign in to another one (each tenant keeps its own "
                                      "sign-in).")
        self.switch_action.triggered.connect(self.switch_tenant)
        toolbar.addAction(self.switch_action)
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
        self.scope_box.currentIndexChanged.connect(lambda _index: self.load_directory(restart=True))
        self.hide_external_box.toggled.connect(lambda _on: self.load_directory(restart=True))
        self.nav.currentRowChanged.connect(self._section_changed)
        self._update_count()

    # -- pages ----------------------------------------------------------------------- #

    @property
    def current_section(self) -> str:
        item = self.nav.currentItem()
        return item.text() if item else "Users"

    def show_section(self, name: str) -> None:
        self.nav.setCurrentRow(SECTIONS.index(name))

    def _section_changed(self, row: int) -> None:
        name = SECTIONS[row] if 0 <= row < len(SECTIONS) else "Users"
        page = self.pages.get(name)
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        on_users = page is self.users_page
        self.toggle_action.setVisible(on_users)
        self.offboard_action.setVisible(on_users)
        self.new_user_action.setVisible(on_users)
        self.refresh_action.setText("Reload directory" if on_users else "Reload")
        self.refresh_action.setEnabled(not self.loading if on_users else True)
        activate = getattr(page, "activate_page", None)
        if activate is not None:
            activate()

    @Slot()
    def reload_current_page(self) -> None:
        page = self.stack.currentWidget()
        if page is self.users_page:
            self.load_directory()
        else:
            page.reload()

    def show_group(self, group_id: str) -> None:
        """Open a group on the Groups page (loading the page first if it hasn't been opened yet)."""
        self.show_section("Groups")
        page = self.groups_page
        if page.loaded:
            page.select_group(group_id)
        else:
            page.pending_group = group_id

    def show_user(self, user_id: str) -> bool:
        """Open a user on the Users page (e.g. double-clicked in an administrative unit)."""
        self.show_section("Users")
        if not self.select_user(user_id):
            self.filter_edit.clear()
            self.apply_filter()
            return self.select_user(user_id)
        return True

    # -- directory ------------------------------------------------------------------ #

    @Slot()
    def load_directory(self, restart: bool = False) -> None:
        """Load the users in the chosen scope. ``restart`` abandons a load that is still running (the
        scope was changed): its pages stop at the next one and its result is dropped."""
        if self.loading and not restart:
            return
        self._load_generation += 1
        generation, graph, scope = self._load_generation, self.session.graph, self.user_scope
        hide_external = self.hide_external_box.isChecked()
        self.loading = True
        self.refresh_action.setEnabled(False)
        self._load_started = time.perf_counter()
        self.statusBar().showMessage("Loading users...")
        self.runner.submit(
            lambda: self._loader(graph, on_progress=self.load_progress.emit, scope=scope,
                                 exclude_external=hide_external,
                                 should_cancel=lambda: self._closing or generation != self._load_generation),
            lambda users: self._loaded(generation, users),
            lambda exc: self._load_failed(generation, exc))

    @property
    def user_scope(self) -> str:
        return self.scope_box.currentData() or "all"

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
        else:
            notes = [n for n in ("" if self.user_scope == "all" else USER_SCOPES[self.user_scope][0].lower(),
                                 "external hidden" if self.hide_external_box.isChecked() else "") if n]
            scope = f" ({', '.join(notes)})" if notes else ""
            noun = "user" if total == 1 else "users"
            self.count_label.setText((f"{total:,} {noun}" if shown == total else f"{shown:,} of {total:,} {noun}") + scope)

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
        self.offboard_action.setEnabled(user is not None and self.change is None and not self._gathering)
        self.new_user_action.setEnabled(self.change is None and not self._gathering)
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
        menu.addAction(self.offboard_action)
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

    @Slot()
    def offboard_selected(self) -> None:
        """Gather what the user has (on a worker), then ask what should happen to it."""
        user = self.selected_user()
        if user is None or self.change is not None or self._gathering:
            return
        self._gathering = True
        self._update_actions(user)
        self.statusBar().showMessage(f"Reading what {user.label} has...")
        graph = self.session.graph

        def failed(exc: BaseException) -> None:
            self._gathering = False
            self._update_actions(self.selected_user())
            self.statusBar().showMessage("Offboarding could not start.", 10_000)
            QMessageBox.warning(self, "Could not start offboarding", f"Reading the user failed:\n\n{exc}")

        self.runner.submit(lambda: gather_leaver_facts(graph, user.id), self._leaver_facts_ready, failed)

    def _leaver_facts_ready(self, facts: LeaverFacts) -> None:
        self._gathering = False
        self.statusBar().clearMessage()
        self._update_actions(self.selected_user())
        dialog = LeaverDialog(facts, self)
        self.dialog = dialog

        def answered(code: int) -> None:
            self.dialog = None
            if code != QDialog.DialogCode.Accepted:
                return
            try:
                plan = plan_leaver(facts, dialog.options())
            except PlanError as exc:
                QMessageBox.information(self, "Nothing to do", str(exc))
                return
            self.start_change(plan, facts.user)

        dialog.finished.connect(answered)
        dialog.open()

    @Slot()
    def new_user(self) -> None:
        """Create a user, modelled on the selected one if there is a selection."""
        if self.change is not None or self._gathering:
            return
        model = self.selected_user()
        if model is None:
            self._open_new_user(None)
            return
        self._gathering = True
        self._update_actions(model)
        self.statusBar().showMessage(f"Reading {model.label} as a template...")
        graph = self.session.graph

        def failed(exc: BaseException) -> None:
            self._gathering = False
            self._update_actions(self.selected_user())
            self.statusBar().showMessage("The template could not be read.", 10_000)
            QMessageBox.warning(self, "Could not read the template", f"Reading {model.label} failed:\n\n{exc}")

        self.runner.submit(lambda: gather_template(graph, model.id), self._open_new_user, failed)

    def _open_new_user(self, template: Optional[Template]) -> None:
        self._gathering = False
        self.statusBar().clearMessage()
        self._update_actions(self.selected_user())
        identity = self.session.identity.removeprefix("user:")
        dialog = NewUserDialog(template, self, default_domain=identity.rpartition("@")[2] if "@" in identity else "")
        self.dialog = dialog

        def answered(code: int) -> None:
            self.dialog = None
            if code != QDialog.DialogCode.Accepted:
                return
            new = dialog.new_user()
            try:
                plan = plan_onboard(new, template, dialog.options(), self.session.graph.base_url)
            except PlanError as exc:
                QMessageBox.information(self, "Can't create this user", str(exc))
                return

            def finished(done: Any) -> None:
                if done.result.status in ("ok", "partial"):
                    self.load_directory()           # the new user appears in the list

            self.start_change(plan, on_finished=finished, extra_secrets={"password": new.password})

        dialog.finished.connect(answered)
        dialog.open()

    def start_change(self, plan: Any, user: Optional[UserSummary] = None, *,
                     on_finished: Optional[Callable[[Any], None]] = None,
                     extra_secrets: Optional[dict[str, str]] = None) -> Optional[ChangeController]:
        """Run a change through the dialogs. One at a time: returns None if another is still running."""
        if self.change is not None:
            QMessageBox.information(self, "Another change is running", "Finish the current change first.")
            return None
        controller = ChangeController(self.session, plan, self.runner, self, sleep=self._change_sleep,
                                      extra_secrets=extra_secrets)
        self.change = controller
        self._update_actions(self.selected_user())
        controller.finished.connect(lambda done: self._change_finished(done, user, on_finished))
        controller.start()
        return controller

    def _change_finished(self, done: Any, user: Optional[UserSummary],
                         on_finished: Optional[Callable[[Any], None]] = None) -> None:
        self.change_done = done
        self.change = None
        if done.cancelled:
            self.statusBar().showMessage("Cancelled. Nothing was changed.", 10_000)
        else:
            self.statusBar().showMessage(f"{done.result.status.upper()}: {done.result.message}", 10_000)
        if user is not None and done.result.status in ("ok", "partial"):
            self._refresh_user(user.id)
        self._update_actions(self.selected_user())
        if on_finished is not None:
            on_finished(done)

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

    @Slot()
    def switch_tenant(self) -> None:
        """Close this window so the app can sign in to another tenant. Not while a change is running."""
        if self.change is not None:
            QMessageBox.information(self, "A change is running", "Finish the current change before switching tenant.")
            return
        self.switch_requested = True
        self.close()

    # -- shutdown --------------------------------------------------------------------------------- #

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt's name
        self._closing = True          # a running directory load stops at its next page
        super().closeEvent(event)
