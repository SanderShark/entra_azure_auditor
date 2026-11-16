"""Property tabs for the selected user: General, On-premises, Groups, Licences, Sign-in methods,
Certificate IDs, Roles, Who can manage.

One profile load feeds every tab (no extra requests per tab). A part of the profile that couldn't be read
is shown as "could not be read", never as an empty list (unknown is not empty).

The profile loads on a worker after the selection settles (a short delay, so arrowing through the list
doesn't fire a burst of Graph requests). A response for a user who is no longer selected is dropped.

"Who can manage" needs some twenty extra requests, so it loads lazily: only when its tab is looked at.
"Licences" loads the same way (it reads the tenant's subscriptions, which must be fresh to show what is free).
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..toolkit.actions import PlanError, plan_change_licences
from ..toolkit.licences import LicenceReport, load_user_licences
from ..toolkit.managers import ManagerReport, who_can_manage
from ..toolkit.models import UserProfile, UserSummary
from ..toolkit.profile import load_user_profile
from .tasks import TaskRunner

SELECTION_DELAY_MS = 250

GENERAL_FIELDS: tuple[tuple[str, Callable[[UserProfile], str]], ...] = (
    ("Name", lambda p: p.display_name or "-"),
    ("User principal name", lambda p: p.upn or "-"),
    ("Email", lambda p: p.mail or "-"),
    ("Object id", lambda p: p.id),
    ("Type", lambda p: p.user_type or "-"),
    ("Account", lambda p: "?" if p.account_enabled is None else "Enabled" if p.account_enabled else "Disabled"),
    ("Job title", lambda p: p.job_title or "-"),
    ("Department", lambda p: p.department or "-"),
    ("Company", lambda p: p.company or "-"),
    ("Office", lambda p: p.office or "-"),
    ("Mobile phone", lambda p: p.mobile_phone or "-"),
    ("Employee id", lambda p: p.employee_id or "-"),
    ("Manager", lambda p: p.manager or "-"),
    ("Usage location", lambda p: p.usage_location or "-"),
    ("Created", lambda p: f"{p.created_at:%Y-%m-%d}" if p.created_at else "-"),
    ("Password changed", lambda p: f"{p.last_password_change:%Y-%m-%d}" if p.last_password_change else "-"),
    ("Last sign-in", lambda p: (f"{p.last_sign_in:%Y-%m-%d %H:%M} UTC" if p.last_sign_in else "never / unknown")
     if p.sign_in_available else "(needs Entra ID P1/P2)"),
    ("Synced from AD", lambda p: ("yes" + (f" ({p.on_prem_sam_account})" if p.on_prem_sam_account else ""))
     if p.on_prem_synced else "no (cloud only)"),
    ("Invitation", lambda p: (p.external_user_state or "-") if p.is_guest else "n/a (member)"),
    ("Licences", lambda p: str(p.license_count)),
    ("Email aliases", lambda p: "\n".join([a for a in p.proxy_addresses if a.lower().startswith("smtp:")]
                                          + p.other_mails) or "-"),
)


def _value_label() -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class GeneralTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)   # long values wrap instead
        inner = QWidget()
        form = QFormLayout(inner)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.values: dict[str, QLabel] = {}
        for name, _ in GENERAL_FIELDS:
            self.values[name] = _value_label()
            form.addRow(f"{name}:", self.values[name])
        self.warnings = _value_label()
        self.warnings.setStyleSheet("color: #b26a00;")
        form.addRow(self.warnings)
        scroll.setWidget(inner)
        outer.addWidget(scroll)

    def show_profile(self, profile: UserProfile) -> None:
        for name, getter in GENERAL_FIELDS:
            self.values[name].setText(getter(profile))
        self.warnings.setText("\n".join(f"! {w}" for w in profile.warnings))


UNREADABLE = "(could not be read)"

ON_PREM_FIELDS: tuple[tuple[str, Callable[[Any], str]], ...] = (
    ("Location", lambda r: r.location or "-"),
    ("Logon name", lambda r: r.logon_name or "-"),
    ("On-premises UPN", lambda r: r.upn or "-"),
    ("Domain", lambda r: r.domain or "-"),
    ("Distinguished name", lambda r: r.distinguished_name or "-"),
    ("Security identifier", lambda r: r.sid or "-"),
    ("Source anchor", lambda r: r.immutable_id or "-"),
    ("Last synchronised", lambda r: f"{r.last_sync:%Y-%m-%d %H:%M} UTC" if r.last_sync else "-"),
    ("Extension attributes", lambda r: "\n".join(f"{k} = {v}" for k, v in r.extension_attributes.items()) or "none set"),
    ("Synchronisation errors", lambda r: "\n".join(r.provisioning_errors) or "none"),
)


ON_PREM_MULTILINE = ("Extension attributes", "Synchronisation errors")


def _value_line() -> QLineEdit:
    """A one-line value that can be longer than the pane (a distinguished name has no spaces to wrap at):
    read-only, selectable, scrollable with the cursor, and shown in full as its tooltip."""
    line = QLineEdit()
    line.setReadOnly(True)
    line.setFrame(False)
    line.setStyleSheet("background: transparent;")
    return line


class OnPremTab(QWidget):
    """What Entra holds about the user's on-premises AD object: the hybrid half of the record."""

    NOTE = ("This is the copy of the on-premises object that the sync keeps in Entra ID, not a live read of Active "
            "Directory: attributes that aren't synchronised don't appear here.")

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        form = QFormLayout(inner)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.status = _value_label()
        form.addRow("Status:", self.status)
        self.values: dict[str, Any] = {}
        for name, _getter in ON_PREM_FIELDS:
            self.values[name] = _value_label() if name in ON_PREM_MULTILINE else _value_line()
            form.addRow(f"{name}:", self.values[name])
        note = _value_label()
        note.setText(self.NOTE)
        note.setStyleSheet("color: #666;")
        form.addRow(note)
        scroll.setWidget(inner)
        outer.addWidget(scroll)

    def show_record(self, record: Any) -> None:
        if record is None:
            self.status.setText(UNREADABLE)
        elif record.synced:
            self.status.setText("Synchronised from on-premises Active Directory: change AD-mastered attributes there.")
        elif record.has_record:
            self.status.setText("Not synchronised now, but an on-premises record remains (it was synchronised before).")
        else:
            self.status.setText("Cloud-only account: there is no on-premises record.")
        for name, getter in ON_PREM_FIELDS:
            text = UNREADABLE if record is None else getter(record) if record.has_record else "-"
            widget = self.values[name]
            widget.setText(text)
            if isinstance(widget, QLineEdit):
                widget.setCursorPosition(0)         # show the start of a long value, not its end
                widget.setToolTip(text)


class ListTab(QWidget):
    """A tab of titled lists. Each section is (title, items or None, text when empty)."""

    def __init__(self, titles: tuple[str, ...], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.lists: dict[str, QListWidget] = {}
        for title in titles:
            layout.addWidget(QLabel(f"<b>{title}</b>"))
            widget = QListWidget()
            widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
            self.lists[title] = widget
            layout.addWidget(widget)

    def show_items(self, title: str, items: Optional[list[str]], empty: str,
                   data: Optional[list[Any]] = None) -> None:
        """``data`` (same length as ``items``) is attached to the rows, for double-click handlers."""
        widget = self.lists[title]
        widget.clear()
        if items is None:
            widget.addItem(UNREADABLE)
        elif not items:
            widget.addItem(empty)
        else:
            widget.addItems(items)
            for row, value in enumerate(data or []):
                widget.item(row).setData(Qt.ItemDataRole.UserRole, value)

    def texts(self, title: str) -> list[str]:
        widget = self.lists[title]
        return [widget.item(i).text() for i in range(widget.count())]


class ManagersTab(QWidget):
    """Who can manage this user: the admins whose role reaches them, and what each can do.

    Loads on demand (`ensure_loaded`, called when the tab is shown). A response for a user who is no longer
    selected is dropped. One wrapped entry per admin (the pane is narrow: a table hid the "Can" column);
    admins who can do nothing for this user are greyed and say why.
    """

    COLUMNS = ("Who", "Role", "Scope", "Assignment", "Can")
    PROMPT = "Open this tab to see who can manage the user."

    def __init__(self, runner: TaskRunner, graph_source: Callable[[], Any], parent: Optional[QWidget] = None, *,
                 loader: Callable[[Any, str], ManagerReport] = who_can_manage) -> None:
        super().__init__(parent)
        self.runner = runner
        self._graph_source = graph_source
        self._loader = loader
        self.user_id: Optional[str] = None
        self.report: Optional[ManagerReport] = None
        self._generation = 0
        self._requested = False

        layout = QVBoxLayout(self)
        self.summary = _value_label()
        layout.addWidget(self.summary)
        self.list = QListWidget()
        self.list.setWordWrap(True)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)   # entries wrap instead
        self.list.setAlternatingRowColors(True)
        self.list.setSpacing(2)
        self.list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        layout.addWidget(self.list, 1)
        self.footnote = _value_label()
        self.footnote.setStyleSheet("color: #666;")
        self.footnote.setText("From Microsoft's published rules for built-in roles. Not shown: custom roles, group "
                              "owners, and admins who would get a role by activating a PIM group membership.")
        layout.addWidget(self.footnote)
        self.set_user(None)

    @property
    def loading(self) -> bool:
        return self._requested and self.report is None and self.user_id is not None

    def set_user(self, user_id: Optional[str]) -> None:
        """Forget what is shown; nothing is requested until the tab is looked at."""
        self._generation += 1
        self.user_id, self.report, self._requested = user_id, None, False
        self.list.clear()
        self.summary.setText(self.PROMPT if user_id else "")

    def ensure_loaded(self) -> None:
        if self.user_id is None or self._requested:
            return
        self._requested = True
        generation, user_id, graph = self._generation, self.user_id, self._graph_source()
        self.summary.setText("Working out who can manage this user...")
        self.runner.submit(lambda: self._loader(graph, user_id),
                           lambda report: self._loaded(generation, report),
                           lambda exc: self._failed(generation, exc), owner=self)

    def _loaded(self, generation: int, report: ManagerReport) -> None:
        if generation != self._generation:
            return
        self.report = report
        lines = list(report.notes) + [f"! {w}" for w in report.warnings]
        if report.managers is None:
            lines.append("The admins " + UNREADABLE + ".")
        elif not report.managers:
            lines.append("No admin with a user-management role was found.")
        self.summary.setText("\n".join(lines))
        self.list.clear()
        grey = QBrush(QColor("#888"))
        for manager in report.managers or []:
            can = ", ".join(manager.can) if manager.can else "nothing for this user"
            if manager.why_not:
                can += f" ({manager.why_not})"
            row = (manager.who, manager.role, manager.scope_label, manager.assignment_label, can)
            item = QListWidgetItem(f"{row[0]}\n{row[1]}  |  {row[2]}  |  {row[3]}\nCan: {can}")
            item.setData(Qt.ItemDataRole.UserRole, row)
            if not manager.can:
                item.setForeground(grey)
            self.list.addItem(item)

    def _failed(self, generation: int, exc: BaseException) -> None:
        if generation != self._generation:
            return
        self._requested = False             # looking at the tab again retries
        self.summary.setText(f"Could not work out who can manage this user: {exc}")

    def rows(self) -> list[tuple[str, ...]]:
        """What is listed, as (who, role, scope, assignment, can) per admin."""
        return [tuple(self.list.item(i).data(Qt.ItemDataRole.UserRole)) for i in range(self.list.count())]


class LicenceDialog(QDialog):
    """Tick the licences the user should hold directly. Inherited ones are shown but can't be unticked here."""

    def __init__(self, report: LicenceReport, user_label: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.report = report
        self.setWindowTitle(f"Licences: {user_label}")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        intro = QLabel("Tick the licences this user should have. Licences that come from a group are "
                       "managed through that group.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.list = QListWidget()
        held = {lic.sku_id: lic for lic in report.licences or []}
        for sku in report.skus or []:
            licence = held.get(sku.sku_id)
            direct = bool(licence and licence.direct)
            text = f"{sku.name}  -  {sku.usage}"
            if licence and licence.groups:
                text += f"  (inherited from {', '.join(licence.groups)})"
            if not sku.assignable:
                text += f"  [{sku.status or 'not assignable'}]"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, sku)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if direct else Qt.CheckState.Unchecked)
            if not direct and (not sku.assignable or sku.available == 0):
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)     # nothing left to give
            self.list.addItem(item)
        layout.addWidget(self.list)
        form = QFormLayout()
        self.location = QLineEdit(report.usage_location or "")
        self.location.setMaxLength(2)
        self.location.setPlaceholderText("two-letter country code, e.g. US")
        self.location.setEnabled(not report.usage_location)
        form.addRow("Usage location", self.location)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("Preview change...")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def set_checked(self, text: str, checked: bool) -> None:
        """Tick or untick the product whose line contains ``text`` (tests and keyboard users)."""
        for row in range(self.list.count()):
            if text in self.list.item(row).text():
                self.list.item(row).setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)

    def changes(self) -> tuple[list[Any], list[Any]]:
        """(subscriptions to add, subscriptions to remove) compared with what is held directly now."""
        direct = {lic.sku_id for lic in self.report.licences or [] if lic.direct}
        add, remove = [], []
        for row in range(self.list.count()):
            item = self.list.item(row)
            sku, ticked = item.data(Qt.ItemDataRole.UserRole), item.checkState() == Qt.CheckState.Checked
            if ticked and sku.sku_id not in direct:
                add.append(sku)
            elif not ticked and sku.sku_id in direct:
                remove.append(sku)
        return add, remove


class LicencesTab(QWidget):
    """The user's licences and where each comes from; "Change licences..." builds a plan and hands it to
    ``on_plan`` (the window runs it through the change flow). Loads when the tab is shown."""

    PROMPT = "Open this tab to see the user's licences."

    def __init__(self, runner: TaskRunner, graph_source: Callable[[], Any], parent: Optional[QWidget] = None, *,
                 loader: Callable[[Any, str], LicenceReport] = load_user_licences) -> None:
        super().__init__(parent)
        self.runner = runner
        self._graph_source = graph_source
        self._loader = loader
        self.user: Optional[UserSummary] = None
        self.report: Optional[LicenceReport] = None
        self.on_plan: Optional[Callable[[Any, UserSummary], None]] = None
        self.dialog: Optional[LicenceDialog] = None
        self.read_only = False          # set by the window for a read-only session
        self._generation = 0
        self._requested = False

        layout = QVBoxLayout(self)
        self.summary = _value_label()
        layout.addWidget(self.summary)
        self.list = QListWidget()
        self.list.setWordWrap(True)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(self.list, 1)
        bar = QHBoxLayout()
        self.change_button = QPushButton("Change licences...")
        self.change_button.clicked.connect(self.change_licences)
        bar.addWidget(self.change_button)
        bar.addStretch()
        layout.addLayout(bar)
        self.set_user(None)

    def set_user(self, user: Optional[UserSummary]) -> None:
        self._generation += 1
        self.user, self.report, self._requested = user, None, False
        self.list.clear()
        self.summary.setText(self.PROMPT if user else "")
        self.change_button.setEnabled(False)

    def ensure_loaded(self) -> None:
        if self.user is None or self._requested:
            return
        self._requested = True
        generation, user_id, graph = self._generation, self.user.id, self._graph_source()
        self.summary.setText("Loading licences...")
        self.runner.submit(lambda: self._loader(graph, user_id),
                           lambda report: self._loaded(generation, report),
                           lambda exc: self._failed(generation, exc), owner=self)

    def _loaded(self, generation: int, report: LicenceReport) -> None:
        if generation != self._generation:
            return
        self.report = report
        self.list.clear()
        if report.licences is None:
            self.list.addItem(UNREADABLE)
        elif not report.licences:
            self.list.addItem("no licences")
        else:
            self.list.addItems([lic.label for lic in report.licences])
        lines = [f"Usage location: {report.usage_location or 'not set (needed before a licence can be assigned)'}"]
        self.summary.setText("\n".join(lines + [f"! {w}" for w in report.warnings]))
        # changing needs both lists: what the tenant has, and what the user holds
        self.change_button.setEnabled(report.licences is not None and bool(report.skus) and not self.read_only)
        self.change_button.setToolTip("Read-only session." if self.read_only else "" if self.change_button.isEnabled()
                                      else "The tenant's subscriptions or the user's licences couldn't be read.")

    def _failed(self, generation: int, exc: BaseException) -> None:
        if generation != self._generation:
            return
        self._requested = False
        self.summary.setText(f"Could not load the licences: {exc}")

    def texts(self) -> list[str]:
        return [self.list.item(i).text() for i in range(self.list.count())]

    def change_licences(self) -> None:
        if self.report is None or self.user is None or self.report.licences is None:
            return
        report, user = self.report, self.user
        dialog = LicenceDialog(report, user.full_label, self)
        self.dialog = dialog

        def answered(code: int) -> None:
            self.dialog = None
            if code != QDialog.DialogCode.Accepted:
                return
            add, remove = dialog.changes()
            try:
                plan = plan_change_licences(user, add, remove, current=report.licences or [],
                                            usage_location=report.usage_location,
                                            set_usage_location=dialog.location.text())
            except PlanError as exc:
                QMessageBox.information(self, "Nothing to do", str(exc))
                return
            if self.on_plan is not None:
                self.on_plan(plan, user)

        dialog.finished.connect(answered)
        dialog.open()


class UserDetail(QWidget):
    """Placeholder text, or the tabs for one user."""

    group_opened = Signal(str)          # a group on the Groups tab was double-clicked (its id)

    def __init__(self, runner: TaskRunner, graph_source: Callable[[], Any], parent: Optional[QWidget] = None, *,
                 loader: Callable[[Any, str], UserProfile] = load_user_profile) -> None:
        super().__init__(parent)
        self.runner = runner
        self._graph_source = graph_source
        self._loader = loader
        self.user: Optional[UserSummary] = None
        self.profile: Optional[UserProfile] = None
        self._generation = 0
        self._pending = False

        self.stack = QStackedWidget()
        self.message = QLabel("Select a user to see their properties.")
        self.message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.message.setWordWrap(True)
        self.tabs = QTabWidget()
        self.general = GeneralTab()
        self.tabs.addTab(self.general, "General")
        self.on_prem_tab = OnPremTab()
        self.tabs.addTab(self.on_prem_tab, "On-premises")
        self.groups_tab = ListTab(("Member of", "Owns"))
        for widget in self.groups_tab.lists.values():
            widget.setToolTip("Double-click a group to open it on the Groups page.")
            widget.itemDoubleClicked.connect(self._open_ref)
        self.licences_tab = LicencesTab(runner, graph_source)
        self.methods_tab = ListTab(("Sign-in methods",))
        self.certs_tab = ListTab(("Certificate user IDs",))
        self.roles_tab = ListTab(("Active roles", "Eligible roles (PIM)"))
        self.tabs.addTab(self.groups_tab, "Groups")
        self.tabs.addTab(self.licences_tab, "Licences")
        self.tabs.addTab(self.methods_tab, "Sign-in methods")
        self.tabs.addTab(self.certs_tab, "Certificate IDs")
        self.tabs.addTab(self.roles_tab, "Roles")
        self.managers_tab = ManagersTab(runner, graph_source)
        self.tabs.addTab(self.managers_tab, "Who can manage")
        self.tabs.currentChanged.connect(self._tab_changed)
        self.stack.addWidget(self.message)
        self.stack.addWidget(self.tabs)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.stack)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(SELECTION_DELAY_MS)
        self._timer.timeout.connect(self._load)

    @property
    def loading(self) -> bool:
        return self._timer.isActive() or self._pending

    def show_user(self, user: Optional[UserSummary]) -> None:
        self._generation += 1
        self.user, self.profile = user, None
        self.managers_tab.set_user(None)
        self.licences_tab.set_user(None)
        if user is None:
            self._timer.stop()
            self._pending = False
            self._show_message("Select a user to see their properties.")
            return
        self._show_message(f"Loading {user.full_label}...")
        self._timer.start()

    def reload(self) -> None:
        self.show_user(self.user)

    def _show_message(self, text: str) -> None:
        self.message.setText(text)
        self.stack.setCurrentWidget(self.message)

    def _load(self) -> None:
        if self.user is None:
            return
        generation, user_id, graph = self._generation, self.user.id, self._graph_source()
        self._pending = True
        self.runner.submit(lambda: self._loader(graph, user_id),
                           lambda profile: self._loaded(generation, profile),
                           lambda exc: self._failed(generation, exc), owner=self)

    def _loaded(self, generation: int, profile: UserProfile) -> None:
        if generation != self._generation:
            return              # the selection moved on while this was loading
        self._pending = False
        self.profile = profile
        self.general.show_profile(profile)
        self.on_prem_tab.show_record(profile.on_prem)
        for title, refs, empty in (("Member of", profile.groups, "no groups"), ("Owns", profile.owned, "nothing")):
            ordered = None if refs is None else sorted(refs, key=lambda r: r.label.casefold())
            self.groups_tab.show_items(title, None if ordered is None else [r.label for r in ordered], empty, ordered)
        self.methods_tab.show_items("Sign-in methods", profile.auth_methods, "none registered")
        # cert IDs come back as [] both when there are none and when they couldn't be read; the warning
        # list says which (the General tab shows it)
        cert_unreadable = any("certificate" in w.lower() for w in profile.warnings)
        self.certs_tab.show_items("Certificate user IDs", None if cert_unreadable else profile.cert_user_ids, "none")
        self.roles_tab.show_items("Active roles", profile.roles_active, "none")
        self.roles_tab.show_items("Eligible roles (PIM)", profile.roles_eligible, "none")
        self.managers_tab.set_user(profile.id)
        self.licences_tab.set_user(self.user)
        self.stack.setCurrentWidget(self.tabs)
        self._tab_changed()

    def _open_ref(self, item: Any) -> None:
        ref = item.data(Qt.ItemDataRole.UserRole)
        if ref is not None and ref.kind == "group":
            self.group_opened.emit(ref.id)

    def _tab_changed(self, _index: int = 0) -> None:
        if self.stack.currentWidget() is not self.tabs:
            return
        current = self.tabs.currentWidget()
        if current is self.managers_tab or current is self.licences_tab:
            current.ensure_loaded()

    def _failed(self, generation: int, exc: BaseException) -> None:
        if generation != self._generation:
            return
        self._pending = False
        self._show_message(f"Could not load this user: {exc}")
