"""Groups page: groups on the left, the selected group's members and owners in the middle, its properties
and what it belongs to on the right.

All groups load once and filter as you type. Exchange-managed groups (mail-enabled security, distribution
lists) are hidden unless asked for: Graph can't change them, they are managed in Exchange. Adding and
removing members and owners goes through the change flow (preview, confirm, PIM elevation, result); what
Graph can't do (synced, dynamic, Exchange-managed groups) is explained instead of attempted.

Double-click a user to open it on the Users page, a group to open that group here.

Group add/remove was fixed in 0.2.3 and is NOT YET VERIFIED AGAINST A LIVE TENANT. See CLAUDE.md.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
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
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..toolkit.actions import (
    PlanError,
    plan_add_group_members,
    plan_add_group_owners,
    plan_remove_group_members,
    plan_remove_group_owners,
)
from ..toolkit.directory import load_groups
from ..toolkit.groups import GroupContents, GroupPerson, load_group_contents
from ..toolkit.models import GroupSummary
from .pickers import PickerDialog

UNREADABLE = "(could not be read)"
KIND_LABEL = {"user": "User", "group": "Group", "device": "Device", "app": "App", "contact": "Contact",
              "unit": "Administrative unit", "role": "Role", "object": "Object"}
MEMBERS, OWNERS = "Members", "Owners"


def read_only_reason(group: GroupSummary, edge: str = MEMBERS) -> str:
    """Why this group's members (or owners) can't be changed here; '' when they can."""
    if group.on_prem_synced:
        return "Synced from on-premises Active Directory: change it there."
    if group.is_exchange_managed:
        return f"{group.kind_label} groups are managed in Exchange; Graph can't change them."
    if edge == MEMBERS and group.is_dynamic:
        return "Dynamic membership: members come from the rule."
    return ""


def _readonly_label() -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


def _people_table() -> QTableWidget:
    table = QTableWidget(0, 4)
    table.setHorizontalHeaderLabels(["Type", "Name", "UPN / mail", "Account"])
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    table.verticalHeader().hide()
    table.verticalHeader().setDefaultSectionSize(22)
    table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
    table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
    return table


class GroupsPage(QWidget):
    def __init__(self, window: Any, *, loader: Callable[[Any], list[GroupSummary]] = load_groups) -> None:
        super().__init__()
        self.window = window
        self._loader = loader
        self.groups: list[GroupSummary] = []
        self.group: Optional[GroupSummary] = None
        self.contents: Optional[GroupContents] = None
        self.loaded = False
        self.loading = False
        self.loading_contents = False
        self._generation = 0
        self.dialog: Optional[QDialog] = None
        self.pending_group: Optional[str] = None     # a group to open as soon as the list has loaded

        # -- left: groups ----------------------------------------------------------------------- #
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.group_filter = QLineEdit()
        self.group_filter.setPlaceholderText("Filter: name, mail, type, description...")
        self.group_filter.setClearButtonEnabled(True)
        self.show_exchange = QCheckBox("Show Exchange-managed groups")
        self.show_exchange.setToolTip("Mail-enabled security groups and distribution lists: managed in Exchange, "
                                      "read-only here.")
        self.group_list = QListWidget()
        self.group_list.setUniformItemSizes(True)
        self.groups_status = QLabel()
        self.groups_status.setWordWrap(True)
        left_layout.addWidget(self.group_filter)
        left_layout.addWidget(self.show_exchange)
        left_layout.addWidget(self.group_list)
        left_layout.addWidget(self.groups_status)

        # -- middle: members and owners ------------------------------------------------------------- #
        middle = QWidget()
        middle_layout = QVBoxLayout(middle)
        middle_layout.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        self.add_users_button = QPushButton("Add users...")
        self.add_groups_button = QPushButton("Add groups...")
        self.remove_button = QPushButton("Remove")
        for button in (self.add_users_button, self.add_groups_button, self.remove_button):
            bar.addWidget(button)
        bar.addStretch()
        middle_layout.addLayout(bar)
        self.people_filter = QLineEdit()
        self.people_filter.setPlaceholderText("Filter members and owners...")
        self.people_filter.setClearButtonEnabled(True)
        middle_layout.addWidget(self.people_filter)
        self.people_tabs = QTabWidget()
        self.tables = {MEMBERS: _people_table(), OWNERS: _people_table()}
        for name, table in self.tables.items():
            self.people_tabs.addTab(table, name)
        middle_layout.addWidget(self.people_tabs)
        self.people_status = QLabel()
        self.people_status.setWordWrap(True)
        middle_layout.addWidget(self.people_status)

        # -- right: properties and parents ------------------------------------------------------------ #
        self.tabs = QTabWidget()
        props = QWidget()
        form = QFormLayout(props)
        self.props: dict[str, QLabel] = {}
        for name in ("Name", "Type", "Mail", "Description", "Object id", "Membership", "Rule", "Source",
                     "Role-assignable", "Changes"):
            self.props[name] = _readonly_label()
            form.addRow(f"{name}:", self.props[name])
        self.tabs.addTab(props, "Properties")
        self.parents_list = QListWidget()
        self.parents_list.setWordWrap(True)
        self.tabs.addTab(self.parents_list, "Member of")

        splitter = QSplitter()
        splitter.addWidget(left)
        splitter.addWidget(middle)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setStretchFactor(2, 2)
        splitter.setSizes([300, 560, 390])
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)

        self.group_filter.textChanged.connect(self._filter_groups)
        self.show_exchange.toggled.connect(lambda _on: self._filter_groups())
        self.group_list.currentItemChanged.connect(self._group_changed)
        self.people_filter.textChanged.connect(lambda _text: self._filter_people())
        self.people_tabs.currentChanged.connect(lambda _index: self._filter_people())
        for table in self.tables.values():
            table.itemSelectionChanged.connect(self._update_buttons)
            table.cellDoubleClicked.connect(self._open_person)
        self.parents_list.itemDoubleClicked.connect(self._open_parent)
        self.add_users_button.clicked.connect(self.add_users)
        self.add_groups_button.clicked.connect(self.add_groups)
        self.remove_button.clicked.connect(self.remove_selected)
        self._show_group(None)

    # -- the group list ------------------------------------------------------------------------------ #

    def activate_page(self) -> None:
        if not self.loaded:
            self.reload()

    def reload(self) -> None:
        if self.loading:
            return
        self.loading = True
        self.groups_status.setText("Loading groups...")
        graph = self.window.session.graph
        self.window.runner.submit(lambda: self._loader(graph), self._groups_loaded, self._groups_failed, owner=self)

    def _groups_loaded(self, groups: list[GroupSummary]) -> None:
        self.loading, self.loaded = False, True
        selected, self.pending_group = self.pending_group or (self.group.id if self.group else None), None
        self.groups = groups
        self.group_list.blockSignals(True)
        self.group_list.clear()
        for group in groups:
            item = QListWidgetItem(f"{group.label}  [{', '.join(self._badges(group))}]")
            item.setData(Qt.ItemDataRole.UserRole, group)
            item.setData(Qt.ItemDataRole.UserRole + 1,
                         f"{group.label} {group.mail or ''} {group.description or ''} "
                         f"{' '.join(self._badges(group))}".casefold())
            item.setToolTip(group.description or group.label)
            self.group_list.addItem(item)
        self.group_list.blockSignals(False)
        self._filter_groups()
        if not (selected and self.select_group(selected)):
            self._show_group(None)

    @staticmethod
    def _badges(group: GroupSummary) -> list[str]:
        return [group.kind_label] + [b for b, on in (("dynamic", group.is_dynamic), ("synced", group.on_prem_synced),
                                                     ("role-assignable", group.is_role_assignable)) if on]

    def _groups_failed(self, exc: BaseException) -> None:
        self.loading = False
        self.groups_status.setText(f"Couldn't load groups: {exc}")

    def _filter_groups(self, _text: str = "") -> None:
        terms = self.group_filter.text().casefold().split()
        with_exchange = self.show_exchange.isChecked()
        shown = hidden_exchange = 0
        for row in range(self.group_list.count()):
            item = self.group_list.item(row)
            group: GroupSummary = item.data(Qt.ItemDataRole.UserRole)
            matches = all(t in item.data(Qt.ItemDataRole.UserRole + 1) for t in terms)
            exchange_hidden = group.is_exchange_managed and not with_exchange
            hidden_exchange += matches and exchange_hidden
            item.setHidden(not matches or exchange_hidden)
            shown += matches and not exchange_hidden
        if self.loaded:
            total = len(self.groups)
            text = f"{total:,} groups" if shown == total else f"{shown:,} of {total:,} groups"
            if hidden_exchange:
                text += f" ({hidden_exchange:,} Exchange-managed hidden)"
            self.groups_status.setText(text if total else "This tenant has no groups.")

    def group_names(self) -> list[str]:
        return [self.group_list.item(r).data(Qt.ItemDataRole.UserRole).label for r in range(self.group_list.count())
                if not self.group_list.item(r).isHidden()]

    def select_group(self, group_id: str) -> bool:
        for row in range(self.group_list.count()):
            item = self.group_list.item(row)
            group: GroupSummary = item.data(Qt.ItemDataRole.UserRole)
            if group.id == group_id:
                if item.isHidden():                     # e.g. opened from a user's or another group's list
                    if group.is_exchange_managed:
                        self.show_exchange.setChecked(True)
                    self.group_filter.clear()
                self.group_list.setCurrentItem(item)
                self.group_list.scrollToItem(item)
                return True
        return False

    def _group_changed(self, current: Optional[QListWidgetItem], _previous: Any) -> None:
        self._show_group(current.data(Qt.ItemDataRole.UserRole) if current else None)

    # -- one group ------------------------------------------------------------------------------------- #

    def _show_group(self, group: Optional[GroupSummary]) -> None:
        self._generation += 1
        self.group, self.contents = group, None
        for table in self.tables.values():
            table.setRowCount(0)
        self.parents_list.clear()
        for label in self.props.values():
            label.setText("")
        if group is None:
            self.loading_contents = False
            self.people_status.setText("Select a group to see its members and owners.")
            self._update_buttons()
            return
        self.props["Name"].setText(group.label)
        self.props["Type"].setText(group.kind_label)
        self.props["Mail"].setText(group.mail or "-")
        self.props["Description"].setText(group.description or "-")
        self.props["Object id"].setText(group.id)
        self.props["Membership"].setText("dynamic" if group.is_dynamic else "assigned")
        self.props["Rule"].setText(group.membership_rule or "-")
        self.props["Source"].setText("synced from on-premises AD" if group.on_prem_synced else "cloud")
        self.props["Role-assignable"].setText("?" if group.is_role_assignable is None else
                                              "yes (needs Privileged Role Administrator to change)"
                                              if group.is_role_assignable else "no")
        members_note, owners_note = read_only_reason(group, MEMBERS), read_only_reason(group, OWNERS)
        self.props["Changes"].setText("members and owners can be changed here" if not members_note else
                                      members_note + ("" if owners_note else " Owners can still be changed."))
        self.people_status.setText(f"Loading {group.label}...")
        self.loading_contents = True
        generation, graph = self._generation, self.window.session.graph
        self.window.runner.submit(lambda: load_group_contents(graph, group.id),
                                  lambda contents: self._contents_loaded(generation, contents),
                                  lambda exc: self._contents_failed(generation, exc), owner=self)
        self._update_buttons()

    def _contents_loaded(self, generation: int, contents: GroupContents) -> None:
        if generation != self._generation:
            return          # another group was selected meanwhile
        self.loading_contents = False
        self.contents = contents
        self._fill(MEMBERS, contents.members)
        self._fill(OWNERS, contents.owners)
        if contents.parents is None:
            self.parents_list.addItem(UNREADABLE)
        elif not contents.parents:
            self.parents_list.addItem("Not a member of any group, administrative unit or role.")
        for parent in contents.parents or []:
            item = QListWidgetItem(f"{KIND_LABEL.get(parent.kind, parent.kind)}: {parent.label}")
            item.setData(Qt.ItemDataRole.UserRole, parent)
            self.parents_list.addItem(item)
        for index, name in enumerate((MEMBERS, OWNERS)):
            people = contents.members if name == MEMBERS else contents.owners
            count = "?" if people is None else f"{len(people):,}" + ("+" if name == MEMBERS and contents.members_truncated else "")
            self.people_tabs.setTabText(index, f"{name} ({count})")
        self._filter_people()
        self._update_buttons()

    def _contents_failed(self, generation: int, exc: BaseException) -> None:
        if generation != self._generation:
            return
        self.loading_contents = False
        self.people_status.setText(f"Couldn't load this group: {exc}")
        self._update_buttons()

    def _fill(self, name: str, people: Optional[list[GroupPerson]]) -> None:
        table = self.tables[name]
        table.setRowCount(len(people or []))
        for row, person in enumerate(people or []):
            account = "-" if person.enabled is None else "Enabled" if person.enabled else "Disabled"
            for col, value in enumerate((KIND_LABEL.get(person.kind, person.kind), person.label,
                                         person.detail or "-", account)):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, person)
                table.setItem(row, col, item)

    @property
    def edge(self) -> str:
        return MEMBERS if self.people_tabs.currentIndex() == 0 else OWNERS

    def _people(self, name: Optional[str] = None) -> Optional[list[GroupPerson]]:
        if self.contents is None:
            return None
        return self.contents.members if (name or self.edge) == MEMBERS else self.contents.owners

    def _filter_people(self) -> None:
        terms = self.people_filter.text().casefold().split()
        for name, table in self.tables.items():
            shown = 0
            for row in range(table.rowCount()):
                person: GroupPerson = table.item(row, 0).data(Qt.ItemDataRole.UserRole)
                hay = f"{person.kind} {person.name or ''} {person.detail or ''} {person.id}".casefold()
                hidden = not all(t in hay for t in terms)
                table.setRowHidden(row, hidden)
                shown += not hidden
            if name != self.edge or self.contents is None:
                continue
            people, error = ((self.contents.members, self.contents.members_error) if name == MEMBERS
                             else (self.contents.owners, self.contents.owners_error))
            if people is None:
                self.people_status.setText(f"{name} couldn't be read: {error}.")
                continue
            noun = name.lower() if len(people) != 1 else name.lower()[:-1]
            text = (f"{shown:,} of {len(people):,} shown" if shown != len(people) else f"{len(people):,} {noun}")
            if name == MEMBERS and self.contents.members_truncated:
                text += f" - only the first {len(people):,} are listed; this group has more."
            note = read_only_reason(self.group, name) if self.group else ""
            self.people_status.setText(text + (f"\n{note}" if note else ""))
        self._update_buttons()

    def people_names(self, name: Optional[str] = None) -> list[str]:
        table = self.tables[name or self.edge]
        return [table.item(r, 1).text() for r in range(table.rowCount()) if not table.isRowHidden(r)]

    def parent_texts(self) -> list[str]:
        return [self.parents_list.item(r).text() for r in range(self.parents_list.count())]

    # -- buttons ---------------------------------------------------------------------------------------- #

    def selected_people(self) -> list[GroupPerson]:
        table = self.tables[self.edge]
        rows = sorted({i.row() for i in table.selectedItems()})
        return [table.item(r, 0).data(Qt.ItemDataRole.UserRole) for r in rows if not table.isRowHidden(r)]

    def _update_buttons(self) -> None:
        group, edge = self.group, self.edge
        idle = self.window.change is None and not self.loading_contents
        reason = read_only_reason(group, edge) if group else ""
        can = bool(group and idle and not reason and self._people() is not None)
        self.add_users_button.setEnabled(can)
        self.add_users_button.setText("Add users..." if edge == MEMBERS else "Add owners...")
        nestable = bool(can and edge == MEMBERS and group and "Unified" not in group.group_types)
        self.add_groups_button.setEnabled(nestable)
        self.add_groups_button.setVisible(edge == MEMBERS)
        self.remove_button.setEnabled(can and bool(self.selected_people()))
        nest_tip = ("A Microsoft 365 group can only have users as members."
                    if group and "Unified" in group.group_types and not reason else reason)
        self.add_users_button.setToolTip(reason)
        self.add_groups_button.setToolTip(nest_tip)
        self.remove_button.setToolTip(reason)

    def _explain(self, title: str, text: str) -> None:
        QMessageBox.information(self, title, text)

    def _start(self, plan_fn: Callable[[], Any]) -> None:
        try:
            plan = plan_fn()
        except PlanError as exc:
            self._explain("Nothing to do", str(exc))
            return
        group_id = self.group.id if self.group else None

        def finished(done: Any) -> None:
            if done.result.status in ("ok", "partial") and group_id and self.group and self.group.id == group_id:
                self._show_group(self.group)        # re-read what is really there now
            self._update_buttons()

        self.window.start_change(plan, on_finished=finished)
        self._update_buttons()

    def _pick(self, title: str, items: list[tuple[str, Any]], on_chosen: Callable[[list[Any]], None]) -> None:
        dialog = PickerDialog(title, items, self)
        self.dialog = dialog

        def answered(code: int) -> None:
            self.dialog = None
            if code == QDialog.DialogCode.Accepted and dialog.chosen:
                on_chosen(dialog.chosen)

        dialog.finished.connect(answered)
        dialog.open()

    def add_users(self) -> None:
        people = self._people()
        if not self.group or people is None:
            return
        present = {p.id for p in people}
        users = [u for u in self.window.model.users if u.id not in present]
        if not users:
            self._explain("No users to add", "Every loaded user is already there (or the user list hasn't loaded "
                                             "yet: see the Users page).")
            return
        group, base, owners = self.group, self.window.session.graph.base_url, self.edge == OWNERS
        plan = plan_add_group_owners if owners else plan_add_group_members
        self._pick(f"Add {'owners' if owners else 'members'} to {group.label}", [(u.full_label, u) for u in users],
                   lambda chosen: self._start(lambda: plan(group, chosen, base)))

    def add_groups(self) -> None:
        people = self._people(MEMBERS)
        if not self.group or people is None:
            return
        present = {p.id for p in people} | {self.group.id}
        # only security groups can be nested (not Microsoft 365 groups, not Exchange-managed ones)
        groups = [g for g in self.groups if g.id not in present and g.security_enabled
                  and "Unified" not in g.group_types and not g.is_exchange_managed]
        if not groups:
            self._explain("No groups to add", "There is no other security group that could be nested here.")
            return
        group, base = self.group, self.window.session.graph.base_url
        self._pick(f"Nest groups in {group.label}", [(f"{g.label} ({g.kind_label})", g) for g in groups],
                   lambda chosen: self._start(lambda: plan_add_group_members(group, chosen, base)))

    def remove_selected(self) -> None:
        chosen = self.selected_people()
        if self.group and chosen:
            group = self.group
            plan = plan_remove_group_owners if self.edge == OWNERS else plan_remove_group_members
            self._start(lambda: plan(group, chosen))

    def _open(self, person: Optional[GroupPerson]) -> None:
        if person is None:
            return
        if person.kind == "user":
            self.window.show_user(person.id)
        elif person.kind == "group":
            self.select_group(person.id)

    def _open_person(self, row: int, _col: int) -> None:
        self._open(self.tables[self.edge].item(row, 0).data(Qt.ItemDataRole.UserRole))

    def _open_parent(self, item: QListWidgetItem) -> None:
        self._open(item.data(Qt.ItemDataRole.UserRole))
