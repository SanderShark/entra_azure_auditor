"""Administrative units page, laid out like OUs in Active Directory Users and Computers:
a tree of units on the left, the selected unit's members in the middle, its settings and scoped roles on
the right.

AUs don't nest, so the tree has two levels: each unit, and under it Users, Groups and Devices (with counts
once the unit has been opened). Selecting the unit shows everything in it; selecting one of the three shows
only that kind. Double-click a user to open it on the Users page, a group to open it on the Groups page. Adding/removing members and editing settings go through the change
flow (preview, confirm, PIM elevation to Privileged Role Administrator, result).

NOT VERIFIED AGAINST A LIVE TENANT. See CLAUDE.md.
"""

from __future__ import annotations

from typing import Any, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..toolkit.actions import PlanError, plan_add_au_members, plan_remove_au_members, plan_update_admin_unit
from ..toolkit.admin_units import (
    AdminUnit,
    AuMember,
    AuRoles,
    list_admin_units,
    list_members,
    member_from_device,
    member_from_group,
    member_from_user,
    scoped_roles,
)
from ..toolkit.directory import load_devices, load_groups
from ..toolkit.models import DeviceSummary, GroupSummary
from .pickers import PickerDialog

UNREADABLE = "(could not be read)"
KIND_LABEL = {"user": "User", "group": "Group", "device": "Device", "object": "Object"}
TREE_KINDS = (("user", "Users"), ("group", "Groups"), ("device", "Devices"))     # the nodes under each unit
UNIT_ROLE = Qt.ItemDataRole.UserRole
KIND_ROLE = Qt.ItemDataRole.UserRole + 1        # None on a unit's own node, else "user" | "group" | "device"


def load_unit_contents(graph: Any, unit_id: str) -> tuple[Optional[list[AuMember]], Optional[str], AuRoles]:
    """Members (or None + the reason) and scoped roles, read on a worker."""
    try:
        members, error = list_members(graph, unit_id), None
    except Exception as exc:  # noqa: BLE001 - shown on the page; hidden-membership units need Member.Read.Hidden
        members, error = None, str(exc)
    return members, error, scoped_roles(graph, unit_id)


class EditUnitDialog(QDialog):
    """Settings that can change after creation (restricted management and visibility can't)."""

    def __init__(self, unit: AdminUnit, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.unit = unit
        self.setWindowTitle(f"Settings: {unit.label}")
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.name = QLineEdit(unit.display_name or "")
        self.description = QLineEdit(unit.description or "")
        self.membership = QComboBox()
        self.membership.addItem("Assigned (managed by hand)", "assigned")
        self.membership.addItem("Dynamic (from a rule; needs Entra ID P1)", "dynamic")
        self.membership.setCurrentIndex(1 if unit.is_dynamic else 0)
        self.rule = QPlainTextEdit(unit.membership_rule or "")
        self.rule.setPlaceholderText('e.g. user.department -eq "Sales"')
        self.rule.setMaximumHeight(80)
        self.processing = QComboBox()
        self.processing.addItems(["On", "Paused"])
        self.processing.setCurrentText(unit.processing_state or "On")
        form.addRow("Name", self.name)
        form.addRow("Description", self.description)
        form.addRow("Membership", self.membership)
        form.addRow("Rule", self.rule)
        form.addRow("Rule processing", self.processing)
        fixed = QLabel(f"Restricted management: {'yes' if unit.restricted else 'no'} (fixed at creation)\n"
                       f"Visibility: {'hidden membership' if unit.hidden else 'public'}")
        fixed.setStyleSheet("color: #666;")
        form.addRow("", fixed)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Preview change...")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.membership.currentIndexChanged.connect(self._sync)
        self._sync()

    def _sync(self) -> None:
        dynamic = self.membership.currentData() == "dynamic"
        self.rule.setEnabled(dynamic)
        self.processing.setEnabled(dynamic)

    def changes(self) -> dict[str, Any]:
        """Everything in the form; the plan keeps only what differs."""
        dynamic = self.membership.currentData() == "dynamic"
        changes: dict[str, Any] = {"displayName": self.name.text(), "description": self.description.text(),
                                   "membershipType": self.membership.currentData()}
        if dynamic:
            changes["membershipRule"] = self.rule.toPlainText()
            changes["membershipRuleProcessingState"] = self.processing.currentText()
        return changes


def _readonly_label() -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class AdminUnitsPage(QWidget):
    def __init__(self, window: Any) -> None:
        super().__init__()
        self.window = window
        self.units: list[AdminUnit] = []
        self.unit: Optional[AdminUnit] = None
        self.members: Optional[list[AuMember]] = None
        self.roles: Optional[AuRoles] = None
        self.loaded = False
        self.loading = False
        self.loading_contents = False
        self._generation = 0
        self.dialog: Optional[QDialog] = None
        self._groups: Optional[list[GroupSummary]] = None
        self._devices: Optional[list[DeviceSummary]] = None

        # -- left: units ------------------------------------------------------------------------ #
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.unit_filter = QLineEdit()
        self.unit_filter.setPlaceholderText("Filter units...")
        self.unit_filter.setClearButtonEnabled(True)
        self.unit_tree = QTreeWidget()
        self.unit_tree.setHeaderHidden(True)
        self.kind_filter: Optional[str] = None      # set while one of a unit's Users/Groups/Devices nodes is selected
        self.units_status = QLabel()
        self.units_status.setWordWrap(True)
        left_layout.addWidget(self.unit_filter)
        left_layout.addWidget(self.unit_tree)
        left_layout.addWidget(self.units_status)

        # -- middle: members ------------------------------------------------------------------------ #
        middle = QWidget()
        middle_layout = QVBoxLayout(middle)
        middle_layout.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        self.add_users_button = QPushButton("Add users...")
        self.add_groups_button = QPushButton("Add groups...")
        self.add_devices_button = QPushButton("Add devices...")
        self.remove_button = QPushButton("Remove")
        self.edit_button = QPushButton("Settings...")
        for button in (self.add_users_button, self.add_groups_button, self.add_devices_button, self.remove_button,
                       self.edit_button):
            bar.addWidget(button)
        bar.addStretch()
        middle_layout.addLayout(bar)
        self.member_filter = QLineEdit()
        self.member_filter.setPlaceholderText("Filter members...")
        self.member_filter.setClearButtonEnabled(True)
        middle_layout.addWidget(self.member_filter)
        self.member_table = QTableWidget(0, 4)
        self.member_table.setHorizontalHeaderLabels(["Type", "Name", "UPN / mail / OS", "Account"])
        self.member_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.member_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.member_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.member_table.verticalHeader().hide()
        self.member_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.member_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        middle_layout.addWidget(self.member_table)
        self.member_status = QLabel()
        self.member_status.setWordWrap(True)
        middle_layout.addWidget(self.member_status)

        # -- right: properties and roles ----------------------------------------------------------------- #
        self.tabs = QTabWidget()
        props = QWidget()
        props_form = QFormLayout(props)
        self.props: dict[str, QLabel] = {}
        for name in ("Name", "Description", "Object id", "Membership", "Rule", "Rule processing",
                     "Restricted management", "Visibility"):
            self.props[name] = _readonly_label()
            props_form.addRow(f"{name}:", self.props[name])
        self.tabs.addTab(props, "Properties")
        roles = QWidget()
        roles_layout = QVBoxLayout(roles)
        roles_layout.addWidget(QLabel("Roles scoped to this unit: these admins manage its members."))
        self.roles_table = QTableWidget(0, 3)
        self.roles_table.setHorizontalHeaderLabels(["Role", "Assigned to", "State"])
        self.roles_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.roles_table.verticalHeader().hide()
        self.roles_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        roles_layout.addWidget(self.roles_table)
        self.roles_status = QLabel()
        self.roles_status.setWordWrap(True)
        self.roles_status.setStyleSheet("color: #b26a00;")
        roles_layout.addWidget(self.roles_status)
        self.tabs.addTab(roles, "Roles")

        splitter = QSplitter()
        splitter.addWidget(left)
        splitter.addWidget(middle)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        splitter.setStretchFactor(2, 2)
        splitter.setSizes([230, 620, 400])
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)

        self.unit_filter.textChanged.connect(self._filter_units)
        self.member_filter.textChanged.connect(self._filter_members)
        self.unit_tree.currentItemChanged.connect(self._unit_changed)
        self.member_table.itemSelectionChanged.connect(self._update_buttons)
        self.member_table.cellDoubleClicked.connect(self._open_member)
        self.add_users_button.clicked.connect(self.add_users)
        self.add_groups_button.clicked.connect(self.add_groups)
        self.add_devices_button.clicked.connect(self.add_devices)
        self.remove_button.clicked.connect(self.remove_selected)
        self.edit_button.clicked.connect(self.edit_settings)
        self._show_unit(None)

    # -- units ------------------------------------------------------------------------------------- #

    def activate_page(self) -> None:
        if not self.loaded:
            self.reload()

    def reload(self) -> None:
        if self.loading:
            return
        self.loading = True
        self.units_status.setText("Loading administrative units...")
        graph = self.window.session.graph
        self.window.runner.submit(lambda: list_admin_units(graph), self._units_loaded, self._units_failed, owner=self)

    def _units_loaded(self, result: tuple[list[AdminUnit], list[str]]) -> None:
        units, warnings = result
        self.loading, self.loaded = False, True
        selected, kind = (self.unit.id if self.unit else None), self.kind_filter
        self.units = units
        self.unit_tree.blockSignals(True)
        self.unit_tree.clear()
        folder = self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        for unit in units:
            item = QTreeWidgetItem([unit.label + (f"  [{', '.join(unit.badges)}]" if unit.badges else "")])
            item.setIcon(0, folder)
            item.setData(0, UNIT_ROLE, unit)
            item.setData(0, KIND_ROLE, None)
            item.setToolTip(0, unit.description or unit.label)
            for member_kind, label in TREE_KINDS:
                child = QTreeWidgetItem([label])
                child.setData(0, UNIT_ROLE, unit)
                child.setData(0, KIND_ROLE, member_kind)
                item.addChild(child)
            self.unit_tree.addTopLevelItem(item)
        self.unit_tree.blockSignals(False)
        self._filter_units(self.unit_filter.text())
        self.units_status.setText(f"{len(units):,} units" + ("".join(f"\n! {w}" for w in warnings)))
        if not units:
            self.units_status.setText("This tenant has no administrative units.")
        self.unit, self.kind_filter = None, None       # the tree was rebuilt: nothing is shown until selected again
        if selected and self.select_unit(selected, kind):
            return
        self._show_unit(None)

    def _units_failed(self, exc: BaseException) -> None:
        self.loading = False
        self.units_status.setText(f"Couldn't load administrative units: {exc}")

    def _unit_items(self) -> list[QTreeWidgetItem]:
        return [self.unit_tree.topLevelItem(row) for row in range(self.unit_tree.topLevelItemCount())]

    def _filter_units(self, text: str) -> None:
        terms = text.casefold().split()
        for item in self._unit_items():
            unit: AdminUnit = item.data(0, UNIT_ROLE)
            hay = f"{unit.label} {unit.description or ''} {' '.join(unit.badges)}".casefold()
            item.setHidden(not all(t in hay for t in terms))

    def unit_texts(self) -> list[str]:
        return [item.text(0) for item in self._unit_items() if not item.isHidden()]

    def node_texts(self, unit_id: str) -> list[str]:
        """The Users / Groups / Devices nodes under a unit, as shown."""
        item = next(i for i in self._unit_items() if i.data(0, UNIT_ROLE).id == unit_id)
        return [item.child(row).text(0) for row in range(item.childCount())]

    def select_unit(self, unit_id: str, kind: Optional[str] = None) -> bool:
        """Select a unit, or (with ``kind``) its Users, Groups or Devices node."""
        for item in self._unit_items():
            if item.data(0, UNIT_ROLE).id == unit_id:
                target = item
                if kind is not None:
                    item.setExpanded(True)
                    target = next((item.child(row) for row in range(item.childCount())
                                   if item.child(row).data(0, KIND_ROLE) == kind), item)
                self.unit_tree.setCurrentItem(target)
                return True
        return False

    def _unit_changed(self, current: Optional[QTreeWidgetItem], _previous: Any) -> None:
        unit = current.data(0, UNIT_ROLE) if current else None
        self.kind_filter = current.data(0, KIND_ROLE) if current else None
        if unit is not None and self.unit is not None and unit.id == self.unit.id:
            self._filter_members(self.member_filter.text())     # same unit, another node: nothing to reload
            self._update_buttons()
            return
        self._show_unit(unit)

    def _update_nodes(self) -> None:
        """Put the counts on the open unit's Users / Groups / Devices nodes."""
        if self.unit is None:
            return
        for item in self._unit_items():
            if item.data(0, UNIT_ROLE).id != self.unit.id:
                continue
            for row, (kind, label) in enumerate(TREE_KINDS):
                count = "?" if self.members is None else sum(1 for m in self.members if m.kind == kind)
                item.child(row).setText(0, f"{label} ({count})")

    def _show_unit(self, unit: Optional[AdminUnit]) -> None:
        self._generation += 1
        self.unit, self.members, self.roles = unit, None, None
        self.member_table.setRowCount(0)
        self.roles_table.setRowCount(0)
        self.roles_status.setText("")
        for label in self.props.values():
            label.setText("")
        if unit is None:
            self.member_status.setText("Select an administrative unit to see what's in it.")
            self._update_buttons()
            return
        self.props["Name"].setText(unit.label)
        self.props["Description"].setText(unit.description or "-")
        self.props["Object id"].setText(unit.id)
        known = unit.settings_known
        self.props["Membership"].setText(("dynamic" if unit.is_dynamic else "assigned") if known else UNREADABLE)
        self.props["Rule"].setText((unit.membership_rule or "-") if known else UNREADABLE)
        self.props["Rule processing"].setText((unit.processing_state or "-") if known else UNREADABLE)
        self.props["Restricted management"].setText(("yes" if unit.restricted else "no") if known else UNREADABLE)
        self.props["Visibility"].setText(("hidden membership" if unit.hidden else "public") if known else UNREADABLE)
        self.member_status.setText(f"Loading {unit.label}...")
        self.loading_contents = True
        generation, graph = self._generation, self.window.session.graph
        self.window.runner.submit(lambda: load_unit_contents(graph, unit.id),
                                  lambda result: self._contents_loaded(generation, result),
                                  lambda exc: self._contents_failed(generation, exc), owner=self)
        self._update_buttons()

    def _contents_loaded(self, generation: int, result: tuple) -> None:
        if generation != self._generation:
            return      # another unit was selected meanwhile
        members, error, roles = result
        self.loading_contents = False
        self.members, self.roles = members, roles
        if members is None:
            hint = " Hidden-membership units also need the Member.Read.Hidden permission." if (
                self.unit and self.unit.hidden) else ""
            self.member_status.setText(f"Members couldn't be read: {error}.{hint}")
        else:
            self._fill_members()
        self._update_nodes()
        self._fill_roles()
        self._update_buttons()

    def _contents_failed(self, generation: int, exc: BaseException) -> None:
        if generation != self._generation:
            return
        self.loading_contents = False
        self.member_status.setText(f"Couldn't load this unit: {exc}")
        self._update_buttons()

    def _fill_members(self) -> None:
        members = self.members or []
        self.member_table.setRowCount(len(members))
        for row, member in enumerate(members):
            account = "-" if member.enabled is None else "Enabled" if member.enabled else "Disabled"
            for col, value in enumerate((KIND_LABEL.get(member.kind, member.kind), member.name or member.id,
                                         member.detail or "-", account)):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, member)
                self.member_table.setItem(row, col, item)
        self._filter_members(self.member_filter.text())

    def _filter_members(self, text: str) -> None:
        terms = text.casefold().split()
        shown = 0
        for row in range(self.member_table.rowCount()):
            member: AuMember = self.member_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            hay = f"{member.kind} {member.name or ''} {member.detail or ''} {member.id}".casefold()
            hidden = not all(t in hay for t in terms) or (self.kind_filter is not None and member.kind != self.kind_filter)
            self.member_table.setRowHidden(row, hidden)
            shown += not hidden
        if self.members is not None:
            total = len(self.members)
            counts = {k: sum(1 for m in self.members if m.kind == k) for k in ("user", "group", "device")}
            summary = ", ".join(f"{n} {k}{'s' if n != 1 else ''}" for k, n in counts.items() if n) or "no members"
            only = f"{dict(TREE_KINDS)[self.kind_filter]} only: " if self.kind_filter else ""
            self.member_status.setText(only + (f"{shown} of {total} shown - " if shown != total else "") + summary)

    def _fill_roles(self) -> None:
        roles = self.roles
        rows: list[tuple[str, str, str]] = []
        if roles is not None:
            for group, state in ((roles.active, "active"), (roles.eligible, "eligible (PIM)")):
                if group is None:
                    rows.append((UNREADABLE, "", state))
                else:
                    rows += [(r.role, r.principal_label, state) for r in group]
            self.roles_status.setText("\n".join(roles.warnings))
        if not rows:
            rows = [("No roles are scoped to this unit.", "", "")]
        self.roles_table.setRowCount(len(rows))
        for r, values in enumerate(rows):
            for c, value in enumerate(values):
                self.roles_table.setItem(r, c, QTableWidgetItem(value))

    def roles_texts(self) -> list[tuple[str, ...]]:
        return [tuple(self.roles_table.item(r, c).text() for c in range(3)) for r in range(self.roles_table.rowCount())]

    def member_names(self) -> list[str]:
        return [self.member_table.item(r, 1).text() for r in range(self.member_table.rowCount())
                if not self.member_table.isRowHidden(r)]

    # -- buttons -------------------------------------------------------------------------------------- #

    def selected_members(self) -> list[AuMember]:
        rows = sorted({i.row() for i in self.member_table.selectedItems()})
        return [self.member_table.item(r, 0).data(Qt.ItemDataRole.UserRole) for r in rows
                if not self.member_table.isRowHidden(r)]

    def _update_buttons(self) -> None:
        unit, idle = self.unit, self.window.change is None and not self.loading_contents
        manual = bool(unit and not unit.is_dynamic and self.members is not None and idle)
        for button in (self.add_users_button, self.add_groups_button, self.add_devices_button):
            button.setEnabled(manual)
            button.setToolTip("Dynamic units take their members from the rule." if unit and unit.is_dynamic else "")
        self.remove_button.setEnabled(manual and bool(self.selected_members()))
        self.edit_button.setEnabled(bool(unit and idle))

    def _explain(self, title: str, text: str) -> None:
        QMessageBox.information(self, title, text)

    def _start(self, plan_fn: Any, reload_units: bool = False) -> None:
        try:
            plan = plan_fn()
        except PlanError as exc:
            self._explain("Nothing to do", str(exc))
            return
        unit_id = self.unit.id if self.unit else None

        def finished(done: Any) -> None:
            if done.result.status in ("ok", "partial"):
                if reload_units:
                    self.reload()
                elif unit_id and self.unit and self.unit.id == unit_id:
                    self._show_unit(self.unit)
            self._update_buttons()

        self.window.start_change(plan, on_finished=finished)
        self._update_buttons()

    def _pick(self, title: str, items: list[tuple[str, Any]], on_chosen: Any) -> None:
        dialog = PickerDialog(title, items, self)
        self.dialog = dialog

        def answered(code: int) -> None:
            self.dialog = None
            if code == QDialog.DialogCode.Accepted and dialog.chosen:
                on_chosen(dialog.chosen)

        dialog.finished.connect(answered)
        dialog.open()

    def add_users(self) -> None:
        if not self.unit or self.members is None:
            return
        present = {m.id for m in self.members}
        users = [u for u in self.window.model.users if u.id not in present]
        if not users:
            self._explain("No users to add", "Every loaded user is already in this unit (or the user list hasn't "
                                             "loaded yet: see the Users page).")
            return
        unit, base = self.unit, self.window.session.graph.base_url
        self._pick(f"Add users to {unit.label}", [(u.full_label, u) for u in users],
                   lambda chosen: self._start(lambda: plan_add_au_members(unit, [member_from_user(u) for u in chosen],
                                                                          base)))

    def add_groups(self) -> None:
        if not self.unit or self.members is None:
            return
        if self._groups is None:
            self.add_groups_button.setEnabled(False)
            self.member_status.setText("Loading groups...")
            graph = self.window.session.graph

            def loaded(groups: list[GroupSummary]) -> None:
                self._groups = groups
                self._filter_members(self.member_filter.text())
                self._update_buttons()
                self.add_groups()

            self.window.runner.submit(lambda: load_groups(graph), loaded,
                                      lambda exc: (self.member_status.setText(f"Couldn't load groups: {exc}"),
                                                   self._update_buttons()), owner=self)
            return
        present = {m.id for m in self.members}
        unit, base = self.unit, self.window.session.graph.base_url
        groups = [g for g in self._groups if g.id not in present]
        self._pick(f"Add groups to {unit.label}", [(f"{g.label} ({g.kind_label})", g) for g in groups],
                   lambda chosen: self._start(lambda: plan_add_au_members(
                       unit, [member_from_group(g) for g in chosen], base)))

    def add_devices(self) -> None:
        if not self.unit or self.members is None:
            return
        if self._devices is None:
            self.add_devices_button.setEnabled(False)
            self.member_status.setText("Loading devices...")
            graph = self.window.session.graph

            def loaded(devices: list[DeviceSummary]) -> None:
                self._devices = devices
                self._filter_members(self.member_filter.text())
                self._update_buttons()
                self.add_devices()

            self.window.runner.submit(lambda: load_devices(graph), loaded,
                                      lambda exc: (self.member_status.setText(f"Couldn't load devices: {exc}"),
                                                   self._update_buttons()), owner=self)
            return
        present = {m.id for m in self.members}
        unit, base = self.unit, self.window.session.graph.base_url
        devices = [d for d in self._devices if d.id not in present]
        items = [(f"{d.label}  -  {d.os_label}, {d.join_type}" + ("" if d.account_enabled is not False else ", disabled"),
                  d) for d in devices]
        self._pick(f"Add devices to {unit.label}", items,
                   lambda chosen: self._start(lambda: plan_add_au_members(
                       unit, [member_from_device(d) for d in chosen], base)))

    def remove_selected(self) -> None:
        chosen = self.selected_members()
        if self.unit and chosen:
            unit = self.unit
            self._start(lambda: plan_remove_au_members(unit, chosen))

    def edit_settings(self) -> None:
        if not self.unit:
            return
        dialog = EditUnitDialog(self.unit, self)
        self.dialog = dialog
        unit = self.unit

        def answered(code: int) -> None:
            self.dialog = None
            if code == QDialog.DialogCode.Accepted:
                changes = dialog.changes()
                self._start(lambda: plan_update_admin_unit(unit, changes), reload_units=True)

        dialog.finished.connect(answered)
        dialog.open()

    def _open_member(self, row: int, _col: int) -> None:
        member: AuMember = self.member_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if member.kind == "user":
            self.window.show_user(member.id)
        elif member.kind == "group":
            self.window.show_group(member.id)
