"""The user list: a table model over the directory loaded once, and the filtered, sorted view of it that
the table shows. Built to stay responsive at several hundred thousand users."""

from __future__ import annotations

from typing import Any, Optional, Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt
from PySide6.QtGui import QColor

from ..toolkit.models import UserSummary

Index = QModelIndex | QPersistentModelIndex
USER_ROLE = Qt.ItemDataRole.UserRole

COLUMNS = ("Name", "User principal name", "Type", "Account", "Job title", "Department")


def _account(u: UserSummary) -> str:
    if u.account_enabled is None:
        return "?"
    return "Enabled" if u.account_enabled else "Disabled"


def _cells(u: UserSummary) -> tuple[str, ...]:
    return (u.display_name or "", u.upn or "", u.user_type or "", _account(u), u.job_title or "", u.department or "")


def _haystack(u: UserSummary) -> str:
    """Everything the filter box matches against, lower-cased once per user."""
    parts = (u.display_name, u.upn, u.mail, u.job_title, u.department, u.employee_id, u.id, u.user_type,
             "disabled" if u.account_enabled is False else "", "synced" if u.on_prem_synced else "")
    return " ".join(p for p in parts if p).casefold()


class UserTableModel(QAbstractTableModel):
    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._users: list[UserSummary] = []
        self._cells: list[tuple[str, ...]] = []
        self._haystacks: list[str] = []
        self._row_of: dict[str, int] = {}

    # -- data ---------------------------------------------------------------- #

    def set_users(self, users: Sequence[UserSummary]) -> None:
        self.beginResetModel()
        self._users = list(users)
        self._cells = [_cells(u) for u in self._users]
        self._haystacks = [_haystack(u) for u in self._users]
        self._row_of = {u.id: i for i, u in enumerate(self._users)}
        self.endResetModel()

    def update_user(self, user: UserSummary) -> None:
        """Replace one user in place (after a change) without reloading the directory."""
        row = self._row_of.get(user.id)
        if row is None:
            return
        self._users[row] = user
        self._cells[row] = _cells(user)
        self._haystacks[row] = _haystack(user)
        self.dataChanged.emit(self.index(row, 0), self.index(row, len(COLUMNS) - 1))

    def user_at(self, row: int) -> Optional[UserSummary]:
        return self._users[row] if 0 <= row < len(self._users) else None

    def haystack(self, row: int) -> str:
        return self._haystacks[row]

    @property
    def users(self) -> list[UserSummary]:
        return list(self._users)

    # -- Qt model interface -------------------------------------------------- #

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008, N802 - Qt's signature
        return 0 if parent.isValid() else len(self._users)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008, N802
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole and 0 <= section < len(COLUMNS):
            return COLUMNS[section]
        return None

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row, col = index.row(), index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self._cells[row][col]
        if role == USER_ROLE:
            return self._users[row]
        user = self._users[row]
        if role == Qt.ItemDataRole.ForegroundRole and user.account_enabled is False:
            return QColor("#c62828") if col == 3 else QColor("#888888")
        if role == Qt.ItemDataRole.ToolTipRole and col == 0:
            notes = [n for n in ("synced from on-premises AD" if user.on_prem_synced else "",
                                 "guest" if user.is_guest else "") if n]
            return user.full_label + (f" ({', '.join(notes)})" if notes else "")
        return None


class UserFilterProxy(QAbstractTableModel):
    """The filtered, sorted view of a ``UserTableModel`` that the table shows.

    Every word typed must appear somewhere in the user's name, UPN, mail, title, department, employee id or
    object id ("disabled" and "synced" match those states too).

    Not a QSortFilterProxyModel on purpose: that calls back into Python once per row and comparison, which
    at 300,000 users took 26 s to sort and 5 s to clear the filter. Here filtering is one pass over the
    pre-built search strings and sorting is one ``sorted`` per column, cached until the data changes; a
    filter change never sorts (it walks the cached order). The selection survives both.
    """

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._source: Optional[UserTableModel] = None
        self._terms: tuple[str, ...] = ()
        self._rows: list[int] = []                 # source rows shown, in display order
        self._sort_column: Optional[int] = None
        self._descending = False
        self._orders: dict[int, list[int]] = {}    # column -> every source row in ascending order

    # -- wiring ---------------------------------------------------------------- #

    def setSourceModel(self, model: UserTableModel) -> None:  # noqa: N802 - mirrors Qt's proxy API
        self._source = model
        model.modelReset.connect(self._source_reset)
        model.dataChanged.connect(lambda *_args: self._source_changed())
        self._source_reset()

    def sourceModel(self) -> Optional[UserTableModel]:  # noqa: N802
        return self._source

    def _source_reset(self) -> None:
        self.beginResetModel()
        self._orders.clear()
        self._rows = self._compute()
        self.endResetModel()

    def _source_changed(self) -> None:
        self._orders.clear()        # a changed cell may sort or match differently
        self._relayout()

    # -- filtering and sorting --------------------------------------------------- #

    def set_filter_text(self, text: str) -> None:
        terms = tuple(text.casefold().split())
        if terms != self._terms:
            self._terms = terms
            self._relayout()

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        self._sort_column = column if 0 <= column < len(COLUMNS) else None
        self._descending = order == Qt.SortOrder.DescendingOrder
        self._relayout()

    def _order(self) -> Sequence[int]:
        source = self._source
        assert source is not None
        count = source.rowCount()
        if self._sort_column is None:
            return range(count)
        if self._sort_column not in self._orders:
            keys = [cells[self._sort_column].casefold() for cells in source._cells]
            self._orders[self._sort_column] = sorted(range(count), key=keys.__getitem__)
        order = self._orders[self._sort_column]
        return order[::-1] if self._descending else order

    def _compute(self) -> list[int]:
        if self._source is None:
            return []
        order, haystacks, terms = self._order(), self._source._haystacks, self._terms
        if not terms:
            return list(order)
        if len(terms) == 1:
            term = terms[0]
            return [row for row in order if term in haystacks[row]]
        return [row for row in order if all(term in haystacks[row] for term in terms)]

    def _relayout(self) -> None:
        """Recompute what is shown, keeping persistent indexes (the selection) on their users."""
        self.layoutAboutToBeChanged.emit()
        old_indexes = self.persistentIndexList()
        old_sources = [self._rows[i.row()] if 0 <= i.row() < len(self._rows) else -1 for i in old_indexes]
        self._rows = self._compute()
        if old_indexes:
            position = {row: pos for pos, row in enumerate(self._rows)} if len(old_indexes) > 8 else None
            new_indexes = []
            for index, source_row in zip(old_indexes, old_sources):
                if position is not None:
                    pos = position.get(source_row, -1)
                else:
                    try:
                        pos = self._rows.index(source_row)
                    except ValueError:
                        pos = -1
                new_indexes.append(self.index(pos, index.column()) if pos >= 0 else QModelIndex())
            self.changePersistentIndexList(old_indexes, new_indexes)
        self.layoutChanged.emit()

    # -- Qt model interface -------------------------------------------------------- #

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008, N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008, N802
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        return self._source.headerData(section, orientation, role) if self._source is not None else None

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or self._source is None or not 0 <= index.row() < len(self._rows):
            return None
        return self._source.data(self._source.index(self._rows[index.row()], index.column()), role)
