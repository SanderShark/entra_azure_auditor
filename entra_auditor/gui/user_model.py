"""The user list: a table model over the directory loaded once, and a proxy that filters as you type."""

from __future__ import annotations

from typing import Any, Optional, Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, QSortFilterProxyModel, Qt
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


class UserFilterProxy(QSortFilterProxyModel):
    """Every word typed must appear somewhere in the user's name, UPN, mail, title, department,
    employee id or object id ("disabled" and "synced" match those states too)."""

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._terms: tuple[str, ...] = ()
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setSortLocaleAware(True)

    def set_filter_text(self, text: str) -> None:
        terms = tuple(text.casefold().split())
        if terms == self._terms:
            return
        if hasattr(self, "beginFilterChange") and hasattr(self, "endFilterChange"):   # Qt >= 6.10
            self.beginFilterChange()
            self._terms = terms
            self.endFilterChange()
        else:                                                                       # older Qt
            self._terms = terms
            self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: Index) -> bool:  # noqa: N802
        if not self._terms:
            return True
        model = self.sourceModel()
        haystack = model.haystack(source_row) if isinstance(model, UserTableModel) else ""
        return all(term in haystack for term in self._terms)
