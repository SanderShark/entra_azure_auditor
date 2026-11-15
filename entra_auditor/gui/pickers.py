"""Pick one or more objects (users, groups) from a list loaded once, filtering as you type."""

from __future__ import annotations

from typing import Any, Optional, Sequence

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)


class PickerDialog(QDialog):
    """``items`` are (text shown, object). Every word typed must appear in the text."""

    def __init__(self, title: str, items: Sequence[tuple[str, Any]], parent: Optional[QWidget] = None, *,
                 prompt: str = "Select one or more (Ctrl/Shift-click):") -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(520, 560)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(prompt))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter...")
        self.filter_edit.setClearButtonEnabled(True)
        layout.addWidget(self.filter_edit)
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        for text, obj in items:
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, obj)
            item.setData(Qt.ItemDataRole.UserRole + 1, text.casefold())
            self.list.addItem(item)
        layout.addWidget(self.list)
        self.count = QLabel()
        layout.addWidget(self.count)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("Add selected")
        self.ok_button.setEnabled(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.filter_edit.textChanged.connect(self.apply_filter)
        self.list.itemSelectionChanged.connect(self._selection_changed)
        self.list.itemDoubleClicked.connect(lambda _item: self.accept())
        self.apply_filter("")

    def apply_filter(self, text: str) -> None:
        terms = text.casefold().split()
        shown = 0
        for row in range(self.list.count()):
            item = self.list.item(row)
            hidden = not all(t in item.data(Qt.ItemDataRole.UserRole + 1) for t in terms)
            item.setHidden(hidden)
            shown += not hidden
        self.count.setText(f"{shown:,} of {self.list.count():,}")

    def select_texts(self, *texts: str) -> None:
        """Select the items whose text contains each given string (tests and keyboard users)."""
        for row in range(self.list.count()):
            item = self.list.item(row)
            if any(t in item.text() for t in texts):
                item.setSelected(True)

    def _selection_changed(self) -> None:
        self.ok_button.setEnabled(bool(self.list.selectedItems()))

    @property
    def chosen(self) -> list[Any]:
        return [item.data(Qt.ItemDataRole.UserRole) for item in self.list.selectedItems() if not item.isHidden()]
