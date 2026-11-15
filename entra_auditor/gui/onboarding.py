"""New-user dialog: name and sign-in name, plus what to copy from a template user (the user that was
selected when the dialog was opened). Nothing is sent from here: accepting hands a plan to the change flow.

The initial password is generated here, never displayed in this dialog, and shown once in the result.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from ..toolkit.onboarding import NewUser, OnboardOptions, Template, suggest_upn
from ..toolkit.passwords import generate_password


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


class NewUserDialog(QDialog):
    def __init__(self, template: Optional[Template] = None, parent: Optional[QWidget] = None, *,
                 default_domain: str = "") -> None:
        super().__init__(parent)
        self.template = template
        self.domain = (template.domain if template else "") or default_domain
        self.password = generate_password()
        self.setWindowTitle("New user")
        self.setMinimumWidth(540)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.given = QLineEdit()
        self.surname = QLineEdit()
        self.display = QLineEdit()
        self.upn = QLineEdit()
        self.upn.setPlaceholderText(f"name@{self.domain or 'your-domain'}")
        form.addRow("First name", self.given)
        form.addRow("Last name", self.surname)
        form.addRow("Display name", self.display)
        form.addRow("Sign-in name (UPN)", self.upn)
        layout.addLayout(form)
        self.force_change = QCheckBox("Must change the password at first sign-in")
        self.force_change.setChecked(True)
        layout.addWidget(self.force_change)
        password_note = QLabel("A random initial password is generated and shown once when the user has been created.")
        password_note.setWordWrap(True)
        password_note.setStyleSheet("color: #666;")
        layout.addWidget(password_note)

        self.boxes: dict[str, QCheckBox] = {}
        if template is None:
            hint = QLabel("No template: select a user before opening this dialog to copy their department, manager, "
                          "licences and groups.")
            hint.setWordWrap(True)
            hint.setStyleSheet("color: #666;")
            layout.addWidget(hint)
        else:
            heading = QLabel(f"<b>Copy from {template.user.full_label}</b>")
            heading.setWordWrap(True)
            layout.addWidget(heading)

            def box(key: str, text: str, available: bool, why_not: str) -> None:
                check = QCheckBox(text if available else f"{text} - {why_not}")
                check.setChecked(available)
                check.setEnabled(available)
                self.boxes[key] = check
                layout.addWidget(check)

            attributes = ", ".join(template.attributes.values())
            box("copy_attributes", f"Department, title, company, office, usage location ({attributes})",
                bool(template.attributes), "none set")
            box("copy_manager", f"Manager ({template.manager_name})", bool(template.manager_id), "none")
            licences = template.copyable_licences
            box("copy_licences", f"{_count(len(licences), 'direct licence')}"
                + (f" ({', '.join(s.name for s in licences)})" if licences else ""), bool(licences),
                "couldn't be read" if template.licences is None else "none that can be assigned")
            groups = template.copyable_groups
            skipped = len(template.groups or []) - len(groups)
            box("copy_groups", f"{_count(len(groups), 'group membership')}"
                + (f" ({skipped} can't be copied)" if skipped else ""), bool(groups),
                "couldn't be read" if template.groups is None else "none that can be copied")
            note = QLabel("Never copied: admin roles, role-assignable groups, administrative units, the mailbox."
                          + "".join(f"\n! {w}" for w in template.warnings))
            note.setWordWrap(True)
            note.setStyleSheet("color: #666;")
            layout.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("Preview change...")
        self.cancel_button = buttons.button(QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        # the display and sign-in names follow the first/last name until they are edited by hand
        self._auto_display = self._auto_upn = True
        self.given.textEdited.connect(self._names_changed)
        self.surname.textEdited.connect(self._names_changed)
        self.display.textEdited.connect(lambda _text: setattr(self, "_auto_display", False))
        self.upn.textEdited.connect(lambda _text: setattr(self, "_auto_upn", False))

    def _names_changed(self, _text: str = "") -> None:
        given, surname = self.given.text(), self.surname.text()
        if self._auto_display:
            self.display.setText(" ".join(part.strip() for part in (given, surname) if part.strip()))
        if self._auto_upn:
            self.upn.setText(suggest_upn(given, surname, self.domain))

    def new_user(self) -> NewUser:
        return NewUser(display_name=self.display.text(), upn=self.upn.text(), password=self.password,
                       given_name=self.given.text() or None, surname=self.surname.text() or None,
                       force_change=self.force_change.isChecked())

    def options(self) -> OnboardOptions:
        return OnboardOptions(**{key: check.isChecked() and check.isEnabled() for key, check in self.boxes.items()})
