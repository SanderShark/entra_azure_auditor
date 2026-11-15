"""Offboarding dialog: tick what should happen to a leaver, see what will be left alone, then preview.

The facts (groups, units, licences, roles) are gathered on a worker before the dialog opens. Nothing is
sent from here: accepting hands a plan to the change flow, which shows every request before applying.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QLabel, QVBoxLayout, QWidget

from ..toolkit.leaver import LeaverFacts, LeaverOptions


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


class LeaverDialog(QDialog):
    def __init__(self, facts: LeaverFacts, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.facts = facts
        user = facts.user
        self.setWindowTitle(f"Offboard {user.full_label}")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        heading = QLabel(f"<b>Offboard {user.full_label}</b>")
        heading.setWordWrap(True)
        layout.addWidget(heading)
        if facts.is_admin:
            roles = sorted(set(facts.roles_active or []) | set(facts.roles_eligible or []))
            admin = QLabel("This user holds admin roles (" + ", ".join(roles) + "). They are NOT removed here: "
                           "remove them in the Entra admin center.")
            admin.setWordWrap(True)
            admin.setStyleSheet("color: #b00020;")
            layout.addWidget(admin)

        defaults = LeaverOptions()
        self.boxes: dict[str, QCheckBox] = {}

        def box(key: str, text: str, available: bool = True, why_not: str = "") -> None:
            check = QCheckBox(text if available else f"{text} - {why_not}")
            check.setChecked(available and getattr(defaults, key))
            check.setEnabled(available)
            self.boxes[key] = check
            layout.addWidget(check)

        box("disable", "Disable the account", user.account_enabled is not False, "already disabled")
        box("revoke_sessions", "Sign the user out everywhere (revoke sessions)")
        box("reset_password", "Reset the password to a new random one", not user.on_prem_synced,
            "synced from on-premises AD: reset it there")
        direct = len(facts.direct_licences)
        box("remove_licences", f"Remove {_count(direct, 'direct licence')}", direct > 0,
            "couldn't be read" if facts.licences is None else "none assigned directly")
        removable, total = len(facts.removable_groups), len(facts.groups or [])
        text = f"Remove from {_count(removable, 'group')}"
        if total > removable:
            text += f" ({total - removable} can't be changed here)"
        box("remove_groups", text, removable > 0, "couldn't be read" if facts.groups is None else "no removable memberships")
        owned = len(facts.owned or [])
        box("remove_ownerships", f"Remove as owner of {_count(owned, 'group')} (may leave them without an owner)",
            owned > 0, "couldn't be read" if facts.owned is None else "owns none")
        units = len(facts.removable_units)
        box("remove_units", f"Remove from {_count(units, 'administrative unit')} (needs Privileged Role Administrator)",
            units > 0, "couldn't be read" if facts.units is None else "none")

        note = QLabel("Not covered: admin roles, the mailbox (forwarding, shared mailbox), devices, and deleting the "
                      "account. The next screen shows every request before anything is sent."
                      + "".join(f"\n! {w}" for w in facts.warnings))
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

    def options(self) -> LeaverOptions:
        return LeaverOptions(**{key: check.isChecked() and check.isEnabled() for key, check in self.boxes.items()})
