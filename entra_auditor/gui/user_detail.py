"""Property tabs for the selected user. This milestone has the General tab; Groups, Sign-in methods,
Certificate IDs, Roles and Activity come next and can reuse the profile already loaded here.

The profile loads on a worker after the selection settles (a short delay, so arrowing through the list
doesn't fire a burst of Graph requests). A response for a user who is no longer selected is dropped.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QFormLayout, QLabel, QScrollArea, QStackedWidget, QTabWidget, QVBoxLayout, QWidget

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


class UserDetail(QWidget):
    """Placeholder text, or the tabs for one user."""

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
                           lambda exc: self._failed(generation, exc))

    def _loaded(self, generation: int, profile: UserProfile) -> None:
        if generation != self._generation:
            return              # the selection moved on while this was loading
        self._pending = False
        self.profile = profile
        self.general.show_profile(profile)
        self.stack.setCurrentWidget(self.tabs)

    def _failed(self, generation: int, exc: BaseException) -> None:
        if generation != self._generation:
            return
        self._pending = False
        self._show_message(f"Could not load this user: {exc}")
