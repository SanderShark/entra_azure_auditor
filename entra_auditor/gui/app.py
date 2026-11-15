"""Start the desktop app: sign in, then the main window; "Switch tenant..." in the window signs in again.

Each tenant has its own token cache, so switching back to a tenant used earlier is usually silent."""

from __future__ import annotations

import sys
from typing import Callable, Optional, Sequence

from PySide6.QtWidgets import QApplication, QDialog

from .. import __version__
from ..tenants import TenantConfigError, load_tenants
from .main_window import MainWindow
from .session import SignInService
from .signin import SignInDialog
from .tasks import TaskRunner


def session_loop(sign_in: Callable[[], Optional[object]], work: Callable[[object], bool]) -> int:
    """Sign in and work until the window closes; start over when the window asked to switch tenant.

    ``sign_in`` returns a session or None (cancelled); ``work`` shows the window for a session, blocks until
    it closes, and returns True when the user chose "Switch tenant...". Returns the process exit code:
    1 when the very first sign-in was cancelled, else 0 (cancelling a later one just ends the app)."""
    first = True
    while True:
        session = sign_in()
        if session is None:
            return 1 if first else 0
        first = False
        if not work(session):
            return 0


def run(argv: Optional[Sequence[str]] = None, *, service: Optional[SignInService] = None) -> int:
    app = QApplication.instance() or QApplication(list(argv if argv is not None else sys.argv[:1]))
    app.setApplicationName("Entra toolkit")
    app.setApplicationVersion(__version__)
    runner = TaskRunner(app)

    config_error = None
    try:
        tenants = load_tenants()
    except TenantConfigError as exc:
        tenants, config_error = [], str(exc)

    def sign_in() -> Optional[object]:
        dialog = SignInDialog(tenants, runner, service=service, config_error=config_error)
        if dialog.exec() != QDialog.DialogCode.Accepted or dialog.session is None:
            runner.wait(5_000)
            return None
        return dialog.session

    def work(session: object) -> bool:
        window = MainWindow(session, runner)        # type: ignore[arg-type]
        window.show()
        window.load_directory()
        try:
            app.exec()
        finally:
            runner.wait(10_000)     # the window's close already told a running load to stop
            session.close()         # type: ignore[attr-defined]
        return window.switch_requested

    return session_loop(sign_in, work)
