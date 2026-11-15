"""Start the desktop app: sign in, then the main window."""

from __future__ import annotations

import sys
from typing import Optional, Sequence

from PySide6.QtWidgets import QApplication, QDialog

from .. import __version__
from ..tenants import TenantConfigError, load_tenants
from .main_window import MainWindow
from .session import SignInService
from .signin import SignInDialog
from .tasks import TaskRunner


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

    dialog = SignInDialog(tenants, runner, service=service, config_error=config_error)
    if dialog.exec() != QDialog.DialogCode.Accepted or dialog.session is None:
        runner.wait(5_000)
        return 1
    session = dialog.session
    window = MainWindow(session, runner)
    window.show()
    window.load_directory()
    try:
        return app.exec()
    finally:
        runner.wait(10_000)         # the window's close already told a running load to stop
        session.close()
