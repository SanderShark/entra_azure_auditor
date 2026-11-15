"""The desktop app (PySide6). Optional: install with ``pip install .[gui]`` and start with ``auditor gui``.

Layout:
    tasks.py        run Graph calls off the UI thread; results come back on the UI thread
    session.py      a signed-in tenant (graph client + token provider), and how to sign in
    signin.py       the sign-in dialog (tenant picker, device code or browser)
    user_model.py   the user table model and the type-to-filter proxy
    user_detail.py  the property tabs for the selected user
    change.py       every tenant change as dialogs, driven by toolkit.flow.ChangeFlow
    main_window.py  navigation | list | property tabs
    app.py          QApplication start-up

Nothing in this package calls ``graph.post/patch/delete`` or ``execute_plan``: changes go through
``change.ChangeController``, which drives the same ``ChangeFlow`` as the terminal.
"""

from __future__ import annotations

MISSING_MESSAGE = (
    "The desktop app needs PySide6, which isn't installed. Install it with\n"
    "    python -m pip install \".[gui]\"\n"
    "(or `python -m pip install PySide6`), then run `auditor gui` again."
)


def qt_available() -> bool:
    try:
        import PySide6.QtWidgets  # noqa: F401
    except ImportError:
        return False
    return True
