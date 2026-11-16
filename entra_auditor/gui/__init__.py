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

import ctypes.util
import os
import sys
from typing import Mapping, Optional

MISSING_MESSAGE = (
    "The desktop app needs PySide6, which isn't installed. Install it with\n"
    "    python -m pip install \".[gui]\"\n"
    "(or `python -m pip install PySide6`), then run `auditor gui` again."
)


# Lines kept under 72 characters: the terminal may be 80 columns wide and Rich re-wraps longer ones.
NO_DISPLAY_MESSAGE = (
    "The desktop app needs a graphical desktop, and this terminal\n"
    "isn't connected to one (DISPLAY and WAYLAND_DISPLAY are empty).\n"
    "That usually means one of:\n"
    "  - you are connected over SSH: run `auditor gui` on the machine's\n"
    "    own desktop, or connect with `ssh -X` so windows open on yours;\n"
    "  - you are on a text console, with no desktop session running;\n"
    "  - the terminal was started outside the desktop session\n"
    "    (for example inside a tmux session started earlier).\n"
    "The command line works without a desktop:\n"
    "  auditor toolkit   auditor id ...   auditor check"
)
XCB_CURSOR_MESSAGE = (
    "Warning: libxcb-cursor isn't installed; Qt 6.5+ needs it on X11.\n"
    "  Arch:          sudo pacman -S xcb-util-cursor\n"
    "  Debian/Ubuntu: sudo apt install libxcb-cursor0\n"
    "  Fedora:        sudo dnf install xcb-util-cursor\n"
    "On a Wayland desktop you can also try:\n"
    "  QT_QPA_PLATFORM=wayland auditor gui"
)


def display_problem(env: Optional[Mapping[str, str]] = None, platform: str = sys.platform,
                    find_library=ctypes.util.find_library) -> tuple[Optional[str], Optional[str]]:
    """(error, warning) about starting a window here, checked BEFORE Qt starts: when Qt can't open a window
    it aborts the whole process with a terse message. Only Linux/BSD desktops are checked."""
    env = os.environ if env is None else env
    if not platform.startswith(("linux", "freebsd", "openbsd")):
        return None, None
    chosen = env.get("QT_QPA_PLATFORM", "").split(":")[0].strip().lower()
    if chosen and chosen not in ("xcb", "wayland", "wayland-egl"):
        return None, None               # offscreen, vnc, eglfs...: the user knows what they asked for
    x11, wayland = bool(env.get("DISPLAY")), bool(env.get("WAYLAND_DISPLAY"))
    if not x11 and not wayland:
        return NO_DISPLAY_MESSAGE, None
    uses_x11 = chosen == "xcb" or (not chosen and x11 and not (wayland and env.get("XDG_SESSION_TYPE") == "wayland"))
    if uses_x11 and find_library("xcb-cursor") is None:
        return None, XCB_CURSOR_MESSAGE
    return None, None


def qt_available() -> bool:
    try:
        import PySide6.QtWidgets  # noqa: F401
    except ImportError:
        return False
    return True
