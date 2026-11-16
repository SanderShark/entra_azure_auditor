"""The display check before Qt starts (Qt aborts the whole process when it can't open a window)."""

from entra_auditor.gui import NO_DISPLAY_MESSAGE, XCB_CURSOR_MESSAGE, display_problem


def found(name):
    return f"lib{name}.so.0"


def missing(name):
    return None


def test_no_display_is_explained_before_qt_starts():
    assert display_problem({}, "linux", found) == (NO_DISPLAY_MESSAGE, None)
    assert display_problem({"DISPLAY": ""}, "linux", found)[0] == NO_DISPLAY_MESSAGE
    assert "ssh -X" in NO_DISPLAY_MESSAGE and "auditor toolkit" in NO_DISPLAY_MESSAGE


def test_a_desktop_is_fine():
    assert display_problem({"DISPLAY": ":0"}, "linux", found) == (None, None)
    assert display_problem({"WAYLAND_DISPLAY": "wayland-0", "XDG_SESSION_TYPE": "wayland"}, "linux", missing) == (None, None)


def test_missing_xcb_cursor_is_a_warning_only_when_x11_is_used():
    assert display_problem({"DISPLAY": ":0"}, "linux", missing) == (None, XCB_CURSOR_MESSAGE)
    wayland_session = {"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0", "XDG_SESSION_TYPE": "wayland"}
    assert display_problem(wayland_session, "linux", missing) == (None, None)            # Qt picks Wayland there
    assert display_problem({**wayland_session, "QT_QPA_PLATFORM": "xcb"}, "linux", missing)[1] == XCB_CURSOR_MESSAGE
    assert "pacman -S xcb-util-cursor" in XCB_CURSOR_MESSAGE


def test_an_explicit_non_desktop_platform_and_other_systems_are_left_alone():
    assert display_problem({"QT_QPA_PLATFORM": "offscreen"}, "linux", missing) == (None, None)
    assert display_problem({}, "win32", missing) == (None, None)
    assert display_problem({}, "darwin", missing) == (None, None)


def test_the_messages_fit_an_80_column_terminal():
    for message in (NO_DISPLAY_MESSAGE, XCB_CURSOR_MESSAGE):
        assert max(len(line) for line in message.splitlines()) <= 72
