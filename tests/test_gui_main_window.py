"""The main window against the permission-enforcing FakeTenant: load, filter, inspect, and change a user
through the real dialogs (preview -> confirm -> PIM elevation -> justification -> result).

The PIM dialogs are tested here against the fake tenant ONLY; they are not yet verified live."""

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QMessageBox  # noqa: E402

from entra_auditor.graph.client import GraphError  # noqa: E402
from entra_auditor.gui.change import (  # noqa: E402
    ElevationDialog,
    JustificationDialog,
    PlanDialog,
    ResultDialog,
)
from entra_auditor.gui.main_window import MainWindow  # noqa: E402
from entra_auditor.toolkit.directory import load_users  # noqa: E402
from tests.fakes import FakeTenant  # noqa: E402
from tests.gui_support import FakeSession  # noqa: E402


@pytest.fixture
def window(qtbot, runner):
    def make(tenant=None, **kw):
        session = FakeSession(tenant)
        win = MainWindow(session, runner, change_sleep=lambda s: None, **kw)
        qtbot.addWidget(win)
        win.show()
        win.load_directory()
        qtbot.waitUntil(lambda: not win.loading)
        return win
    return make


def wait_for(qtbot, ctrl, kind):
    """The dialog the change is waiting on. `ctrl` is the ChangeController (the window lets go of it as
    soon as the change finishes, while its result dialog is still open)."""
    qtbot.waitUntil(lambda: isinstance(ctrl.dialog, kind), timeout=5000)
    return ctrl.dialog


def pim_writes(win):
    return [w for w in win.session.graph.writes if w[1] == "pim"]


# ---- loading, filtering, details ------------------------------------------------------------

def test_the_directory_loads_in_the_background_and_is_counted(qtbot, window):
    win = window()
    assert win.model.rowCount() == 8 and win.count_label.text() == "8 users"
    assert "Loaded 8 users" in win.statusBar().currentMessage()
    assert win.session.graph.calls.count(("GET", "/users")) == 1         # one listing, not one per search


def test_typing_filters_the_list_without_asking_graph_again(qtbot, window):
    win = window()
    calls = len(win.session.graph.calls)
    qtbot.keyClicks(win.filter_edit, "bob")
    qtbot.waitUntil(lambda: win.count_label.text() == "2 of 8 users")
    assert len(win.session.graph.calls) == calls


def test_selecting_a_user_shows_the_general_tab(qtbot, window):
    win = window()
    assert win.select_user("u-alice")
    qtbot.waitUntil(lambda: win.detail.profile is not None)
    values = win.detail.general.values
    assert values["Name"].text() == "Alice Ng" and values["Employee id"].text() == "E100"
    assert values["Account"].text() == "Enabled" and win.toggle_action.text() == "Disable account"
    assert win.detail.stack.currentWidget() is win.detail.tabs


def test_a_stale_profile_response_does_not_overwrite_the_current_user(qtbot, window, runner):
    import threading

    gate = threading.Event()

    def slow_for_alice(graph, user_id):
        from entra_auditor.toolkit.profile import load_user_profile
        if user_id == "u-alice":
            gate.wait(5)
        return load_user_profile(graph, user_id)

    win = window()
    win.detail._loader = slow_for_alice
    win.select_user("u-alice")
    qtbot.waitUntil(lambda: win.detail._pending)          # alice's load is in flight
    win.select_user("u-bob")
    qtbot.waitUntil(lambda: win.detail.profile is not None and win.detail.profile.id == "u-bob")
    gate.set()
    runner.wait()
    qtbot.wait(20)
    assert win.detail.profile.id == "u-bob" and win.detail.general.values["Name"].text() == "Bob Stone"


def test_a_failed_load_says_so_and_keeps_the_list_it_had(qtbot, window, monkeypatch):
    shown = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: shown.append(a[2]))
    win = window()

    def broken(graph, **kw):
        raise GraphError("Graph is unavailable", status_code=503)

    win._loader = broken
    win.load_directory()
    qtbot.waitUntil(lambda: not win.loading)
    assert shown and "unavailable" in shown[0]
    assert win.model.rowCount() == 8                        # unknown is not empty: the old list stays


def test_a_large_directory_reports_progress(qtbot, window):
    from tests.fakes import FakeGraph

    users = [{"id": f"u{i}", "displayName": f"User {i}", "userPrincipalName": f"u{i}@contoso.com"} for i in range(2500)]
    progress = []
    win = window()
    win.load_progress.connect(progress.append)
    win.session.graph = FakeGraph({"/users": users})
    win.load_directory()
    qtbot.waitUntil(lambda: not win.loading)
    assert progress[:2] == [999, 1998] and win.count_label.text() == "2,500 users"


# ---- changes through the dialogs --------------------------------------------------------------

def start_disable(qtbot, win, user_id="u-alice"):
    """Click "Disable account"; returns (controller, the preview dialog)."""
    win.select_user(user_id)
    assert win.toggle_action.isEnabled()
    win.toggle_action.trigger()
    ctrl = win.change
    return ctrl, wait_for(qtbot, ctrl, PlanDialog)


def test_the_preview_shows_the_exact_request_and_cancel_is_the_default(qtbot, window):
    win = window()
    ctrl, plan = start_disable(qtbot, win)
    assert plan.requests.item(0, 0).text() == "PATCH" and plan.requests.item(0, 1).text() == "/users/u-alice"
    assert "accountEnabled" in plan.requests.item(0, 2).text()
    assert plan.cancel_button.isDefault() and any("revoke sessions" in w.text() for w in plan.warnings)
    plan.cancel_button.click()
    qtbot.waitUntil(lambda: win.change is None)
    assert win.session.graph.writes == [] and "Cancelled" in win.statusBar().currentMessage()


def test_disable_with_pim_elevation_end_to_end(qtbot, window):
    win = window()
    ctrl, plan = start_disable(qtbot, win)
    plan.apply_button.click()

    elevation = wait_for(qtbot, ctrl, ElevationDialog)        # FakeTenant denies until a role is active
    assert elevation.chosen_role.name == "User Administrator"
    elevation.activate_button.click()

    justification = wait_for(qtbot, ctrl, JustificationDialog)
    assert not justification.ok_button.isEnabled()           # a reason is required
    qtbot.keyClicks(justification.text, "   ")
    assert not justification.ok_button.isEnabled()           # blanks don't count
    qtbot.keyClicks(justification.text, "INC-42 leaver")
    assert justification.ok_button.isEnabled()
    justification.ok_button.click()

    result = wait_for(qtbot, ctrl, ResultDialog)
    assert result.status_label.text().startswith("OK:")
    assert pim_writes(win)[0][2]["justification"] == "INC-42 leaver"
    assert win.session.graph.users["u-alice"]["accountEnabled"] is False
    assert win.session.provider.refreshes >= 1               # token refreshed after the activation
    result.accept()
    qtbot.waitUntil(lambda: win.toggle_action.text() == "Enable account")    # the row was re-read
    row = next(r for r in range(win.model.rowCount()) if win.model.user_at(r).id == "u-alice")
    assert win.model.index(row, 3).data() == "Disabled"


def test_declining_elevation_ends_denied_without_activating(qtbot, window):
    win = window()
    ctrl, plan = start_disable(qtbot, win)
    plan.apply_button.click()
    wait_for(qtbot, ctrl, ElevationDialog).skip_button.click()
    result = wait_for(qtbot, ctrl, ResultDialog)
    assert result.status_label.text().startswith("DENIED")
    assert pim_writes(win) == [] and win.session.graph.users["u-alice"]["accountEnabled"] is True


def test_cancelling_the_justification_activates_nothing(qtbot, window):
    win = window()
    ctrl, plan = start_disable(qtbot, win)
    plan.apply_button.click()
    wait_for(qtbot, ctrl, ElevationDialog).activate_button.click()
    wait_for(qtbot, ctrl, JustificationDialog).cancel_button.click()
    result = wait_for(qtbot, ctrl, ResultDialog)
    assert result.status_label.text().startswith("DENIED") and pim_writes(win) == []


def test_a_role_that_cannot_be_activated_explains_why(qtbot, window):
    win = window(FakeTenant(require_mfa={"User Administrator"}))
    ctrl, plan = start_disable(qtbot, win)
    plan.apply_button.click()
    wait_for(qtbot, ctrl, ElevationDialog).activate_button.click()
    justification = wait_for(qtbot, ctrl, JustificationDialog)
    qtbot.keyClicks(justification.text, "INC-1")
    justification.ok_button.click()
    result = wait_for(qtbot, ctrl, ResultDialog)
    texts = " ".join(label.text() for label in result.findChildren(type(result.status_label)))
    assert result.status_label.text().startswith("DENIED") and "multifactor" in texts.lower()


def test_an_allowed_change_needs_no_elevation(qtbot, window):
    tenant = FakeTenant()
    tenant.active_roles["r-user-administrator"] = "User Administrator"
    win = window(tenant)
    ctrl, plan = start_disable(qtbot, win)
    plan.apply_button.click()
    result = wait_for(qtbot, ctrl, ResultDialog)
    assert result.status_label.text().startswith("OK:") and pim_writes(win) == []


def test_only_one_change_runs_at_a_time(qtbot, window):
    win = window()
    ctrl, _plan = start_disable(qtbot, win)
    assert not win.toggle_action.isEnabled()
    win.toggle_selected_account()                             # e.g. a second click via the context menu
    assert win.change is ctrl


def test_the_gui_never_writes_except_through_the_change_flow():
    """Rule 1: UI code builds plans and hands them to ChangeController; it never sends writes itself."""
    import ast
    import pathlib

    import entra_auditor.gui as gui

    offenders = []
    for path in pathlib.Path(gui.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Attribute) and node.attr in ("post", "patch", "delete", "request"):
                offenders.append(f"{path.name}:{node.lineno} .{node.attr}")
            if isinstance(node, ast.Name) and node.id == "execute_plan":
                offenders.append(f"{path.name}:{node.lineno} execute_plan")
    assert offenders == []


def test_loading_via_the_real_loader_is_what_the_window_uses():
    import inspect

    assert inspect.signature(MainWindow).parameters["loader"].default is load_users


def test_pressing_enter_in_the_preview_cancels_instead_of_applying(qtbot, window):
    from PySide6.QtCore import Qt

    win = window()
    ctrl, plan = start_disable(qtbot, win)
    assert plan.cancel_button.isDefault() and not plan.apply_button.isDefault()
    qtbot.keyClick(plan, Qt.Key.Key_Return)
    qtbot.waitUntil(lambda: win.change is None)
    assert ctrl.done.cancelled and win.session.graph.writes == []


# ---- the other property tabs ----------------------------------------------------------------

def test_the_property_tabs_show_groups_methods_cert_ids_and_roles(qtbot, window):
    win = window()

    win.select_user("u-alice")
    qtbot.waitUntil(lambda: win.detail.profile is not None)
    calls_before = len(win.session.graph.calls)
    d = win.detail
    assert d.groups_tab.texts("Member of") == ["Project X (Microsoft 365)"] and d.groups_tab.texts("Owns") == ["nothing"]
    assert len(d.methods_tab.texts("Sign-in methods")) == 2
    assert d.certs_tab.texts("Certificate user IDs") == ["X509:<PN>alice@contoso.com"]
    assert d.roles_tab.texts("Active roles") == ["none"]
    for index in range(d.tabs.count()):            # switching tabs asks Graph for nothing more
        d.tabs.setCurrentIndex(index)
    assert len(win.session.graph.calls) == calls_before


def test_an_admin_shows_their_roles(qtbot, window):
    win = window()
    win.select_user("u-admin")
    qtbot.waitUntil(lambda: win.detail.profile is not None)
    assert win.detail.roles_tab.texts("Active roles") == ["Global Administrator"]
    assert win.detail.roles_tab.texts("Eligible roles (PIM)") == ["Global Administrator"]


def test_unreadable_parts_say_so_instead_of_looking_empty(qtbot, window):
    from entra_auditor.toolkit.models import UserProfile

    def partial(graph, user_id):
        return UserProfile(id=user_id, display_name="Alice Ng", groups=None, auth_methods=None, roles_active=None,
                           warnings=["certificate user IDs: unavailable (403)", "group memberships: unavailable (403)"])

    win = window()
    win.detail._loader = partial
    win.select_user("u-alice")
    qtbot.waitUntil(lambda: win.detail.profile is not None)
    d = win.detail
    assert d.groups_tab.texts("Member of") == ["(could not be read)"]
    assert d.methods_tab.texts("Sign-in methods") == ["(could not be read)"]
    assert d.certs_tab.texts("Certificate user IDs") == ["(could not be read)"]
    assert d.roles_tab.texts("Active roles") == ["(could not be read)"]
    assert "group memberships" in d.general.warnings.text()
