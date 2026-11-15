"""The main window against the permission-enforcing FakeTenant: load, filter, inspect, and change a user
through the real dialogs (preview -> confirm -> PIM elevation -> justification -> result).

The PIM dialogs are tested here against the fake tenant ONLY; they are not yet verified live."""

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt  # noqa: E402
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
    for index in range(d.tabs.count()):            # switching tabs asks Graph for nothing more...
        if d.tabs.widget(index) not in (d.managers_tab, d.licences_tab):   # ...except the two that load on demand
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


def test_the_elevation_dialog_offers_a_pim_group(qtbot, window):
    tenant = FakeTenant(eligible=()).add_pim_group("g-uadm", "User Admins (PIM)", roles=["User Administrator"])
    win = window(tenant)
    ctrl, plan = start_disable(qtbot, win)
    plan.apply_button.click()
    elevation = wait_for(qtbot, ctrl, ElevationDialog)
    assert "grants User Administrator" in elevation.roles.item(0).text()
    elevation.activate_button.click()
    justification = wait_for(qtbot, ctrl, JustificationDialog)
    qtbot.keyClicks(justification.text, "INC-5")
    justification.ok_button.click()
    result = wait_for(qtbot, ctrl, ResultDialog)
    assert result.status_label.text().startswith("OK:") and tenant.users["u-alice"]["accountEnabled"] is False


# ---- who can manage ---------------------------------------------------------------------------

def managed_tenant():
    from tests.fakes import U
    tenant = FakeTenant()
    for uid, name in (("a-ga", "Gail Global"), ("a-hd", "Hank Helpdesk"), ("a-exec", "Eve Executive-Support")):
        tenant.users[uid] = U(uid, name, f"{uid}@contoso.com")
    tenant.add_admin_unit("au-exec", "Executives", members=("u-bob",), isMemberManagementRestricted=True)
    tenant.add_role_holder("Global Administrator", "a-ga").add_role_holder("Helpdesk Administrator", "a-hd")
    tenant.add_role_holder("Helpdesk Administrator", "a-exec", au="au-exec")
    return tenant


def open_managers(qtbot, win, user_id):
    win.select_user(user_id)
    qtbot.waitUntil(lambda: win.detail.profile is not None)
    tab = win.detail.managers_tab
    assert tab.report is None and tab.rows() == [] and "Open this tab" in tab.summary.text()   # nothing asked yet
    win.detail.tabs.setCurrentWidget(tab)
    qtbot.waitUntil(lambda: tab.report is not None)
    return tab


def test_who_can_manage_loads_when_its_tab_is_opened_and_lists_the_admins(qtbot, window):
    win = window(managed_tenant())
    tab = open_managers(qtbot, win, "u-alice")
    assert tab.rows() == [
        ("Gail Global (a-ga@contoso.com)", "Global Administrator", "Whole tenant", "Active",
         "reset password, enable/disable, delete, change sign-in name, sign-in methods, edit profile, licences"),
        ("Hank Helpdesk (a-hd@contoso.com)", "Helpdesk Administrator", "Whole tenant", "Active", "reset password"),
    ]
    calls = len(win.session.graph.calls)
    win.detail.tabs.setCurrentIndex(0)
    win.detail.tabs.setCurrentWidget(tab)                       # coming back doesn't ask again
    assert len(win.session.graph.calls) == calls and win.session.graph.writes == []


def test_who_can_manage_explains_a_restricted_unit(qtbot, window):
    win = window(managed_tenant())
    tab = open_managers(qtbot, win, "u-bob")
    assert "restricted management unit Executives" in tab.summary.text()
    by_who = {row[0].split(" (")[0]: row for row in tab.rows()}
    assert by_who["Eve Executive-Support"][2:] == ("Unit: Executives", "Active", "reset password")
    assert by_who["Gail Global"][4].startswith("licences (everything else is blocked by a restricted")
    assert by_who["Hank Helpdesk"][4].startswith("nothing for this user (blocked")


def test_who_can_manage_follows_the_selection_and_stays_on_the_tab(qtbot, window):
    win = window(managed_tenant())
    tab = open_managers(qtbot, win, "u-alice")
    win.select_user("u-bob")                                    # the tab is still the open one: it reloads
    qtbot.waitUntil(lambda: tab.report is not None and tab.report.user_id == "u-bob")
    assert any(row[2] == "Unit: Executives" for row in tab.rows())


def test_a_late_answer_for_a_user_no_longer_selected_is_dropped(qtbot, window):
    import threading

    from entra_auditor.toolkit.managers import ManagerReport, who_can_manage
    release = threading.Event()

    def slow_for_alice(graph, user_id):
        if user_id == "u-alice":
            release.wait(5)
            return ManagerReport(user_id=user_id, notes=["STALE"])
        return who_can_manage(graph, user_id)

    win = window(managed_tenant())
    tab = win.detail.managers_tab
    tab._loader = slow_for_alice
    win.select_user("u-alice")
    qtbot.waitUntil(lambda: win.detail.profile is not None)
    win.detail.tabs.setCurrentWidget(tab)
    qtbot.waitUntil(lambda: tab.loading)
    win.select_user("u-bob")
    qtbot.waitUntil(lambda: tab.report is not None and tab.report.user_id == "u-bob")
    release.set()
    qtbot.waitUntil(lambda: not win.runner.busy)
    assert tab.report.user_id == "u-bob" and "STALE" not in tab.summary.text()


def test_who_can_manage_says_when_the_admins_cannot_be_read_and_a_failure_can_be_retried(qtbot, window):
    tenant = managed_tenant()
    tenant.assignments_denied = True
    win = window(tenant)
    tab = open_managers(qtbot, win, "u-alice")
    assert tab.rows() == [] and "(could not be read)" in tab.summary.text()

    calls = []

    def flaky(graph, user_id):
        calls.append(user_id)
        if len(calls) == 1:
            raise GraphError("boom", status_code=500)
        from entra_auditor.toolkit.managers import ManagerReport
        return ManagerReport(user_id=user_id, managers=[])

    tab._loader = flaky
    win.select_user("u-bob")
    qtbot.waitUntil(lambda: "Could not work out" in tab.summary.text())
    win.detail.tabs.setCurrentIndex(0)
    win.detail.tabs.setCurrentWidget(tab)                       # looking again retries
    qtbot.waitUntil(lambda: tab.report is not None)
    assert "No admin with a user-management role was found." in tab.summary.text()


# ---- licences -----------------------------------------------------------------------------------

def licence_tenant(**kw):
    tenant = FakeTenant(eligible=("License Administrator",), **kw)
    tenant.add_sku("sku-e3", "SPE_E3", total=3).add_sku("sku-p1", "AAD_PREMIUM", total=5).add_sku("sku-full", "VISIOCLIENT", total=1)
    tenant.users["u-alice"]["usageLocation"] = "US"
    tenant.give_licence("u-alice", "sku-e3").give_licence("u-alice", "sku-p1", group="g-fin").give_licence("u-guest", "sku-full")
    return tenant


def open_licences(qtbot, win, user_id):
    win.select_user(user_id)
    qtbot.waitUntil(lambda: win.detail.profile is not None)
    tab = win.detail.licences_tab
    assert tab.report is None and not tab.change_button.isEnabled()
    win.detail.tabs.setCurrentWidget(tab)
    qtbot.waitUntil(lambda: tab.report is not None)
    return tab


def test_the_licences_tab_shows_what_the_user_holds_and_where_from(qtbot, window):
    tab = open_licences(qtbot, window(licence_tenant()), "u-alice")
    assert tab.texts() == ["Microsoft 365 E3 (SPE_E3)  -  direct",
                           "Microsoft Entra ID P1 (AAD_PREMIUM)  -  from group Finance Share"]
    assert tab.summary.text() == "Usage location: US" and tab.change_button.isEnabled()


def test_changing_licences_goes_through_the_dialog_the_preview_and_pim(qtbot, window):
    from entra_auditor.gui.user_detail import LicenceDialog
    tenant = licence_tenant()
    win = window(tenant)
    tab = open_licences(qtbot, win, "u-alice")
    tab.change_button.click()
    qtbot.waitUntil(lambda: isinstance(tab.dialog, LicenceDialog))
    dialog = tab.dialog
    lines = [dialog.list.item(i).text() for i in range(dialog.list.count())]
    assert lines == ["Microsoft 365 E3 (SPE_E3)  -  2 of 3 free",
                     "Microsoft Entra ID P1 (AAD_PREMIUM)  -  4 of 5 free  (inherited from Finance Share)",
                     "Visio Plan 2 (VISIOCLIENT)  -  0 of 1 free"]
    assert not dialog.list.item(2).flags() & Qt.ItemFlag.ItemIsEnabled       # none left: can't be ticked
    assert not dialog.location.isEnabled()                                   # she has a usage location already
    dialog.set_checked("SPE_E3", False)
    dialog.set_checked("AAD_PREMIUM", True)
    dialog.ok_button.click()
    qtbot.waitUntil(lambda: win.change is not None)
    ctrl = win.change
    assert ctrl.flow.plan.details == ["+ Microsoft Entra ID P1 (AAD_PREMIUM)", "- Microsoft 365 E3 (SPE_E3)"]
    wait_for(qtbot, ctrl, PlanDialog).apply_button.click()
    wait_for(qtbot, ctrl, ElevationDialog).activate_button.click()
    justification = wait_for(qtbot, ctrl, JustificationDialog)
    qtbot.keyClicks(justification.text, "INC-30")
    justification.ok_button.click()
    wait_for(qtbot, ctrl, ResultDialog).accept()
    assert tenant.licences["u-alice"] == {"sku-p1": {"direct": True, "groups": ["g-fin"]}}
    qtbot.waitUntil(lambda: tab.report is not None and len(tab.texts()) == 1)   # the tab re-read the user
    assert tab.texts() == ["Microsoft Entra ID P1 (AAD_PREMIUM)  -  direct, from group Finance Share"]


def test_a_user_without_a_usage_location_is_asked_for_one(qtbot, window, monkeypatch):
    from entra_auditor.gui.user_detail import LicenceDialog
    tenant = licence_tenant()
    tenant.active_roles["r"] = "License Administrator"
    win = window(tenant)
    tab = open_licences(qtbot, win, "u-bob")
    assert tab.texts() == ["no licences"] and "not set" in tab.summary.text()
    said = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: said.append(a[2]))
    tab.change_button.click()
    qtbot.waitUntil(lambda: isinstance(tab.dialog, LicenceDialog))
    tab.dialog.set_checked("SPE_E3", True)
    tab.dialog.ok_button.click()                                # no location given: explained, nothing started
    qtbot.waitUntil(lambda: tab.dialog is None)
    assert "usage location" in said[0] and win.change is None and tenant.writes == []
    tab.change_button.click()
    qtbot.waitUntil(lambda: isinstance(tab.dialog, LicenceDialog))
    tab.dialog.set_checked("SPE_E3", True)
    tab.dialog.location.setText("gb")
    tab.dialog.ok_button.click()
    qtbot.waitUntil(lambda: win.change is not None)
    ctrl = win.change
    wait_for(qtbot, ctrl, PlanDialog).apply_button.click()
    wait_for(qtbot, ctrl, ResultDialog).accept()
    assert tenant.users["u-bob"]["usageLocation"] == "GB" and "sku-e3" in tenant.licences["u-bob"]


def test_licences_that_cannot_be_read_offer_no_changes(qtbot, window):
    tenant = licence_tenant()
    tenant.skus_denied = True
    tab = open_licences(qtbot, window(tenant), "u-alice")
    assert not tab.change_button.isEnabled() and "subscriptions couldn't be read" in tab.summary.text()
    assert tab.texts()[0].startswith("sku-e3")                  # still listed, by id


# ---- offboarding ----------------------------------------------------------------------------------

def leaver_tenant(**kw):
    tenant = licence_tenant(**kw)
    tenant.eligible_names.append("User Administrator")
    tenant.role_ids["User Administrator"] = "r-user-administrator"
    tenant.members.update({"g-fin": {"u-bob"}, "g-dyn": {"u-bob"}})
    tenant.owners["g-fin"] = {"u-bob"}
    tenant.add_admin_unit("au-sea", "Seattle", members=("u-bob",))
    tenant.give_licence("u-bob", "sku-e3")
    return tenant


def open_offboarding(qtbot, win, user_id="u-bob"):
    from entra_auditor.gui.leaver import LeaverDialog
    win.select_user(user_id)
    assert win.offboard_action.isEnabled()
    win.offboard_action.trigger()
    qtbot.waitUntil(lambda: isinstance(win.dialog, LeaverDialog))
    return win.dialog


def test_offboarding_shows_what_the_user_has_and_what_cannot_be_done(qtbot, window):
    dialog = open_offboarding(qtbot, window(leaver_tenant()))
    texts = {key: box.text() for key, box in dialog.boxes.items()}
    assert texts["remove_licences"] == "Remove 1 direct licence"
    assert texts["remove_groups"] == "Remove from 1 group (1 can't be changed here)"
    assert texts["remove_units"].startswith("Remove from 1 administrative unit")
    assert dialog.boxes["remove_ownerships"].isEnabled() and not dialog.boxes["remove_ownerships"].isChecked()
    assert all(dialog.boxes[k].isChecked() for k in ("disable", "revoke_sessions", "reset_password", "remove_groups"))
    dialog.cancel_button.click()


def test_offboarding_runs_as_one_previewed_change_with_elevation(qtbot, window):
    tenant = leaver_tenant()
    win = window(tenant)
    dialog = open_offboarding(qtbot, win)
    dialog.boxes["reset_password"].setChecked(False)
    dialog.ok_button.click()
    qtbot.waitUntil(lambda: win.change is not None)
    ctrl = win.change
    assert [r.description for r in ctrl.flow.plan.requests] == [
        "Disable account", "Revoke sign-in sessions", "Remove licences", "Remove from group Finance Share",
        "Remove from administrative unit Seattle"]
    assert tenant.writes == []                                    # nothing before the preview is confirmed
    plan = wait_for(qtbot, ctrl, PlanDialog)
    assert plan.cancel_button.isDefault()
    plan.apply_button.click()
    elevation = wait_for(qtbot, ctrl, ElevationDialog)
    assert elevation.roles.item(0).text() == "User Administrator"
    elevation.activate_button.click()
    justification = wait_for(qtbot, ctrl, JustificationDialog)
    qtbot.keyClicks(justification.text, "Leaver HR-77")
    justification.ok_button.click()
    result = wait_for(qtbot, ctrl, ResultDialog)
    assert result.status_label.text().startswith("OK:")
    result.accept()
    assert tenant.users["u-bob"]["accountEnabled"] is False and tenant.members["g-fin"] == set()
    assert "u-bob" not in tenant.licences or "sku-e3" not in tenant.licences["u-bob"]
    assert "u-bob" not in tenant.au_members["au-sea"] and tenant.owners["g-fin"] == {"u-bob"}
    qtbot.waitUntil(lambda: win.selected_user().account_enabled is False)       # the list was refreshed


def test_offboarding_reports_the_steps_that_were_refused(qtbot, window):
    tenant = leaver_tenant()
    tenant.active_roles["r"] = "User Administrator"
    tenant.refuse = [r"/administrativeUnits/"]
    win = window(tenant)
    open_offboarding(qtbot, win).ok_button.click()
    qtbot.waitUntil(lambda: win.change is not None)
    ctrl = win.change
    wait_for(qtbot, ctrl, PlanDialog).apply_button.click()
    result = wait_for(qtbot, ctrl, ResultDialog)
    assert result.status_label.text().startswith("PARTIAL: 5 of 6 steps done; 1 could not be done")
    assert result.password_label is not None                     # the new password is still shown once
    result.accept()
    assert tenant.users["u-bob"]["accountEnabled"] is False and "u-bob" in tenant.au_members["au-sea"]


def test_cancelling_offboarding_sends_nothing(qtbot, window):
    tenant = leaver_tenant()
    win = window(tenant)
    open_offboarding(qtbot, win).cancel_button.click()
    qtbot.waitUntil(lambda: win.dialog is None)
    assert win.change is None and tenant.writes == [] and win.offboard_action.isEnabled()


# ---- onboarding -------------------------------------------------------------------------------------

def onboarding_tenant():
    tenant = licence_tenant()
    tenant.eligible_names.append("User Administrator")
    tenant.role_ids["User Administrator"] = "r-user-administrator"
    tenant.users["u-alice"].update(usageLocation="US")
    tenant.managers["u-alice"] = "u-bob"
    tenant.members.update({"g-fin": {"u-alice"}, "g-dyn": {"u-alice"}})
    return tenant


def open_new_user(qtbot, win, template_id=None):
    from entra_auditor.gui.onboarding import NewUserDialog
    if template_id:
        win.select_user(template_id)
    win.new_user_action.trigger()
    qtbot.waitUntil(lambda: isinstance(win.dialog, NewUserDialog))
    return win.dialog


def test_the_new_user_dialog_suggests_names_until_they_are_edited(qtbot, window):
    dialog = open_new_user(qtbot, window(onboarding_tenant()), "u-alice")
    qtbot.keyClicks(dialog.given, "Nia")
    qtbot.keyClicks(dialog.surname, "Novak")
    assert dialog.display.text() == "Nia Novak" and dialog.upn.text() == "nia.novak@contoso.com"
    dialog.upn.clear()
    qtbot.keyClicks(dialog.upn, "nnovak@contoso.com")           # edited by hand: no longer overwritten
    qtbot.keyClicks(dialog.surname, "a")
    assert dialog.upn.text() == "nnovak@contoso.com" and dialog.display.text() == "Nia Novaka"
    texts = {key: box.text() for key, box in dialog.boxes.items()}
    assert texts["copy_manager"] == "Manager (Bob Stone)"
    assert texts["copy_licences"] == "1 direct licence (Microsoft 365 E3 (SPE_E3))"
    assert texts["copy_groups"] == "2 group memberships (1 can't be copied)"
    assert dialog.password not in " ".join(w.text() for w in dialog.findChildren(type(dialog.display)))
    dialog.cancel_button.click()


def test_a_user_is_created_from_a_template_and_the_password_shown_once(qtbot, window):
    tenant = onboarding_tenant()
    win = window(tenant)
    dialog = open_new_user(qtbot, win, "u-alice")
    qtbot.keyClicks(dialog.given, "Nia")
    qtbot.keyClicks(dialog.surname, "Novak")
    password = dialog.password
    dialog.ok_button.click()
    qtbot.waitUntil(lambda: win.change is not None)
    ctrl = win.change
    plan = wait_for(qtbot, ctrl, PlanDialog)
    shown = " ".join(label.text() for label in plan.findChildren(type(plan.findChildren(type(win.count_label))[0])))
    assert password not in shown and tenant.writes == []
    plan.apply_button.click()
    wait_for(qtbot, ctrl, ElevationDialog).activate_button.click()
    justification = wait_for(qtbot, ctrl, JustificationDialog)
    qtbot.keyClicks(justification.text, "Starter HR-12")
    justification.ok_button.click()
    result = wait_for(qtbot, ctrl, ResultDialog)
    assert result.status_label.text().startswith("OK:") and result.password_label.text() == password
    result.accept()
    assert tenant.created == ["new-1"] and tenant.managers["new-1"] == "u-bob" and "new-1" in tenant.members["g-fin"]
    assert tenant.passwords["new-1"]["password"] == password and "sku-e3" in tenant.licences["new-1"]
    qtbot.waitUntil(lambda: not win.loading and win.select_user("new-1"))      # the directory was reloaded
    assert win.selected_user().upn == "nia.novak@contoso.com"


def test_a_user_can_be_created_without_a_template_and_bad_input_is_explained(qtbot, window, monkeypatch):
    tenant = onboarding_tenant()
    tenant.active_roles["r"] = "User Administrator"
    win = window(tenant)
    said = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: said.append(a[2]))
    dialog = open_new_user(qtbot, win)
    assert dialog.template is None and dialog.boxes == {} and dialog.domain == "contoso.com"
    dialog.ok_button.click()                                    # nothing filled in
    qtbot.waitUntil(lambda: win.dialog is None)
    assert "display name" in said[0] and win.change is None and tenant.writes == []
    dialog = open_new_user(qtbot, win)
    qtbot.keyClicks(dialog.given, "Sol")
    dialog.ok_button.click()
    qtbot.waitUntil(lambda: win.change is not None)
    ctrl = win.change
    assert len(ctrl.flow.plan.requests) == 1
    wait_for(qtbot, ctrl, PlanDialog).apply_button.click()
    wait_for(qtbot, ctrl, ResultDialog).accept()
    assert tenant.users["new-1"]["userPrincipalName"] == "sol@contoso.com"


# ---- which users are loaded -----------------------------------------------------------------------

def test_the_load_scope_filters_on_the_server_and_says_what_is_shown(qtbot, window):
    win = window()
    assert win.user_scope == "all" and win.count_label.text() == "8 users"
    win.scope_box.setCurrentIndex(win.scope_box.findData("guests"))
    qtbot.waitUntil(lambda: not win.loading and win.model.rowCount() == 1)
    assert win.count_label.text() == "1 user (guests only)" and win.session.graph.filters[-1] == "userType eq 'Guest'"
    win.scope_box.setCurrentIndex(win.scope_box.findData("synced"))
    qtbot.waitUntil(lambda: not win.loading and [u.id for u in win.model.users] == ["u-sync"])
    win.scope_box.setCurrentIndex(win.scope_box.findData("members"))
    qtbot.waitUntil(lambda: not win.loading and win.model.rowCount() == 7)
    assert all(u.user_type == "Member" for u in win.model.users)


def test_the_tenant_can_set_its_starting_scope(qtbot, runner):
    import dataclasses
    session = FakeSession()
    session.tenant = dataclasses.replace(session.tenant, user_scope="synced")
    win = MainWindow(session, runner, change_sleep=lambda s: None)
    qtbot.addWidget(win)
    win.load_directory()
    qtbot.waitUntil(lambda: not win.loading)
    assert win.user_scope == "synced" and [u.id for u in win.model.users] == ["u-sync"]


# ---- switching tenant ---------------------------------------------------------------------------------

def test_switch_tenant_closes_the_window_and_asks_the_app_to_sign_in_again(qtbot, window):
    win = window()
    assert not win.switch_requested
    win.switch_action.trigger()
    assert win.switch_requested and not win.isVisible() and win._closing


def test_switching_is_refused_while_a_change_is_running(qtbot, window, monkeypatch):
    said = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: said.append(a[2]))
    win = window()
    win.select_user("u-alice")
    win.toggle_action.trigger()
    qtbot.waitUntil(lambda: win.change is not None)
    ctrl = win.change
    win.switch_action.trigger()
    assert not win.switch_requested and win.isVisible() and "Finish the current change" in said[0]
    wait_for(qtbot, ctrl, PlanDialog).cancel_button.click()
    qtbot.waitUntil(lambda: win.change is None)


def test_the_app_signs_in_again_after_a_switch_and_ends_otherwise():
    from entra_auditor.gui.app import session_loop
    sessions, worked = iter(["contoso", "fabrikam", None]), []
    assert session_loop(lambda: next(sessions), lambda s: (worked.append(s), s == "contoso")[1]) == 0
    assert worked == ["contoso", "fabrikam"]                    # switched once, then closed normally
    assert session_loop(lambda: None, lambda s: False) == 1     # the first sign-in was cancelled
    sessions = iter(["contoso", None])
    assert session_loop(lambda: next(sessions), lambda s: True) == 0     # cancelled after a switch: just end


def test_hiding_external_users_reloads_without_them_and_says_so(qtbot, window):
    win = window()
    assert win.model.rowCount() == 8 and not win.hide_external_box.isChecked()
    win.hide_external_box.setChecked(True)
    qtbot.waitUntil(lambda: not win.loading and win.model.rowCount() == 7)
    assert not any("#EXT#" in (u.upn or "") for u in win.model.users)
    assert win.count_label.text() == "7 users (external hidden)"
    win.scope_box.setCurrentIndex(win.scope_box.findData("members"))
    qtbot.waitUntil(lambda: not win.loading and win.count_label.text() == "7 users (members only, external hidden)")
    win.hide_external_box.setChecked(False)
    qtbot.waitUntil(lambda: not win.loading and win.count_label.text() == "7 users (members only)")
