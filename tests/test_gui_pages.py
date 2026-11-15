"""The Administrative units and Roles / PIM pages, against the permission-enforcing FakeTenant.
Both are tested against the fake only; neither is verified against a live tenant yet."""

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QMessageBox  # noqa: E402

from entra_auditor.gui.admin_units_page import EditUnitDialog  # noqa: E402
from entra_auditor.gui.change import ElevationDialog, JustificationDialog, PlanDialog, ResultDialog  # noqa: E402
from entra_auditor.gui.main_window import MainWindow  # noqa: E402
from entra_auditor.gui.pickers import PickerDialog  # noqa: E402
from entra_auditor.gui.roles_page import ActivateDialog  # noqa: E402
from tests.fakes import FakeTenant  # noqa: E402
from tests.gui_support import FakeSession  # noqa: E402


def au_tenant(**kw):
    t = FakeTenant(eligible=("Privileged Role Administrator",), **kw)
    t.add_admin_unit("au-sea", "Seattle", members=["u-alice", "g-fin", "dev-1"], description="Seattle office")
    t.add_admin_unit("au-dyn", "Contractors", membershipType="Dynamic", membershipRule='user.userType -eq "Guest"',
                     membershipRuleProcessingState="On")
    t.add_admin_unit("au-vip", "Executives", isMemberManagementRestricted=True)
    t.au_roles += [("au-sea", "User Administrator", "u-bob", "active"),
                   ("au-sea", "Helpdesk Administrator", "u-alice", "eligible")]
    return t


@pytest.fixture
def window(qtbot, runner):
    def make(tenant=None):
        win = MainWindow(FakeSession(tenant), runner, change_sleep=lambda s: None)
        qtbot.addWidget(win)
        win.show()
        win.load_directory()
        qtbot.waitUntil(lambda: not win.loading)
        return win
    return make


def open_units(qtbot, win, unit_id="au-sea"):
    win.show_section("Administrative units")
    page = win.admin_units_page
    qtbot.waitUntil(lambda: page.loaded)
    assert page.select_unit(unit_id)
    qtbot.waitUntil(lambda: not page.loading_contents)
    return page


def wait_for(qtbot, holder, kind, attr="dialog"):
    qtbot.waitUntil(lambda: isinstance(getattr(holder, attr), kind), timeout=5000)
    return getattr(holder, attr)


def elevate_through(qtbot, ctrl, reason="INC-11"):
    """Preview -> apply -> PIM role -> justification -> result."""
    wait_for(qtbot, ctrl, PlanDialog).apply_button.click()
    wait_for(qtbot, ctrl, ElevationDialog).activate_button.click()
    justification = wait_for(qtbot, ctrl, JustificationDialog)
    qtbot.keyClicks(justification.text, reason)
    justification.ok_button.click()
    return wait_for(qtbot, ctrl, ResultDialog)


# ---- administrative units ---------------------------------------------------------------------

def test_units_load_when_the_page_is_first_opened(qtbot, window):
    win = window(au_tenant())
    assert not win.admin_units_page.loaded                     # not before it is shown
    win.show_section("Administrative units")
    page = win.admin_units_page
    qtbot.waitUntil(lambda: page.loaded)
    assert page.unit_texts() == ["Contractors  [dynamic]", "Executives  [restricted]", "Seattle"]
    assert page.node_texts("au-sea") == ["Users", "Groups", "Devices"]            # no counts until it is opened
    assert win.refresh_action.text() == "Reload" and not win.toggle_action.isVisible()


def test_selecting_a_unit_shows_its_members_settings_and_roles(qtbot, window):
    page = open_units(qtbot, window(au_tenant()))
    assert page.member_names() == ["Alice Ng", "Finance Share", "SEA-LT-001"]
    assert page.member_status.text() == "1 user, 1 group, 1 device"
    assert page.props["Description"].text() == "Seattle office" and page.props["Membership"].text() == "assigned"
    assert page.roles_texts() == [("User Administrator", "Bob Stone (bob@contoso.com)", "active"),
                                  ("Helpdesk Administrator", "Alice Ng (alice@contoso.com)", "eligible (PIM)")]


def test_a_dynamic_unit_shows_its_rule_and_offers_no_manual_membership(qtbot, window):
    page = open_units(qtbot, window(au_tenant()), "au-dyn")
    assert page.props["Membership"].text() == "dynamic" and "Guest" in page.props["Rule"].text()
    assert not page.add_users_button.isEnabled() and not page.add_groups_button.isEnabled()
    assert page.edit_button.isEnabled()


def test_members_can_be_filtered(qtbot, window):
    page = open_units(qtbot, window(au_tenant()))
    page.member_filter.setText("finance")
    assert page.member_names() == ["Finance Share"] and page.member_status.text().startswith("1 of 3 shown")


def test_double_clicking_a_user_opens_it_on_the_users_page(qtbot, window):
    win = window(au_tenant())
    page = open_units(qtbot, win)
    page._open_member(0, 1)
    assert win.current_section == "Users" and win.selected_user().id == "u-alice"


def test_adding_users_goes_through_preview_and_pim_elevation(qtbot, window):
    tenant = au_tenant()
    win = window(tenant)
    page = open_units(qtbot, win)
    page.add_users_button.click()
    picker = wait_for(qtbot, page, PickerDialog)
    assert not any("alice@contoso.com" in picker.list.item(i).text() for i in range(picker.list.count()))
    picker.filter_edit.setText("bob stone")
    picker.select_texts("Bob Stone")
    picker.ok_button.click()
    result = elevate_through(qtbot, win.change)
    assert result.status_label.text().startswith("OK:") and "u-bob" in tenant.au_members["au-sea"]
    pim = [w for w in tenant.writes if w[1] == "pim"][0][2]
    assert pim["roleDefinitionId"] == "r-privileged-role-administrator"
    result.accept()
    qtbot.waitUntil(lambda: "Bob Stone" in page.member_names())      # the unit was re-read


def test_adding_groups_loads_the_group_list_once(qtbot, window):
    tenant = au_tenant()
    tenant.active_roles["r"] = "Privileged Role Administrator"
    win = window(tenant)
    page = open_units(qtbot, win)
    page.add_groups_button.click()
    picker = wait_for(qtbot, page, PickerDialog)
    picker.select_texts("Role Group")
    picker.ok_button.click()
    ctrl = win.change
    wait_for(qtbot, ctrl, PlanDialog).apply_button.click()
    assert wait_for(qtbot, ctrl, ResultDialog).status_label.text().startswith("OK:")
    assert "g-role" in tenant.au_members["au-sea"]
    assert sum(1 for c in tenant.calls if c == ("GET", "/groups")) == 1


def test_a_restricted_unit_refuses_a_microsoft_365_group_before_sending(qtbot, window, monkeypatch):
    explained = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: explained.append(a[2]))
    tenant = au_tenant()
    win = window(tenant)
    page = open_units(qtbot, win, "au-vip")
    page.add_groups_button.click()
    picker = wait_for(qtbot, page, PickerDialog)
    picker.select_texts("Project X")
    picker.ok_button.click()
    qtbot.waitUntil(lambda: bool(explained))
    assert "restricted management" in explained[0] and win.change is None
    assert not [w for w in tenant.writes if "administrativeUnits" in w[1]]


def test_removing_a_member(qtbot, window):
    tenant = au_tenant()
    tenant.active_roles["r"] = "Privileged Role Administrator"
    win = window(tenant)
    page = open_units(qtbot, win)
    page.member_table.selectRow(2)                               # SEA-LT-001 (object id dev-1)
    page.remove_button.click()
    ctrl = win.change
    plan = wait_for(qtbot, ctrl, PlanDialog)
    assert plan.requests.item(0, 0).text() == "DELETE" and "dev-1" in plan.requests.item(0, 1).text()
    plan.apply_button.click()
    wait_for(qtbot, ctrl, ResultDialog).accept()
    qtbot.waitUntil(lambda: page.member_names() == ["Alice Ng", "Finance Share"])


def test_adding_devices_lists_os_and_join_type_and_sends_object_ids(qtbot, window):
    tenant = au_tenant()
    tenant.active_roles["r"] = "Privileged Role Administrator"
    win = window(tenant)
    page = open_units(qtbot, win)
    page.add_devices_button.click()
    picker = wait_for(qtbot, page, PickerDialog)
    texts = [picker.list.item(i).text() for i in range(picker.list.count())]
    assert texts == ["OLD-PC  -  Windows 10.0.19045, hybrid joined, disabled", "Pixel 8  -  Android 15, registered"]
    picker.filter_edit.setText("android")
    picker.select_texts("Pixel 8")
    picker.ok_button.click()
    ctrl = win.change
    plan = wait_for(qtbot, ctrl, PlanDialog)
    assert "directoryObjects/dev-2" in plan.requests.item(0, 2).text()
    plan.apply_button.click()
    wait_for(qtbot, ctrl, ResultDialog).accept()
    assert "dev-2" in tenant.au_members["au-sea"]
    qtbot.waitUntil(lambda: "Pixel 8" in page.member_names())
    assert sum(1 for c in tenant.calls if c == ("GET", "/devices")) == 1


def test_editing_settings_sends_only_the_change(qtbot, window):
    tenant = au_tenant()
    tenant.active_roles["r"] = "Privileged Role Administrator"
    win = window(tenant)
    page = open_units(qtbot, win)
    page.edit_button.click()
    dialog = wait_for(qtbot, page, EditUnitDialog)
    assert not dialog.rule.isEnabled()                          # assigned: no rule to edit
    dialog.description.setText("Seattle and Tacoma offices")
    dialog.accept()
    ctrl = win.change
    plan = wait_for(qtbot, ctrl, PlanDialog)
    assert "Seattle and Tacoma" in plan.requests.item(0, 2).text() and "displayName" not in plan.requests.item(0, 2).text()
    plan.apply_button.click()
    wait_for(qtbot, ctrl, ResultDialog).accept()
    assert tenant.admin_units["au-sea"]["description"] == "Seattle and Tacoma offices"
    qtbot.waitUntil(lambda: page.props["Description"].text() == "Seattle and Tacoma offices")


def test_hidden_membership_that_cannot_be_read_says_why(qtbot, window):
    from entra_auditor.graph.client import GraphPermissionError

    tenant = au_tenant()
    tenant.add_admin_unit("au-hid", "Board", visibility="HiddenMembership")
    original = tenant.get_paged

    def get_paged(path, **kw):
        if path.endswith("/au-hid/members"):
            raise GraphPermissionError("Insufficient privileges", status_code=403)
        return original(path, **kw)

    tenant.get_paged = get_paged
    page = open_units(qtbot, window(tenant), "au-hid")
    assert "couldn't be read" in page.member_status.text() and "Member.Read.Hidden" in page.member_status.text()
    assert not page.add_users_button.isEnabled()               # unknown members: no blind adds


# ---- roles / PIM ---------------------------------------------------------------------------------

def pim_tenant():
    tenant = FakeTenant().add_pim_group("g-uadm", "User Admins (PIM)", roles=["User Administrator"])
    tenant.active_roles["r-global-reader"] = "Global Reader"
    return tenant


def open_roles(qtbot, win):
    win.show_section("Roles / PIM")
    page = win.roles_page
    qtbot.waitUntil(lambda: page.loaded)
    return page


def table_texts(table):
    return [[table.item(r, c).text() if table.item(r, c) else "" for c in range(table.columnCount())]
            for r in range(table.rowCount())]


def test_the_roles_page_lists_roles_and_pim_groups(qtbot, window):
    page = open_roles(qtbot, window(pim_tenant()))
    roles = table_texts(page.roles_table)
    assert ["Global Reader", "active (activated)"] == roles[0][:2]
    assert ["Groups Administrator", "eligible"] == roles[1][:2]
    assert table_texts(page.groups_table)[0][:4] == ["User Admins (PIM)", "member", "eligible", "User Administrator"]


def test_activating_a_pim_group_from_the_roles_page(qtbot, window):
    tenant = pim_tenant()
    win = window(tenant)
    page = open_roles(qtbot, win)
    assert page.select("group", "User Admins")
    assert page.activate_button.isEnabled() and not page.deactivate_button.isEnabled()
    page.activate_button.click()
    dialog = wait_for(qtbot, page, ActivateDialog)
    dialog.minutes.setValue(120)
    assert not dialog.ok_button.isEnabled()
    qtbot.keyClicks(dialog.text, "INC-20")
    dialog.ok_button.click()
    qtbot.waitUntil(lambda: "active for 120 minutes" in page.message.text())
    body = [w for w in tenant.writes if w[1] == "group-pim"][0][2]
    assert body["scheduleInfo"]["expiration"]["duration"] == "PT2H" and body["justification"] == "INC-20"
    qtbot.waitUntil(lambda: table_texts(page.groups_table)[0][2] == "active (activated)")
    assert win.session.provider.refreshes >= 1


def test_deactivating_an_activated_role_asks_first(qtbot, window, monkeypatch):
    tenant = pim_tenant()
    win = window(tenant)
    page = open_roles(qtbot, win)
    page.select("role", "Global Reader")
    assert page.deactivate_button.isEnabled()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    page.deactivate_button.click()
    assert "r-global-reader" in tenant.active_roles                # "No" changes nothing
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    page.deactivate_button.click()
    qtbot.waitUntil(lambda: "was deactivated" in page.message.text())
    assert "r-global-reader" not in tenant.active_roles


def test_missing_group_pim_permissions_are_explained_and_roles_still_show(qtbot, window):
    from entra_auditor.graph.client import GraphPermissionError

    tenant = pim_tenant()
    original = tenant.get_paged

    def get_paged(path, **kw):
        if path.startswith("/identityGovernance"):
            raise GraphPermissionError("403", status_code=403)
        return original(path, **kw)

    tenant.get_paged = get_paged
    page = open_roles(qtbot, window(tenant))
    assert "PrivilegedEligibilitySchedule.Read.AzureADGroup" in page.groups_error.text()
    assert page.groups_table.rowCount() == 0                     # not "you have none": it is unknown
    assert table_texts(page.roles_table)[0][0] == "Global Reader"


def test_the_preview_shows_every_change_and_the_whole_body(qtbot, runner):
    """A confirmation screen must not hide part of what will be sent."""
    from entra_auditor.toolkit.actions import plan_update_admin_unit
    from entra_auditor.toolkit.admin_units import AdminUnit

    plan = plan_update_admin_unit(AdminUnit(id="au-sea", display_name="Seattle"), {
        "membershipType": "dynamic", "membershipRule": 'user.department -eq "Sales"' + " or x" * 20})
    dialog = PlanDialog(plan)
    qtbot.addWidget(dialog)
    dialog.show()
    qtbot.wait(50)
    body = dialog.requests.item(0, 2)
    assert "membershipRuleProcessingState" in body.text()            # the full text is in the cell...
    assert dialog.requests.rowHeight(0) >= dialog.requests.sizeHintForRow(0)   # ...and the row shows all of it
    details = [w for w in dialog.findChildren(type(dialog.warnings[0])) if "membershipRuleProcessingState" in w.text()]
    assert details and details[0].isVisible() and details[0].height() >= details[0].heightForWidth(details[0].width())


# ---- the unit tree ------------------------------------------------------------------------------------

def test_a_unit_expands_to_users_groups_and_devices_with_counts(qtbot, window):
    tenant = au_tenant()
    page = open_units(qtbot, window(tenant))
    assert page.node_texts("au-sea") == ["Users (1)", "Groups (1)", "Devices (1)"]
    assert page.node_texts("au-vip") == ["Users", "Groups", "Devices"]            # other units aren't loaded for this
    calls = len(tenant.calls)
    assert page.select_unit("au-sea", "group")
    assert page.member_names() == ["Finance Share"] and page.member_status.text().startswith("Groups only: 1 of 3 shown")
    assert page.select_unit("au-sea", "device") and page.member_names() == ["SEA-LT-001"]
    assert page.select_unit("au-sea", "user") and page.member_names() == ["Alice Ng"]
    assert page.select_unit("au-sea") and page.member_names() == ["Alice Ng", "Finance Share", "SEA-LT-001"]
    assert len(tenant.calls) == calls                                             # moving between nodes reads nothing
    assert page.add_users_button.isEnabled() and page.unit.id == "au-sea"


def test_a_node_filter_combines_with_the_text_filter_and_follows_to_another_unit(qtbot, window):
    tenant = au_tenant()
    tenant.au_members["au-vip"] = {"u-bob", "dev-2"}
    page = open_units(qtbot, window(tenant))
    page.select_unit("au-sea", "user")
    page.member_filter.setText("finance")
    assert page.member_names() == []                                              # the group matches, but only users show
    page.member_filter.clear()
    assert page.select_unit("au-vip", "device")
    qtbot.waitUntil(lambda: not page.loading_contents and page.unit.id == "au-vip")
    assert page.member_names() == ["Pixel 8"] and page.node_texts("au-vip") == ["Users (1)", "Groups (0)", "Devices (1)"]


def test_the_node_stays_selected_and_its_count_updates_after_a_change(qtbot, window):
    tenant = au_tenant()
    tenant.active_roles["r"] = "Privileged Role Administrator"
    win = window(tenant)
    page = open_units(qtbot, win)
    page.select_unit("au-sea", "user")
    page.add_users_button.click()
    picker = wait_for(qtbot, page, PickerDialog)
    picker.select_texts("Bob Stone")
    picker.ok_button.click()
    wait_for(qtbot, win.change, PlanDialog).apply_button.click()
    wait_for(qtbot, win.change, ResultDialog).accept()
    qtbot.waitUntil(lambda: page.node_texts("au-sea")[0] == "Users (2)")
    assert page.kind_filter == "user" and page.member_names() == ["Alice Ng", "Bob Stone"]


def test_double_clicking_a_group_member_opens_the_groups_page(qtbot, window):
    win = window(au_tenant())
    page = open_units(qtbot, win)
    page._open_member(1, 1)
    groups = win.groups_page
    qtbot.waitUntil(lambda: groups.group is not None and groups.group.id == "g-fin")
    assert win.current_section == "Groups"
