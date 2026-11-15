"""The Groups page against the permission-enforcing FakeTenant (not verified against a live tenant)."""

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QMessageBox  # noqa: E402

from entra_auditor.gui.change import ElevationDialog, JustificationDialog, PlanDialog, ResultDialog  # noqa: E402
from entra_auditor.gui.groups_page import MEMBERS, OWNERS, read_only_reason  # noqa: E402
from entra_auditor.gui.main_window import MainWindow  # noqa: E402
from entra_auditor.gui.pickers import PickerDialog  # noqa: E402
from entra_auditor.toolkit.directory import load_groups  # noqa: E402
from tests.fakes import FakeTenant, G  # noqa: E402
from tests.gui_support import FakeSession  # noqa: E402


def group_tenant(**kw):
    t = FakeTenant(**kw)
    t.groups["g-sec"] = G("g-sec", "Nested Sec", description="Second-line support")
    t.groups["g-dl"] = G("g-dl", "All Staff DL", mailEnabled=True, securityEnabled=False, mail="staff@contoso.com")
    t.members["g-fin"] = {"u-bob", "g-sec"}
    t.add_admin_unit("au-sea", "Seattle", members=("g-fin",))
    return t


@pytest.fixture
def window(qtbot, runner):
    def make(tenant=None):
        win = MainWindow(FakeSession(tenant or group_tenant()), runner, change_sleep=lambda s: None)
        qtbot.addWidget(win)
        win.show()
        win.load_directory()
        qtbot.waitUntil(lambda: not win.loading)
        return win
    return make


def open_group(qtbot, win, group_id="g-fin"):
    win.show_section("Groups")
    page = win.groups_page
    qtbot.waitUntil(lambda: page.loaded)
    assert page.select_group(group_id)
    qtbot.waitUntil(lambda: not page.loading_contents)
    return page


def wait_for(qtbot, holder, kind, attr="dialog"):
    qtbot.waitUntil(lambda: isinstance(getattr(holder, attr), kind), timeout=5000)
    return getattr(holder, attr)


def elevate_through(qtbot, ctrl, reason="INC-21"):
    wait_for(qtbot, ctrl, PlanDialog).apply_button.click()
    wait_for(qtbot, ctrl, ElevationDialog).activate_button.click()
    justification = wait_for(qtbot, ctrl, JustificationDialog)
    qtbot.keyClicks(justification.text, reason)
    justification.ok_button.click()
    return wait_for(qtbot, ctrl, ResultDialog)


# ---- the list ------------------------------------------------------------------------------------

def test_groups_load_when_the_page_is_first_opened_without_exchange_managed_ones(qtbot, window):
    win = window()
    assert not win.groups_page.loaded
    win.show_section("Groups")
    page = win.groups_page
    qtbot.waitUntil(lambda: page.loaded)
    assert page.group_names() == ["AD Group", "Dynamic IT", "Finance Share", "Nested Sec", "Project X", "Role Group"]
    assert page.groups_status.text() == "6 of 8 groups (2 Exchange-managed hidden)"
    page.show_exchange.setChecked(True)
    assert "All Staff DL" in page.group_names() and "Mail-Sec" in page.group_names()
    assert page.groups_status.text() == "8 groups"
    assert win.refresh_action.text() == "Reload" and not win.toggle_action.isVisible()


def test_the_list_filters_on_name_type_and_description(qtbot, window):
    win = window()
    page = open_group(qtbot, win)
    page.group_filter.setText("microsoft 365")
    assert page.group_names() == ["Project X"]
    page.group_filter.setText("second-line")
    assert page.group_names() == ["Nested Sec"]
    page.group_filter.setText("dynamic")
    assert page.group_names() == ["Dynamic IT"] and page.groups_status.text() == "1 of 8 groups"
    page.group_filter.setText("staff")                          # matches only a hidden Exchange group: say so
    assert page.group_names() == [] and "1 Exchange-managed hidden" in page.groups_status.text()


# ---- one group -------------------------------------------------------------------------------------

def test_selecting_a_group_shows_members_owners_properties_and_parents(qtbot, window):
    page = open_group(qtbot, window())
    assert page.people_names(MEMBERS) == ["Bob Stone", "Nested Sec"] and page.people_names(OWNERS) == ["Bob Stone"]
    assert [page.people_tabs.tabText(i) for i in range(2)] == ["Members (2)", "Owners (1)"]
    assert page.people_status.text() == "2 members"
    assert page.props["Type"].text() == "Security" and page.props["Source"].text() == "cloud"
    assert page.props["Changes"].text() == "members and owners can be changed here"
    assert page.parent_texts() == ["Administrative unit: Seattle"]
    page.people_tabs.setCurrentIndex(1)
    assert page.people_status.text() == "1 owner" and page.add_users_button.text() == "Add owners..."
    assert not page.add_groups_button.isVisible()


def test_members_can_be_filtered(qtbot, window):
    page = open_group(qtbot, window())
    page.people_filter.setText("group")
    assert page.people_names() == ["Nested Sec"] and page.people_status.text() == "1 of 2 shown"


@pytest.mark.parametrize("group_id, members, owners", [
    ("g-fin", "", ""),
    ("g-dyn", "Dynamic membership: members come from the rule.", ""),
    ("g-sync", "Synced from on-premises Active Directory: change it there.",
     "Synced from on-premises Active Directory: change it there."),
    ("g-mes", "Mail-enabled security groups are managed in Exchange; Graph can't change them.",
     "Mail-enabled security groups are managed in Exchange; Graph can't change them."),
])
def test_why_a_group_is_read_only(group_id, members, owners):
    group = next(g for g in load_groups(group_tenant()) if g.id == group_id)
    assert read_only_reason(group, MEMBERS) == members and read_only_reason(group, OWNERS) == owners


def test_a_dynamic_group_offers_no_membership_changes_but_its_owners_can_change(qtbot, window):
    page = open_group(qtbot, window(), "g-dyn")
    assert not page.add_users_button.isEnabled() and "rule" in page.add_users_button.toolTip()
    assert "Dynamic membership" in page.people_status.text() and "IT" in page.props["Rule"].text()
    assert page.props["Changes"].text().endswith("Owners can still be changed.")
    page.people_tabs.setCurrentIndex(1)
    assert page.add_users_button.isEnabled()


def test_a_microsoft_365_group_cannot_nest_groups(qtbot, window):
    page = open_group(qtbot, window(), "g-m365")
    assert page.add_users_button.isEnabled() and not page.add_groups_button.isEnabled()
    assert "only have users" in page.add_groups_button.toolTip()


def test_unreadable_members_say_so_and_offer_no_changes(qtbot, window):
    tenant = group_tenant()
    tenant.unreadable_groups.add("g-fin")
    page = open_group(qtbot, window(tenant))
    assert page.people_names() == [] and "Members couldn't be read" in page.people_status.text()
    assert page.people_tabs.tabText(0) == "Members (?)" and not page.add_users_button.isEnabled()


def test_double_clicking_opens_users_and_nested_groups(qtbot, window):
    win = window()
    page = open_group(qtbot, win)
    page._open_person(1, 0)                                     # the nested group opens here
    qtbot.waitUntil(lambda: page.group is not None and page.group.id == "g-sec" and not page.loading_contents)
    assert page.parent_texts() == ["Group: Finance Share"]
    page._open_parent(page.parents_list.item(0))                # and back up through "Member of"
    qtbot.waitUntil(lambda: page.group.id == "g-fin" and not page.loading_contents)
    page._open_person(0, 0)
    assert win.current_section == "Users" and win.selected_user().id == "u-bob"


def test_a_group_can_be_opened_before_the_page_has_loaded(qtbot, window):
    win = window()
    win.show_group("g-mes")                                     # hidden by default: the filter gives way
    page = win.groups_page
    qtbot.waitUntil(lambda: page.group is not None and page.group.id == "g-mes")
    assert win.current_section == "Groups" and page.show_exchange.isChecked()


# ---- changes -----------------------------------------------------------------------------------------

def test_adding_members_goes_through_preview_and_pim_elevation(qtbot, window):
    tenant = group_tenant()
    win = window(tenant)
    page = open_group(qtbot, win)
    page.add_users_button.click()
    picker = wait_for(qtbot, page, PickerDialog)
    assert not any("bob@contoso.com" in picker.list.item(i).text() for i in range(picker.list.count()))
    picker.select_texts("alice@contoso.com")
    picker.ok_button.click()
    result = elevate_through(qtbot, win.change)
    assert result.status_label.text().startswith("OK:") and "u-alice" in tenant.members["g-fin"]
    result.accept()
    qtbot.waitUntil(lambda: "Alice Ng" in page.people_names(MEMBERS))      # the group was re-read
    assert page.people_tabs.tabText(0) == "Members (3)"


def test_cancelling_the_preview_changes_nothing(qtbot, window):
    tenant = group_tenant()
    win = window(tenant)
    page = open_group(qtbot, win)
    page.tables[MEMBERS].selectRow(0)
    page.remove_button.click()
    plan = wait_for(qtbot, win.change, PlanDialog)
    assert win.change.flow.plan.details == ["- Bob Stone"] and plan.cancel_button.isDefault()
    plan.cancel_button.click()
    qtbot.waitUntil(lambda: win.change is None)
    assert tenant.writes == [] and tenant.members["g-fin"] == {"u-bob", "g-sec"}


def test_a_nested_group_can_be_added_and_removed(qtbot, window):
    tenant = group_tenant()
    tenant.active_roles["r"] = "Groups Administrator"
    tenant.groups["g-new"] = G("g-new", "New Sec")
    win = window(tenant)
    page = open_group(qtbot, win)
    page.add_groups_button.click()
    picker = wait_for(qtbot, page, PickerDialog)
    offered = [picker.list.item(i).text() for i in range(picker.list.count())]
    assert not any(t.startswith(("Project X", "Finance Share", "Nested Sec", "All Staff DL")) for t in offered)
    picker.select_texts("New Sec")
    picker.ok_button.click()
    wait_for(qtbot, win.change, PlanDialog).apply_button.click()
    wait_for(qtbot, win.change, ResultDialog).accept()
    qtbot.waitUntil(lambda: "New Sec" in page.people_names(MEMBERS))
    page.tables[MEMBERS].selectRow(page.people_names(MEMBERS).index("New Sec"))
    page.remove_button.click()
    wait_for(qtbot, win.change, PlanDialog).apply_button.click()
    wait_for(qtbot, win.change, ResultDialog).accept()
    qtbot.waitUntil(lambda: "New Sec" not in page.people_names(MEMBERS))
    assert "g-new" not in tenant.members["g-fin"]


def test_owners_are_added_and_removed_on_the_owners_tab(qtbot, window):
    tenant = group_tenant()
    tenant.active_roles["r"] = "Groups Administrator"
    win = window(tenant)
    page = open_group(qtbot, win)
    page.people_tabs.setCurrentIndex(1)
    page.add_users_button.click()
    picker = wait_for(qtbot, page, PickerDialog)
    picker.select_texts("alice@contoso.com")
    picker.ok_button.click()
    wait_for(qtbot, win.change, PlanDialog).apply_button.click()
    wait_for(qtbot, win.change, ResultDialog).accept()
    qtbot.waitUntil(lambda: page.people_names(OWNERS) == ["Alice Ng", "Bob Stone"])
    assert tenant.owners["g-fin"] == {"u-alice", "u-bob"} and tenant.members["g-fin"] == {"u-bob", "g-sec"}


def test_a_failed_load_says_so(qtbot, window, monkeypatch):
    win = window()
    win.groups_page._loader = lambda graph: (_ for _ in ()).throw(RuntimeError("boom"))
    win.show_section("Groups")
    qtbot.waitUntil(lambda: "Couldn't load groups: boom" in win.groups_page.groups_status.text())
    assert not win.groups_page.loaded
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)


def test_double_clicking_a_group_on_a_users_groups_tab_opens_it(qtbot, window):
    win = window()
    win.select_user("u-alice")
    qtbot.waitUntil(lambda: win.detail.profile is not None)
    member_of = win.detail.groups_tab.lists["Member of"]
    assert member_of.item(0).text() == "Project X (Microsoft 365)"
    member_of.itemDoubleClicked.emit(member_of.item(0))
    page = win.groups_page
    qtbot.waitUntil(lambda: page.group is not None and page.group.id == "g-m365" and not page.loading_contents)
    assert win.current_section == "Groups" and page.people_names(MEMBERS) == ["Alice Ng"]
