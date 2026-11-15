"""Administrative units: reads (toolkit/admin_units.py) and change plans (toolkit/actions.py)."""

import pytest

from entra_auditor.graph.client import GraphError
from entra_auditor.toolkit import actions
from entra_auditor.toolkit.actions import PlanError, execute_plan
from entra_auditor.toolkit.admin_units import (
    AU_BASIC_SELECT,
    AdminUnit,
    AuMember,
    list_admin_units,
    list_members,
    scoped_roles,
)
from tests.fakes import G, FakeGraph, FakeTenant


def tenant(**kw):
    t = FakeTenant(eligible=("Privileged Role Administrator",), **kw)
    t.add_admin_unit("au-sea", "Seattle", members=["u-alice", "g-fin", "dev-1"], description="Seattle office")
    t.add_admin_unit("au-dyn", "Contractors", membershipType="Dynamic", membershipRule='user.userType -eq "Guest"',
                     membershipRuleProcessingState="On")
    t.add_admin_unit("au-vip", "Executives", isMemberManagementRestricted=True, visibility="HiddenMembership")
    t.au_roles += [("au-sea", "User Administrator", "u-bob", "active"),
                   ("au-sea", "Helpdesk Administrator", "u-alice", "eligible")]
    return t


# ---- reads ---------------------------------------------------------------------------------

def test_units_are_listed_by_name_with_their_settings():
    units, warnings = list_admin_units(tenant())
    assert [u.label for u in units] == ["Contractors", "Executives", "Seattle"] and warnings == []
    contractors, executives, seattle = units
    assert contractors.is_dynamic and contractors.badges == ["dynamic"]
    assert executives.restricted and executives.hidden and executives.badges == ["restricted", "hidden membership"]
    assert seattle.description == "Seattle office" and not seattle.is_dynamic


def test_if_the_full_settings_are_rejected_names_still_load_with_a_warning():
    def units(kw):
        if kw["select"] != AU_BASIC_SELECT:
            raise GraphError("Could not find a property named 'isMemberManagementRestricted'", status_code=400)
        return [{"id": "au1", "displayName": "Seattle"}]

    found, warnings = list_admin_units(FakeGraph({"/directory/administrativeUnits": units}))
    assert [u.label for u in found] == ["Seattle"] and found[0].restricted is None   # unknown, not False
    assert warnings and "names only" in warnings[0]


def test_members_are_users_then_groups_then_devices():
    members = list_members(tenant(), "au-sea")
    assert [(m.kind, m.label) for m in members] == [("user", "Alice Ng"), ("group", "Finance Share"),
                                                    ("device", "dev-1")]
    assert members[0].detail == "alice@contoso.com" and members[0].enabled is True
    assert members[2].detail == "Windows"


def test_scoped_roles_show_active_and_eligible_assignments_with_names():
    roles = scoped_roles(tenant(), "au-sea")
    assert [(r.role, r.principal_label) for r in roles.active] == [("User Administrator", "Bob Stone (bob@contoso.com)")]
    assert [(r.role, r.state) for r in roles.eligible] == [("Helpdesk Administrator", "eligible")]
    assert roles.warnings == []


def test_without_the_scope_filter_active_roles_come_from_scoped_role_members_and_eligible_is_unknown():
    t = tenant()
    t.au_scope_filter_supported = False
    roles = scoped_roles(t, "au-sea")
    assert [(r.role, r.principal_label) for r in roles.active] == [("User Administrator", "Bob Stone")]
    assert roles.eligible is None and "Eligible" in roles.warnings[0]


# ---- plans ---------------------------------------------------------------------------------

SEATTLE = AdminUnit(id="au-sea", display_name="Seattle")
DYNAMIC = AdminUnit(id="au-dyn", display_name="Contractors", membership_type="Dynamic", membership_rule="x")
RESTRICTED = AdminUnit(id="au-vip", display_name="Executives", restricted=True)
ALICE = AuMember(id="u-alice", kind="user", name="Alice Ng")
SEC_GROUP = AuMember(id="g-sec", kind="group", name="Sec", security_enabled=True, mail_enabled=False)
M365 = AuMember(id="g-m365", kind="group", name="Project X", security_enabled=False, mail_enabled=True, unified=True)


def test_adding_members_posts_one_reference_per_object():
    plan = actions.plan_add_au_members(SEATTLE, [ALICE, SEC_GROUP], "https://graph.microsoft.us/v1.0")
    assert [(r.method, r.path) for r in plan.requests] == [
        ("POST", "/directory/administrativeUnits/au-sea/members/$ref")] * 2
    assert plan.requests[0].json == {"@odata.id": "https://graph.microsoft.us/v1.0/directoryObjects/u-alice"}
    assert plan.suggested_roles == ("Privileged Role Administrator",) and plan.target_type == "administrative unit"


def test_a_dynamic_unit_refuses_manual_members_both_ways():
    with pytest.raises(PlanError, match="dynamic membership"):
        actions.plan_add_au_members(DYNAMIC, [ALICE])
    with pytest.raises(PlanError, match="dynamic membership"):
        actions.plan_remove_au_members(DYNAMIC, [ALICE])


def test_a_restricted_unit_takes_security_groups_but_not_m365_or_synced_groups():
    plan = actions.plan_add_au_members(RESTRICTED, [ALICE, SEC_GROUP])
    assert any("tenant-wide admins can no longer manage" in w for w in plan.warnings)
    with pytest.raises(PlanError, match="Project X"):
        actions.plan_add_au_members(RESTRICTED, [M365])
    synced = SEC_GROUP.model_copy(update={"synced": True, "name": "AD Group"})
    with pytest.raises(PlanError, match="AD Group"):
        actions.plan_add_au_members(RESTRICTED, [synced])


def test_removing_members_deletes_each_reference():
    plan = actions.plan_remove_au_members(SEATTLE, [ALICE])
    assert [(r.method, r.path) for r in plan.requests] == [
        ("DELETE", "/directory/administrativeUnits/au-sea/members/u-alice/$ref")]


def test_an_empty_selection_is_refused():
    with pytest.raises(PlanError):
        actions.plan_add_au_members(SEATTLE, [])
    with pytest.raises(PlanError):
        actions.plan_remove_au_members(SEATTLE, [])


def test_updating_settings_sends_only_what_changed():
    unit = AdminUnit(id="au-sea", display_name="Seattle", description="old")
    plan = actions.plan_update_admin_unit(unit, {"displayName": "Seattle", "description": "  new  "})
    assert plan.requests[0].json == {"description": "new"} and plan.details == ["description: 'old' -> 'new'"]


def test_nothing_to_change_is_refused():
    with pytest.raises(PlanError, match="Nothing to change"):
        actions.plan_update_admin_unit(SEATTLE, {"displayName": "Seattle"})


@pytest.mark.parametrize("changes, message", [
    ({"displayName": "  "}, "needs a name"),
    ({"displayName": "x" * 257}, "256"),
    ({"membershipType": "dynamic"}, "needs a membership rule"),
    ({"membershipType": "sometimes"}, "assigned or dynamic"),
    ({"membershipRuleProcessingState": "Off"}, "On or Paused"),
    ({"isMemberManagementRestricted": True}, "fixed when the unit is created"),
    ({"visibility": "Public"}, "can't be changed here"),
])
def test_invalid_settings_are_refused_with_a_reason(changes, message):
    with pytest.raises(PlanError, match=message):
        actions.plan_update_admin_unit(SEATTLE, changes)


def test_the_name_limit_boundary_is_256():
    assert actions.plan_update_admin_unit(SEATTLE, {"displayName": "x" * 256}).requests


def test_switching_to_dynamic_turns_processing_on_and_warns():
    plan = actions.plan_update_admin_unit(SEATTLE, {"membershipType": "Dynamic",
                                                    "membershipRule": 'user.department -eq "Sales"'})
    assert plan.requests[0].json == {"membershipType": "dynamic", "membershipRule": 'user.department -eq "Sales"',
                                     "membershipRuleProcessingState": "On"}
    assert any("replaces the current members" in w for w in plan.warnings)


def test_switching_back_to_assigned_warns_that_the_rule_stops():
    plan = actions.plan_update_admin_unit(DYNAMIC, {"membershipType": "assigned"})
    assert plan.requests[0].json == {"membershipType": "assigned"}
    assert any("stops the rule" in w for w in plan.warnings)


# ---- executing against the permission-enforcing fake --------------------------------------

def test_changes_are_denied_until_privileged_role_administrator_is_active(isolated_env):
    t = tenant()
    plan = actions.plan_add_au_members(SEATTLE, [AuMember(id="u-bob", kind="user", name="Bob")])
    assert execute_plan(t, plan, actor="me").status == "denied" and "u-bob" not in t.au_members["au-sea"]
    t.active_roles["r-privileged-role-administrator"] = "Privileged Role Administrator"
    assert execute_plan(t, plan, actor="me").status == "ok" and "u-bob" in t.au_members["au-sea"]


def test_the_fake_rejects_what_the_plans_guard_against():
    t = tenant()
    t.active_roles["r"] = "Privileged Role Administrator"
    t.groups["g-m365x"] = G("g-m365x", "M365", mailEnabled=True, groupTypes=["Unified"])
    with pytest.raises(GraphError):
        t.post("/directory/administrativeUnits/au-vip/members/$ref",
               {"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/g-m365x"})
    with pytest.raises(GraphError):
        t.post("/directory/administrativeUnits/au-dyn/members/$ref",
               {"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/u-bob"})
