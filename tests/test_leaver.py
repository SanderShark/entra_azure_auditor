"""The offboarding workflow: what it gathers, the one plan it builds, and how partial success is reported."""

from __future__ import annotations

import pytest

from entra_auditor.toolkit.actions import PlanError, execute_plan
from entra_auditor.toolkit.leaver import LeaverOptions, gather_leaver_facts, group_blocker, plan_leaver
from tests.fakes import FakeTenant, G

ALL = LeaverOptions(remove_ownerships=True)


def tenant():
    t = FakeTenant()
    t.groups["g-sec"] = G("g-sec", "Helpdesk Tools")
    t.members.update({"g-fin": {"u-bob", "u-alice"}, "g-sec": {"u-bob"}, "g-dyn": {"u-bob"}, "g-sync": {"u-bob"},
                      "g-mes": {"u-bob"}, "g-role": {"u-bob"}})
    t.owners["g-sec"] = {"u-bob"}
    t.add_admin_unit("au-sea", "Seattle", members=("u-bob",))
    t.add_admin_unit("au-dyn", "Contractors", members=("u-bob",), membershipType="Dynamic")
    t.add_sku("sku-e3", "SPE_E3").add_sku("sku-p1", "AAD_PREMIUM")
    t.give_licence("u-bob", "sku-e3").give_licence("u-bob", "sku-p1", group="g-fin")
    t.active_roles["r"] = "User Administrator"
    return t


def steps(plan):
    return [r.description for r in plan.requests]


def test_the_facts_cover_groups_units_ownerships_licences_and_roles():
    facts = gather_leaver_facts(tenant(), "u-bob")
    assert [g.label for g in facts.groups] == ["AD Group", "Dynamic IT", "Finance Share", "Helpdesk Tools", "Mail-Sec",
                                               "Role Group"]
    assert [g.label for g in facts.removable_groups] == ["Finance Share", "Helpdesk Tools", "Role Group"]
    assert [(u.name, u.dynamic) for u in facts.units] == [("Contractors", True), ("Seattle", False)]
    assert [g.label for g in facts.owned] == ["Finance Share", "Helpdesk Tools"]
    assert [lic.sku_id for lic in facts.direct_licences] == ["sku-e3"] and len(facts.licences) == 2
    assert facts.roles_active == [] and not facts.is_admin and facts.warnings == []


def test_why_a_membership_cannot_be_removed():
    groups = {g.id: g for g in gather_leaver_facts(tenant(), "u-bob").groups}
    assert group_blocker(groups["g-fin"]) == "" and group_blocker(groups["g-role"]) == ""
    assert group_blocker(groups["g-dyn"]) == "dynamic membership"
    assert group_blocker(groups["g-sync"]) == "synced from on-premises AD"
    assert group_blocker(groups["g-mes"]) == "managed in Exchange"


def test_the_plan_is_ordered_with_the_privileged_steps_last():
    plan = plan_leaver(gather_leaver_facts(tenant(), "u-bob"), ALL)
    assert steps(plan) == [
        "Disable account", "Revoke sign-in sessions", "Reset password", "Remove licences",
        "Remove from group Finance Share", "Remove from group Helpdesk Tools",
        "Remove as owner of Finance Share", "Remove as owner of Helpdesk Tools",
        "Remove from role-assignable group Role Group", "Remove from administrative unit Seattle"]
    assert plan.continue_on_error and plan.action == "user.offboard"
    assert plan.requests[3].json == {"addLicenses": [], "removeLicenses": ["sku-e3"]}
    said = " | ".join(plan.warnings)
    assert "AD Group (synced from on-premises AD), Dynamic IT (dynamic membership), Mail-Sec (managed in Exchange)" in said
    assert "dynamic administrative units (their rule decides): Contractors" in said
    assert "Not covered: the mailbox" in said
    assert "inherited from a group stay" not in said            # Finance Share goes, and its licence with it


def test_everything_selected_really_happens(tmp_path):
    t = tenant()
    result = execute_plan(t, plan_leaver(gather_leaver_facts(t, "u-bob"), ALL), log_path=tmp_path / "log", sleep=lambda s: None)
    assert result.status == "ok" and result.secrets["password"]
    assert t.users["u-bob"]["accountEnabled"] is False
    assert all("u-bob" not in t.members[g] for g in ("g-fin", "g-sec", "g-role"))
    assert "u-bob" in t.members["g-dyn"] and "u-bob" not in t.owners["g-sec"]
    assert "u-bob" not in t.au_members["au-sea"] and t.licences["u-bob"] == {"sku-p1": {"direct": False, "groups": ["g-fin"]}}
    logged = (tmp_path / "log").read_text()
    assert "user.offboard" in logged and result.secrets["password"] not in logged


def test_only_what_is_ticked_is_planned():
    facts = gather_leaver_facts(tenant(), "u-bob")
    plan = plan_leaver(facts, LeaverOptions(reset_password=False, remove_licences=False, remove_groups=False,
                                            remove_units=False))
    assert steps(plan) == ["Disable account", "Revoke sign-in sessions"]
    said = " | ".join(plan.warnings)
    assert "Still owns: Finance Share, Helpdesk Tools" in said          # ownerships are off by default
    assert "inherited from a group stay until that membership ends: Microsoft Entra ID P1" in said
    with pytest.raises(PlanError, match="Nothing to do"):
        plan_leaver(facts, LeaverOptions(disable=False, revoke_sessions=False, reset_password=False,
                                         remove_licences=False, remove_groups=False, remove_units=False))


def test_an_already_disabled_account_is_not_disabled_again_and_a_synced_one_keeps_its_password():
    t = tenant()
    t.users["u-bob"]["accountEnabled"] = False
    assert "Disable account" not in steps(plan_leaver(gather_leaver_facts(t, "u-bob"), ALL))
    plan = plan_leaver(gather_leaver_facts(t, "u-sync"), ALL)
    assert "Reset password" not in steps(plan) and "synced from on-premises AD; reset it there" in " ".join(plan.warnings)


def test_admin_roles_are_called_out_first_and_not_touched():
    t = tenant().add_role_holder("Helpdesk Administrator", "u-bob").add_role_holder("User Administrator", "u-bob", state="eligible")
    plan = plan_leaver(gather_leaver_facts(t, "u-bob"), ALL)
    assert plan.warnings[0].startswith("ADMIN ROLES ARE NOT REMOVED by this workflow: Helpdesk Administrator, "
                                       "User Administrator (eligible)")
    assert "may be refused" in " ".join(plan.warnings)
    assert not any("roleAssignments" in r.path for r in plan.requests)


def test_what_could_not_be_read_is_left_alone_and_said():
    t = tenant()
    t.memberof_denied = True
    facts = gather_leaver_facts(t, "u-bob")
    assert facts.groups is None and facts.units is None
    plan = plan_leaver(facts, ALL)
    assert not any("/members/" in r.path for r in plan.requests)
    assert "Group and unit memberships couldn't be read" in plan.warnings[0] and "left alone" in plan.warnings[0]


# ---- partial success ----------------------------------------------------------------------------

def test_a_refused_step_is_reported_and_the_rest_still_runs(tmp_path):
    t = tenant()
    t.refuse = [r"/administrativeUnits/", r"/groups/g-role/"]            # what needs Privileged Role Administrator
    result = execute_plan(t, plan_leaver(gather_leaver_facts(t, "u-bob"), ALL), log_path=tmp_path / "log", sleep=lambda s: None)
    assert result.status == "partial" and result.message.startswith("8 of 10 steps done; 2 could not be done")
    refused = [line for line in result.lines if "NOT PERMITTED" in line]
    assert [line.split(":")[0] for line in refused] == ["Remove from role-assignable group Role Group",
                                                        "Remove from administrative unit Seattle"]
    assert t.users["u-bob"]["accountEnabled"] is False and "u-bob" not in t.members["g-fin"]
    assert "u-bob" in t.au_members["au-sea"] and "u-bob" in t.members["g-role"]


def test_a_broken_step_in_the_middle_does_not_stop_the_ones_after_it(tmp_path):
    t = tenant()
    t.break_paths = [r"/assignLicense$"]
    result = execute_plan(t, plan_leaver(gather_leaver_facts(t, "u-bob"), ALL), log_path=tmp_path / "log", sleep=lambda s: None)
    assert result.status == "partial" and "Remove licences: FAILED" in " | ".join(result.lines)
    assert "u-bob" not in t.members["g-fin"] and "sku-e3" in t.licences["u-bob"]


def test_a_refusal_of_the_very_first_step_is_a_denial_so_elevation_is_offered(tmp_path):
    t = tenant()
    t.active_roles.clear()
    result = execute_plan(t, plan_leaver(gather_leaver_facts(t, "u-bob"), ALL), log_path=tmp_path / "log", sleep=lambda s: None)
    assert result.status == "denied" and t.users["u-bob"]["accountEnabled"] is True


def test_plans_without_the_flag_still_stop_at_the_first_failure(tmp_path):
    t = tenant()
    t.break_paths = [r"/assignLicense$"]
    plan = plan_leaver(gather_leaver_facts(t, "u-bob"), ALL)
    plan.continue_on_error = False
    result = execute_plan(t, plan, log_path=tmp_path / "log", sleep=lambda s: None)
    assert result.status == "partial" and "u-bob" in t.members["g-fin"]     # stopped before the groups
