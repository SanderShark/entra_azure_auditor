"""Onboarding: the template, the plan that creates a user from it, and how execution handles the new id."""

from __future__ import annotations

import json as jsonlib

import pytest

from entra_auditor.toolkit.actions import NEW_ID, PlanError, execute_plan
from entra_auditor.toolkit.onboarding import NewUser, OnboardOptions, gather_template, plan_onboard, suggest_upn
from tests.fakes import FakeTenant

PW = "Corr3ct-Horse-Battery!"


def tenant():
    t = FakeTenant()
    t.users["u-alice"].update(usageLocation="US", companyName="Contoso", officeLocation="SEA-2")
    t.managers["u-alice"] = "u-bob"
    t.members.update({"g-fin": {"u-alice"}, "g-dyn": {"u-alice"}, "g-role": {"u-alice"}, "g-m365": {"u-alice"}})
    t.add_sku("sku-e3", "SPE_E3", total=3).add_sku("sku-p1", "AAD_PREMIUM").add_sku("sku-full", "VISIOCLIENT", total=1)
    t.give_licence("u-alice", "sku-e3").give_licence("u-alice", "sku-full").give_licence("u-alice", "sku-p1", group="g-fin")
    t.active_roles["r"] = "User Administrator"
    return t


def new(**kw):
    return NewUser(**{"display_name": "Nia Novak", "upn": "nia.novak@contoso.com", "password": PW,
                      "given_name": "Nia", "surname": "Novak", **kw})


def run(t, plan, tmp_path):
    return execute_plan(t, plan, log_path=tmp_path / "log", sleep=lambda s: None)


def test_the_template_knows_what_can_be_copied():
    template = gather_template(tenant(), "u-alice")
    assert template.attributes == {"department": "IT", "jobTitle": "Engineer", "companyName": "Contoso",
                                   "officeLocation": "SEA-2", "usageLocation": "US"}
    assert (template.manager_id, template.manager_name) == ("u-bob", "Bob Stone")
    assert [g.label for g in template.copyable_groups] == ["Finance Share", "Project X"]     # not dynamic, not role
    assert [s.sku_id for s in template.copyable_licences] == ["sku-e3"]                    # Visio has none left
    assert template.domain == "contoso.com" and template.warnings == []


def test_a_sign_in_name_is_suggested_from_the_name():
    assert suggest_upn("Nia", "Novak", "contoso.com") == "nia.novak@contoso.com"
    assert suggest_upn(" José ", "O'Neil-Smith", "contoso.com") == "jos.o'neil-smith@contoso.com"
    assert suggest_upn("", "", "contoso.com") == "" and suggest_upn("Nia", "", "") == ""


def test_the_plan_creates_first_and_refers_to_the_new_user_by_placeholder():
    t = tenant()
    plan = plan_onboard(new(), gather_template(t, "u-alice"), base=t.base_url)
    assert [r.description for r in plan.requests] == ["Create user", "Set manager", "Assign licences",
                                                       "Add to group Finance Share", "Add to group Project X"]
    create = plan.requests[0]
    assert create.capture_id and (create.method, create.path) == ("POST", "/users")
    assert create.json["mailNickname"] == "nia.novak" and create.json["department"] == "IT"
    assert create.json["passwordProfile"] == {"password": PW, "forceChangePasswordNextSignIn": True}
    assert plan.requests[1].path == f"/users/{NEW_ID}/manager/$ref"
    assert plan.requests[3].json == {"@odata.id": f"{t.base_url}/directoryObjects/{NEW_ID}"}
    said = " | ".join(plan.warnings)
    assert "Not assigned (none left, or not assignable): Visio Plan 2 (VISIOCLIENT)" in said
    assert "Comes with group membership, not assigned directly: Microsoft Entra ID P1" in said
    assert "Groups not copied: Dynamic IT (dynamic membership), Role Group (role-assignable)" in said


def test_the_password_never_reaches_the_preview_or_the_log(tmp_path):
    t = tenant()
    plan = plan_onboard(new(), gather_template(t, "u-alice"), base=t.base_url)
    assert PW not in jsonlib.dumps(plan.log_requests()) and plan.requests[0].redacted_json()["passwordProfile"] == "********"
    assert PW not in " ".join(plan.details)
    assert run(t, plan, tmp_path).status == "ok"
    assert PW not in (tmp_path / "log").read_text() and "user.create" in (tmp_path / "log").read_text()


def test_executing_fills_in_the_new_id_everywhere(tmp_path):
    t = tenant()
    result = run(t, plan_onboard(new(), gather_template(t, "u-alice"), base=t.base_url), tmp_path)
    assert result.status == "ok" and t.created == ["new-1"]
    user = t.users["new-1"]
    assert user["userPrincipalName"] == "nia.novak@contoso.com" and user["usageLocation"] == "US"
    assert t.managers["new-1"] == "u-bob" and t.licences["new-1"] == {"sku-e3": {"direct": True, "groups": []}}
    assert "new-1" in t.members["g-fin"] and "new-1" in t.members["g-m365"] and "new-1" not in t.members["g-role"]
    assert not any(NEW_ID in str(w) for w in t.writes)


def test_a_new_user_that_is_not_known_everywhere_yet_is_retried(tmp_path):
    t = tenant()
    t.replication_misses = 3
    waits = []
    plan = plan_onboard(new(), gather_template(t, "u-alice"), base=t.base_url)
    result = execute_plan(t, plan, log_path=tmp_path / "log", sleep=waits.append)
    assert result.status == "ok" and waits == [3.0, 3.0, 3.0] and "new-1" in t.members["g-fin"]


def test_a_step_that_never_succeeds_is_reported_and_the_rest_continue(tmp_path):
    t = tenant()
    t.break_paths = [r"/manager/"]
    result = run(t, plan_onboard(new(), gather_template(t, "u-alice"), base=t.base_url), tmp_path)
    assert result.status == "partial" and "Set manager: FAILED" in " | ".join(result.lines)
    assert "new-1" in t.members["g-fin"] and "new-1" not in t.managers


def test_a_failed_creation_stops_everything(tmp_path):
    t = tenant()
    plan = plan_onboard(new(upn="alice@contoso.com"), gather_template(t, "u-alice"), base=t.base_url)   # taken
    result = run(t, plan, tmp_path)
    assert result.status == "failed" and "already exists" in result.message and t.created == []
    assert len([w for w in t.writes if w[0] != "pim"]) == 1            # nothing after the failed creation
    t.active_roles.clear()
    assert run(t, plan_onboard(new(), None), tmp_path).status == "denied"      # so PIM elevation is offered


def test_without_a_template_only_the_account_is_created(tmp_path):
    t = tenant()
    plan = plan_onboard(new(given_name=None, surname=" "))
    assert len(plan.requests) == 1 and "givenName" not in plan.requests[0].json and plan.warnings == []
    assert plan.target_type == "new user" and plan.suggested_roles[0] == "User Administrator"
    assert run(t, plan, tmp_path).status == "ok"


def test_options_switch_each_copy_off():
    template = gather_template(tenant(), "u-alice")
    plan = plan_onboard(new(), template, OnboardOptions(copy_attributes=False, copy_manager=False, copy_groups=False))
    assert [r.description for r in plan.requests] == ["Create user"]          # no usage location: no licences
    assert "department" not in plan.requests[0].json
    assert "Licences not copied: the new user has no usage location" in " | ".join(plan.warnings)
    plan = plan_onboard(new(), template, OnboardOptions(copy_licences=False, copy_groups=False))
    assert [r.description for r in plan.requests] == ["Create user", "Set manager"]


@pytest.mark.parametrize("change, message", [
    ({"display_name": "  "}, "needs a display name"),
    ({"upn": "nia novak@contoso.com"}, "must look like name@your-domain"),
    ({"upn": "nia.novak"}, "must look like name@your-domain"),
    ({"upn": "josé@contoso.com"}, "must look like name@your-domain"),
    ({"password": "short"}, "Password rejected"),
])
def test_bad_input_is_refused_before_anything_is_sent(change, message):
    with pytest.raises(PlanError, match=message):
        plan_onboard(new(**change))


def test_an_unreadable_part_of_the_template_is_not_copied_and_said():
    t = tenant()
    t.memberof_denied = True
    template = gather_template(t, "u-alice")
    assert template.groups is None and "groups couldn't be read" in template.warnings[0]
    plan = plan_onboard(new(), template, base=t.base_url)
    assert not any("/groups/" in r.path for r in plan.requests) and "won't be copied" in plan.warnings[0]
