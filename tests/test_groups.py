"""Group contents (toolkit/groups.py) and the nesting rules in the membership plans."""

from __future__ import annotations

import pytest

from entra_auditor.graph.client import GraphAuthError
from entra_auditor.toolkit import actions
from entra_auditor.toolkit.actions import PlanError, execute_plan
from entra_auditor.toolkit.directory import load_groups
from entra_auditor.toolkit.groups import GroupPerson, load_group_contents, load_group_people
from tests.fakes import FakeTenant, G


def tenant():
    t = FakeTenant()
    t.groups["g-sec"] = G("g-sec", "Nested Sec")
    t.members["g-fin"] = {"u-bob", "u-alice", "g-sec", "dev-1"}
    t.add_admin_unit("au-sea", "Seattle", members=("g-sec",))
    return t


def group(t, gid):
    return next(g for g in load_groups(t) if g.id == gid)


def test_members_are_typed_and_sorted_users_first():
    contents = load_group_contents(tenant(), "g-fin")
    assert [(p.kind, p.label) for p in contents.members] == [
        ("user", "Alice Ng"), ("user", "Bob Stone"), ("group", "Nested Sec"), ("device", "SEA-LT-001")]
    assert contents.members[0].detail == "alice@contoso.com" and contents.members[0].enabled is True
    assert [p.label for p in contents.owners] == ["Bob Stone"] and not contents.members_truncated


def test_what_a_group_belongs_to_includes_groups_and_administrative_units():
    contents = load_group_contents(tenant(), "g-sec")
    assert [(p.kind, p.label) for p in contents.parents] == [("group", "Finance Share"), ("unit", "Seattle")]
    assert load_group_contents(tenant(), "g-dyn").parents == []


def test_a_long_member_list_is_cut_off_and_says_so():
    t = tenant()
    people, truncated = load_group_people(t, "g-fin", "members", limit=4)
    assert len(people) == 4 and not truncated                      # exactly the limit: nothing was cut
    people, truncated = load_group_people(t, "g-fin", "members", limit=3)
    assert len(people) == 3 and truncated
    with pytest.raises(ValueError):
        load_group_people(t, "g-fin", "guests")


def test_an_unreadable_part_is_unknown_with_its_reason_and_auth_failures_abort():
    t = tenant()
    t.unreadable_groups.add("g-fin")
    contents = load_group_contents(t, "g-fin")
    assert contents.members is None and contents.owners is None and "Authorization_RequestDenied" in contents.members_error
    assert contents.parents == []                                   # the part that could be read still is
    t.get_paged = lambda *a, **k: (_ for _ in ()).throw(GraphAuthError("401", status_code=401))
    with pytest.raises(GraphAuthError):
        load_group_contents(t, "g-fin")


# ---- nesting ---------------------------------------------------------------------------------

def test_a_security_group_can_be_nested_in_a_security_group(tmp_path):
    t = tenant()
    t.active_roles["r"] = "Groups Administrator"
    t.groups["g-new"] = G("g-new", "New Sec")
    plan = actions.plan_add_group_members(group(t, "g-fin"), [group(t, "g-new")], t.base_url)
    assert plan.details == ["+ New Sec"] and execute_plan(t, plan, log_path=tmp_path / "log").status == "ok"
    assert "g-new" in t.members["g-fin"]


def test_a_microsoft_365_group_takes_users_only_and_cannot_itself_be_nested():
    t = tenant()
    with pytest.raises(PlanError, match="can only have users as members"):
        actions.plan_add_group_members(group(t, "g-m365"), [group(t, "g-sec")])
    with pytest.raises(PlanError, match="can't be members of another group: Project X"):
        actions.plan_add_group_members(group(t, "g-fin"), [group(t, "g-m365")])
    with pytest.raises(PlanError, match="member of itself"):
        actions.plan_add_group_members(group(t, "g-fin"), [group(t, "g-fin")])
    # a member row from the page (not a GroupSummary) is recognised as a group too
    with pytest.raises(PlanError, match="users as members"):
        actions.plan_add_group_members(group(t, "g-m365"), [GroupPerson(id="g-sec", kind="group", name="Nested Sec")])


def test_the_fake_rejects_what_entra_rejects(tmp_path):
    from entra_auditor.graph.client import GraphError
    t = tenant()
    t.active_roles["r"] = "Groups Administrator"
    with pytest.raises(GraphError):
        t.post("/groups/g-m365/members/$ref", {"@odata.id": f"{t.base_url}/directoryObjects/g-sec"})


def test_any_kind_of_member_can_be_removed(tmp_path):
    t = tenant()
    t.active_roles["r"] = "Groups Administrator"
    members = load_group_contents(t, "g-fin").members
    plan = actions.plan_remove_group_members(group(t, "g-fin"), [m for m in members if m.kind != "user"])
    assert plan.details == ["- Nested Sec", "- SEA-LT-001"]
    assert execute_plan(t, plan, log_path=tmp_path / "log").status == "ok" and t.members["g-fin"] == {"u-bob", "u-alice"}
