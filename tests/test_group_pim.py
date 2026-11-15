"""PIM for Groups (toolkit/group_pim.py) against the permission-enforcing FakeTenant."""

from datetime import datetime, timezone

import pytest

from entra_auditor.graph.client import GraphPermissionError
from entra_auditor.toolkit.group_pim import GroupAccess, GroupPimService
from entra_auditor.toolkit.pim import PimError
from tests.fakes import FakeGraph, FakeTenant

CLOCK = lambda: datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc)  # noqa: E731
ELIGIBLE = "/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances/filterByCurrentUser(on='principal')"


def tenant():
    return (FakeTenant(eligible=())
            .add_pim_group("g-uadm", "User Admins (PIM)", roles=["User Administrator"])
            .add_pim_group("g-ops", "Ops Owners", access="owner")
            .add_pim_group("g-read", "Readers", roles=["Global Reader"]))


def service(t):
    return GroupPimService(t, clock=CLOCK, sleep=lambda s: None)


def test_eligible_groups_come_with_their_names_and_the_roles_they_grant():
    eligible = service(tenant()).eligible()
    assert [(a.group_name, a.access, a.roles) for a in eligible] == [
        ("Ops Owners", "owner", ()), ("Readers", "member", ("Global Reader",)),
        ("User Admins (PIM)", "member", ("User Administrator",))]
    assert eligible[2].label == "User Admins (PIM) (member) - grants User Administrator"


def test_an_unreadable_group_name_falls_back_to_the_id():
    t = tenant()
    del t.groups["g-ops"]
    assert any(a.group_name == "g-ops" for a in service(t).eligible())


def test_activation_sends_the_documented_request_and_makes_the_membership_active():
    t = tenant()
    svc = service(t)
    target = next(a for a in svc.eligible() if a.group_id == "g-uadm")
    result = svc.activate(target, reason="  INC-7 reset  ", minutes=90)
    body = [w for w in t.writes if w[1] == "group-pim"][0][2]
    assert body == {"accessId": "member", "principalId": "u-me", "groupId": "g-uadm", "action": "selfActivate",
                    "justification": "INC-7 reset", "scheduleInfo": {
                        "startDateTime": "2026-10-06T08:00:00Z",
                        "expiration": {"type": "afterDuration", "duration": "PT1H30M"}}}
    assert result.active_now and svc.wait_until_active(target)
    assert [(a.group_id, a.activated) for a in svc.active()] == [("g-uadm", True)]


def test_an_activated_role_group_membership_unlocks_writes():
    t = tenant()
    with pytest.raises(GraphPermissionError):
        t.patch("/users/u-alice", {"jobTitle": "x"})
    svc = service(t)
    svc.activate(next(a for a in svc.eligible() if a.group_id == "g-uadm"), reason="x")
    t.patch("/users/u-alice", {"jobTitle": "x"})          # now allowed
    assert t.users["u-alice"]["jobTitle"] == "x"


def test_deactivation_ends_it():
    t = tenant()
    svc = service(t)
    target = next(a for a in svc.eligible() if a.group_id == "g-uadm")
    svc.activate(target, reason="x")
    svc.deactivate(target)
    assert svc.active() == []


@pytest.mark.parametrize("reason", ["", "   "])
def test_a_justification_is_required_before_anything_is_sent(reason):
    t = tenant()
    svc = service(t)
    with pytest.raises(PimError, match="justification"):
        svc.activate(svc.eligible()[0], reason=reason)
    assert not [w for w in t.writes if w[1] == "group-pim"]


def test_activating_something_you_are_not_eligible_for_is_explained():
    svc = service(tenant())
    stranger = GroupAccess("g-fin", "Finance Share", "member")
    with pytest.raises(PimError) as info:
        svc.activate(stranger, reason="x")
    assert "aren't allowed" in str(info.value) and "AzureADGroup" in info.value.hint


def test_missing_permissions_say_which_ones():
    graph = FakeGraph({ELIGIBLE: GraphPermissionError("403", status_code=403)})
    with pytest.raises(PimError) as info:
        GroupPimService(graph).eligible()
    assert "PrivilegedEligibilitySchedule.Read.AzureADGroup" in info.value.hint


def test_granting_picks_eligible_memberships_whose_group_holds_the_role():
    svc = service(tenant())
    eligible = svc.eligible()
    picks = GroupPimService.granting(eligible, ["Groups Administrator", "User Administrator"])
    assert [a.group_id for a in picks] == ["g-uadm"]
    assert GroupPimService.granting(eligible, ["Helpdesk Administrator"]) == []
    # ownership never grants a group's roles
    owner = GroupAccess("g-x", "X", "owner", roles=("User Administrator",))
    assert GroupPimService.granting([owner], ["User Administrator"]) == []
    # already active: not offered again
    active = [GroupAccess("g-uadm", "User Admins (PIM)", "member", "active")]
    assert GroupPimService.granting(eligible, ["User Administrator"], active) == []


def test_a_group_holding_a_role_for_one_unit_only_grants_it_inside_that_unit_only():
    au, other = "/administrativeUnits/au-1", "/administrativeUnits/au-2"
    scoped = GroupAccess("g-s", "Seattle Helpdesk", "member", roles=("User Administrator",),
                         role_scopes=(("User Administrator", au),))
    wide = GroupAccess("g-w", "User Admins", "member", roles=("User Administrator",),
                       role_scopes=(("User Administrator", "/"),))
    names = ["User Administrator"]
    assert GroupPimService.granting([scoped, wide], names, target_scopes=frozenset({"/", au})) == [scoped, wide]
    assert GroupPimService.granting([scoped, wide], names, target_scopes=frozenset({"/", other})) == [wide]
    assert GroupPimService.granting([scoped, wide], names, target_scopes=frozenset({"/"})) == [wide]
    assert GroupPimService.granting([scoped, wide], names, target_scopes=None) == [wide, scoped]   # unknown: last
    assert "one administrative unit only" in scoped.label and "only" not in wide.label
    # a group holding the role both ways grants it everywhere
    both = GroupAccess("g-b", "Both", "member", roles=("User Administrator",),
                       role_scopes=(("User Administrator", au), ("User Administrator", "/")))
    assert both.grants("User Administrator", frozenset({"/"})) is True and "only" not in both.label


def test_the_scope_of_a_groups_roles_is_read_with_the_roles():
    t = FakeTenant().add_admin_unit("au-1", "Seattle")
    t.add_pim_group("g-hd", "Seattle Helpdesk", roles=("User Administrator",), au="au-1")
    (access,) = GroupPimService(t, sleep=lambda s: None).eligible()
    assert access.roles == ("User Administrator",)
    assert access.role_scopes == (("User Administrator", "/administrativeUnits/au-1"),)
