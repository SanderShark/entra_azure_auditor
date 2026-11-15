from datetime import datetime, timezone

import pytest

from entra_auditor.toolkit import actions
from entra_auditor.toolkit.pim import PimError, PimRole, PimService, iso_duration
from tests.fakes import FakeTenant

CLOCK = lambda: datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)  # noqa: E731


def service(tenant):
    return PimService(tenant, clock=CLOCK, sleep=lambda s: None)


def test_eligible_roles_are_parsed_and_sorted(tenant):
    assert [r.name for r in service(tenant).eligible()] == ["Global Reader", "Groups Administrator", "User Administrator"]
    assert service(tenant).active() == []


@pytest.mark.parametrize("minutes,expected", [(60, "PT1H"), (90, "PT1H30M"), (30, "PT30M"), (1440, "PT24H")])
def test_iso_durations(minutes, expected):
    assert iso_duration(minutes) == expected


@pytest.mark.parametrize("minutes", [0, -5, 1441])
def test_durations_outside_a_day_are_rejected(minutes):
    with pytest.raises(PimError):
        iso_duration(minutes)


def test_find_by_exact_name_partial_name_and_errors(tenant):
    roles = service(tenant).eligible()
    assert PimService.find(roles, "Global Reader").name == "Global Reader"
    assert PimService.find(roles, "user adm").name == "User Administrator"
    with pytest.raises(PimError, match="several"):
        PimService.find(roles, "administrator")
    with pytest.raises(PimError, match="No role"):
        PimService.find(roles, "wizard")


def test_match_picks_eligible_roles_for_a_plan_in_preference_order(tenant):
    roles = service(tenant).eligible()
    assert [r.name for r in PimService.match(roles, actions.ROLES_GROUP_MEMBERS)] == ["Groups Administrator", "User Administrator"]


def test_roles_already_active_are_not_offered_again(tenant):
    pim = service(tenant)
    pim.activate(PimService.find(pim.eligible(), "Groups Administrator"), reason="x")
    assert PimService.match(pim.eligible(), ("Groups Administrator",), active=pim.active()) == []


def test_activation_request_is_built_correctly(tenant):
    pim = service(tenant)
    result = pim.activate(PimService.find(pim.eligible(), "Groups Administrator"), reason="INC-123: fix group", minutes=90,
                          ticket_number="INC-123", ticket_system="ServiceNow")
    body = [w for w in tenant.writes if w[1] == "pim"][-1][2]
    assert body["action"] == "selfActivate" and body["principalId"] == "u-me"
    assert body["roleDefinitionId"] == "r-groups-administrator" and body["directoryScopeId"] == "/"
    assert body["justification"] == "INC-123: fix group"
    assert body["scheduleInfo"] == {"startDateTime": "2026-10-06T12:00:00Z",
                                    "expiration": {"type": "afterDuration", "duration": "PT1H30M"}}
    assert body["ticketInfo"] == {"ticketNumber": "INC-123", "ticketSystem": "ServiceNow"}
    assert result.active_now and not result.pending_approval


def test_activated_roles_show_as_active_and_can_be_awaited(tenant):
    pim = service(tenant)
    role = PimService.find(pim.eligible(), "User Administrator")
    pim.activate(role, reason="x")
    assert pim.wait_until_active(role.role_id, timeout=5)
    assert [(r.name, r.activated) for r in pim.active()] == [("User Administrator", True)]


def test_waiting_gives_up_when_the_role_never_appears(tenant):
    assert not service(tenant).wait_until_active("r-never", timeout=0)


def test_deactivation(tenant):
    pim = service(tenant)
    role = PimService.find(pim.eligible(), "User Administrator")
    pim.activate(role, reason="x")
    assert pim.deactivate(role).status == "Revoked" and pim.active() == []


def test_a_blank_justification_is_refused_locally(tenant):
    pim = service(tenant)
    with pytest.raises(PimError, match="justification"):
        pim.activate(PimService.find(pim.eligible(), "User Administrator"), reason="   ")
    assert not [w for w in tenant.writes if w[1] == "pim"]


def test_mfa_policy_failures_get_actionable_advice():
    tenant = FakeTenant(require_mfa={"Global Reader"})
    pim = service(tenant)
    with pytest.raises(PimError) as info:
        pim.activate(PimService.find(pim.eligible(), "Global Reader"), reason="x")
    assert "multifactor" in str(info.value).lower() and "login --mode browser" in info.value.hint


def test_not_eligible_is_explained():
    tenant = FakeTenant(eligible=("User Administrator",))
    pim = service(tenant)
    role = PimService.find(pim.eligible(), "User Administrator")
    tenant.eligible_names.clear()                      # eligibility was removed meanwhile
    with pytest.raises(PimError, match="aren't allowed"):
        pim.activate(role, reason="x")


# ---- roles scoped to an administrative unit ------------------------------------------------

AU = "/administrativeUnits/au-1"
EVERYWHERE = frozenset({"/"})
IN_AU = frozenset({"/", AU})


def test_a_scope_covers_the_tenant_or_the_members_of_one_unit_or_is_unknown():
    from entra_auditor.toolkit.pim import scope_applies
    assert scope_applies("/", EVERYWHERE) and scope_applies("", None) and scope_applies(None, EVERYWHERE)
    assert scope_applies(AU, IN_AU) is True
    assert scope_applies(AU, EVERYWHERE) is False                       # the target is in no unit
    assert scope_applies(AU, frozenset({"/", "/administrativeUnits/au-2"})) is False
    assert scope_applies(AU, None) is None                              # units unknown: can't tell
    assert scope_applies("/0b1c-app-object-id", IN_AU) is False         # scoped to one app registration
    assert scope_applies("/0b1c-app-object-id", None) is False


def test_match_keeps_tenant_wide_and_scoped_eligibility_for_the_same_role_apart():
    wide = PimRole("r-ua", "User Administrator")
    scoped = PimRole("r-ua", "User Administrator", AU)
    for order in ([wide, scoped], [scoped, wide]):                      # whichever Graph lists first
        assert PimService.match(order, ["User Administrator"], target_scopes=IN_AU) == [wide, scoped]
        assert PimService.match(order, ["User Administrator"], target_scopes=EVERYWHERE) == [wide]
        assert PimService.match(order, ["User Administrator"], target_scopes=None) == [wide, scoped]
    assert PimService.match([scoped], ["User Administrator"], target_scopes=EVERYWHERE) == []


def test_match_puts_roles_that_only_might_apply_after_every_role_that_does():
    scoped_first_choice = PimRole("r-hd", "Helpdesk Administrator", AU)
    wide_second_choice = PimRole("r-ua", "User Administrator")
    picks = PimService.match([scoped_first_choice, wide_second_choice],
                             ["Helpdesk Administrator", "User Administrator"], target_scopes=None)
    assert picks == [wide_second_choice, scoped_first_choice]
    picks = PimService.match([scoped_first_choice, wide_second_choice],
                             ["Helpdesk Administrator", "User Administrator"], target_scopes=IN_AU)
    assert picks == [scoped_first_choice, wide_second_choice]           # known to apply: preference order wins


def test_a_role_active_at_one_scope_is_still_offered_at_another():
    wide = PimRole("r-ua", "User Administrator")
    scoped = PimRole("r-ua", "User Administrator", AU)
    active_scoped = PimRole("r-ua", "User Administrator", AU, "active")
    assert PimService.match([wide, scoped], ["User Administrator"], [active_scoped], IN_AU) == [wide]
    active_wide = PimRole("r-ua", "User Administrator", "/", "active")
    assert PimService.match([wide, scoped], ["User Administrator"], [active_wide], IN_AU) == [scoped]


def test_labels_say_when_a_role_is_for_one_unit_only():
    assert PimRole("r", "User Administrator").label == "User Administrator"
    assert PimRole("r", "User Administrator", AU).label == "User Administrator (administrative unit au-1 only)"
    assert PimRole("r", "User Administrator", AU, scope_name="Seattle").label == \
        "User Administrator (administrative unit Seattle only)"
    assert PimRole("r", "Application Administrator", "/app-1").label == "Application Administrator (scope /app-1)"


def test_scoped_eligibility_is_listed_activated_and_awaited_at_its_own_scope():
    tenant = FakeTenant(eligible=("User Administrator",))
    tenant.add_admin_unit("au-1", "Seattle").add_scoped_eligibility("User Administrator", "au-1")
    pim = service(tenant)
    assert [r.scope for r in pim.eligible()] == ["/", AU]
    scoped = next(r for r in pim.eligible() if r.scope == AU)
    pim.activate(scoped, reason="x")
    assert [w for w in tenant.writes if w[1] == "pim"][-1][2]["directoryScopeId"] == AU
    assert pim.wait_until_active(scoped.role_id, timeout=0, scope=AU)
    assert not pim.wait_until_active(scoped.role_id, timeout=0, scope="/")   # tenant-wide isn't active
    assert pim.wait_until_active(scoped.role_id, timeout=0)                  # no scope given: any scope
    pim.deactivate(next(r for r in pim.active() if r.scope == AU))
    assert pim.active() == []
