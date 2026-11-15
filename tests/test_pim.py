from datetime import datetime, timezone

import pytest

from entra_auditor.toolkit import actions
from entra_auditor.toolkit.pim import PimError, PimService, iso_duration
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
