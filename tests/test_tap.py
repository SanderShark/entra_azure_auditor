"""Temporary Access Pass: the plan, and that the pass is shown once and never logged."""

from __future__ import annotations

import pytest

from entra_auditor.toolkit.actions import PlanError, execute_plan, plan_create_tap
from entra_auditor.toolkit.search import resolve_user
from tests.fakes import FakeTenant


def alice(t):
    return resolve_user(t, "alice@contoso.com")


def test_the_plan_is_one_documented_post_with_the_right_roles():
    t = FakeTenant()
    plan = plan_create_tap(alice(t), 90, usable_once=True)
    (request,) = plan.requests
    assert (request.method, request.path) == ("POST", "/users/u-alice/authentication/temporaryAccessPassMethods")
    assert request.json == {"lifetimeInMinutes": 90, "isUsableOnce": True} and request.reveal == ("temporaryAccessPass",)
    assert plan.details[:2] == ["Valid for 1 h 30 min, from now", "Usable once"]
    assert plan.suggested_roles == ("Authentication Administrator", "Privileged Authentication Administrator")
    assert "replaced" in plan.warnings[0]
    admin = plan_create_tap(alice(t), 60, usable_once=False, target_is_admin=True)
    assert admin.suggested_roles == ("Privileged Authentication Administrator",)
    assert "more than once" in admin.warnings[1] and admin.details[:2] == ["Valid for 1 h, from now", "Usable repeatedly while valid"]


@pytest.mark.parametrize("minutes, ok", [(9, False), (10, True), (43200, True), (43201, False)])
def test_the_lifetime_limits(minutes, ok):
    t = FakeTenant()
    if ok:
        assert plan_create_tap(alice(t), minutes).requests[0].json["lifetimeInMinutes"] == minutes
    else:
        with pytest.raises(PlanError, match="between 10 minutes and 30 days"):
            plan_create_tap(alice(t), minutes)


def test_the_pass_is_returned_once_and_never_logged(tmp_path):
    t = FakeTenant()
    t.active_roles["r"] = "Authentication Administrator"
    log = tmp_path / "log"
    result = execute_plan(t, plan_create_tap(alice(t), 60), log_path=log)
    assert result.status == "ok" and result.secrets == {"temporaryAccessPass": "T@p-9x2Q"}
    assert t.taps["u-alice"] == {"lifetimeInMinutes": 60, "isUsableOnce": True}
    text = log.read_text()
    assert "user.create_tap" in text and "T@p-9x2Q" not in text


def test_without_a_role_it_is_denied_so_elevation_can_be_offered(tmp_path):
    t = FakeTenant()
    result = execute_plan(t, plan_create_tap(alice(t), 60), log_path=tmp_path / "log")
    assert result.status == "denied" and result.secrets == {}
