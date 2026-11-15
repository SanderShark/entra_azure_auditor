"""The UI-independent change flow (toolkit/flow.py), driven step by step as a GUI would."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from entra_auditor.graph.client import GraphError
from entra_auditor.toolkit import flow as F
from entra_auditor.toolkit.actions import plan_set_enabled, plan_update_user
from entra_auditor.toolkit.pim import PimService
from entra_auditor.toolkit.search import resolve_user
from tests.fakes import FakeTenant


class Sess:
    def __init__(self, tenant, *, user_mode=True):
        self.graph = tenant
        self.identity = "user:me@contoso.com"
        self.user_mode = user_mode
        self.refreshes = 0

    def refresh(self):
        self.refreshes += 1


def make(tenant=None, *, user_mode=True, plan=None, **kwargs):
    tenant = tenant or FakeTenant()
    sess = Sess(tenant, user_mode=user_mode)
    plan = plan or plan_update_user(resolve_user(tenant, "alice@contoso.com"), {"jobTitle": "Principal"})
    sleeps: list[float] = []
    reporter = F.RecordingReporter()
    kwargs.setdefault("pim", PimService(tenant, sleep=lambda s: None))
    flow = F.ChangeFlow(sess, plan, reporter=reporter, sleep=sleeps.append, **kwargs)
    return SimpleNamespace(tenant=tenant, sess=sess, plan=plan, flow=flow, reporter=reporter, sleeps=sleeps)


def texts(reporter):
    return " | ".join(n.text for n in reporter.notices)


def elevate(env, reason="INC-1"):
    """Answer the usual way: confirm, take the first role, justify."""
    step = env.flow.confirm(True)
    assert isinstance(step, F.NeedsElevation)
    step = env.flow.choose_role(step.candidate_roles[0])
    assert isinstance(step, F.NeedsJustification)
    return env.flow.justify(reason)


# ---- the happy paths --------------------------------------------------------------------

def test_the_first_step_is_a_confirmation_of_the_plan_and_nothing_is_sent_yet():
    env = make()
    step = env.flow.start()
    assert isinstance(step, F.NeedsConfirmation) and step.plan is env.plan
    assert env.tenant.writes == []


def test_declining_the_confirmation_cancels_without_sending_anything():
    env = make()
    env.flow.start()
    step = env.flow.confirm(False)
    assert isinstance(step, F.Done) and step.cancelled and step.result.status == "skipped"
    assert env.tenant.writes == [] and env.flow.done


def test_a_dry_run_finishes_immediately_without_asking_or_sending():
    env = make(dry_run=True)
    step = env.flow.start()
    assert isinstance(step, F.Done) and step.result.status == "dry_run" and not step.cancelled
    assert env.tenant.writes == []


def test_a_change_that_is_allowed_finishes_without_elevation():
    tenant = FakeTenant()
    tenant.active_roles["r-user-administrator"] = "User Administrator"
    env = make(tenant)
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.Done) and step.result.status == "ok"
    assert tenant.users["u-alice"]["jobTitle"] == "Principal"


def test_a_denied_change_offers_eligible_roles_best_first():
    env = make()
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.NeedsElevation)
    assert [r.name for r in step.candidate_roles] == ["User Administrator"] and step.minutes == 60
    assert "permissions aren't enough" in texts(env.reporter)


def test_elevation_activates_refreshes_the_token_and_retries():
    env = make(minutes=30)
    env.flow.start()
    step = elevate(env, "  INC-1 fix title  ")
    assert isinstance(step, F.Done) and step.result.status == "ok"
    body = [w for w in env.tenant.writes if w[1] == "pim"][0][2]
    assert body["justification"] == "INC-1 fix title"          # trimmed
    assert env.sess.refreshes == 1 and env.tenant.users["u-alice"]["jobTitle"] == "Principal"
    assert "User Administrator is active for 30 minutes." in texts(env.reporter)
    assert "Waiting for User Administrator to become active..." in env.reporter.busy_texts


# ---- retries after activation: the boundary is RETRY_ATTEMPTS --------------------------

def test_the_last_retry_attempt_can_still_succeed():
    env = make(FakeTenant(propagation_delay=F.RETRY_ATTEMPTS - 1))
    env.flow.start()
    step = elevate(env)
    assert step.result.status == "ok"
    assert env.sleeps == [F.RETRY_WAIT] * (F.RETRY_ATTEMPTS - 1)   # no wait after the successful try
    assert env.sess.refreshes == 2                                 # after activation, and again on attempt 2


def test_one_denial_too_many_gives_up_with_the_denied_result():
    env = make(FakeTenant(propagation_delay=F.RETRY_ATTEMPTS))
    env.flow.start()
    step = elevate(env)
    assert step.result.status == "denied"
    assert env.sleeps == [F.RETRY_WAIT] * (F.RETRY_ATTEMPTS - 1)   # no wait after the last try


# ---- declining or failing elevation -----------------------------------------------------

def test_choosing_no_role_ends_with_the_original_denial():
    env = make()
    env.flow.start()
    env.flow.confirm(True)
    step = env.flow.choose_role(None)
    assert isinstance(step, F.Done) and step.result.status == "denied" and not step.cancelled
    assert not env.tenant.active_roles


def test_giving_up_at_the_justification_activates_nothing():
    env = make()
    env.flow.start()
    step = env.flow.confirm(True)
    env.flow.choose_role(step.candidate_roles[0])
    step = env.flow.justify(None)
    assert isinstance(step, F.Done) and step.result.status == "denied" and not env.tenant.active_roles


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_justification_is_refused_and_the_question_stays_open(blank):
    env = make()
    env.flow.start()
    step = env.flow.confirm(True)
    env.flow.choose_role(step.candidate_roles[0])
    with pytest.raises(ValueError, match="justification"):
        env.flow.justify(blank)
    assert isinstance(env.flow.step, F.NeedsJustification) and not env.tenant.active_roles
    assert env.flow.justify("x").result.status == "ok"


def test_a_failed_activation_explains_why_and_ends_denied():
    env = make(FakeTenant(require_mfa={"User Administrator"}))
    env.flow.start()
    step = elevate(env)
    assert step.result.status == "denied"
    errors = [n for n in env.reporter.notices if n.level == "error"]
    assert errors and "multifactor" in errors[0].text.lower()


def test_app_mode_never_offers_elevation():
    env = make(user_mode=False)
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.Done) and step.result.status == "denied"
    assert "only works with a user sign-in" in texts(env.reporter)


def test_not_eligible_for_a_suitable_role_ends_denied_and_lists_what_you_have():
    env = make(FakeTenant(eligible=("Global Reader",)))
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.Done) and step.result.status == "denied"
    assert "aren't eligible" in texts(env.reporter) and "You are eligible for: Global Reader" in texts(env.reporter)


def test_unreadable_pim_roles_end_denied_with_the_roles_to_activate_by_hand():
    class BrokenPim:
        def eligible(self):
            raise GraphError("boom", status_code=500)

        active = eligible

    env = make(pim=BrokenPim())
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.Done) and step.result.status == "denied"
    assert step.activate_manually == tuple(env.plan.suggested_roles) and step.activate_manually
    assert "Couldn't read your PIM roles" in texts(env.reporter)


def test_an_already_active_role_is_used_after_a_token_refresh_without_asking():
    tenant = FakeTenant(propagation_delay=1)
    tenant.active_roles["r-user-administrator"] = "User Administrator"
    tenant._denied_after_activation = 1                 # active, but not yet in the token
    env = make(tenant)
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.Done) and step.result.status == "ok"
    assert env.sess.refreshes == 1 and not [w for w in tenant.writes if w[1] == "pim"]


# ---- secrets ----------------------------------------------------------------------------

def test_extra_secrets_are_attached_only_to_a_successful_result():
    tenant = FakeTenant()
    tenant.active_roles["r-user-administrator"] = "User Administrator"
    env = make(tenant, plan=plan_set_enabled(resolve_user(tenant, "alice@contoso.com"), False),
               extra_secrets={"password": "S3cret!"})
    env.flow.start()
    assert env.flow.confirm(True).result.secrets["password"] == "S3cret!"

    denied = make(extra_secrets={"password": "S3cret!"})
    denied.flow.start()
    denied.flow.confirm(True)
    assert "password" not in denied.flow.choose_role(None).result.secrets


def test_a_dry_run_never_carries_extra_secrets():
    env = make(dry_run=True, extra_secrets={"password": "S3cret!"})
    assert "password" not in env.flow.start().result.secrets


# ---- answering out of turn --------------------------------------------------------------

def test_answers_must_match_the_current_step():
    env = make()
    with pytest.raises(F.FlowStateError):
        env.flow.confirm(True)                  # not started
    env.flow.start()
    with pytest.raises(F.FlowStateError):
        env.flow.start()
    with pytest.raises(F.FlowStateError):
        env.flow.justify("x")
    env.flow.confirm(False)
    with pytest.raises(F.FlowStateError):
        env.flow.confirm(True)                  # already done


def test_only_an_offered_role_can_be_chosen():
    env = make()
    env.flow.start()
    env.flow.confirm(True)
    other = PimService(env.tenant, sleep=lambda s: None).eligible()
    not_offered = next(r for r in other if r.name == "Global Reader")
    with pytest.raises(ValueError, match="not one of the offered"):
        env.flow.choose_role(not_offered)
    assert isinstance(env.flow.step, F.NeedsElevation)


def test_the_flow_runs_with_no_reporter_at_all():
    tenant = FakeTenant()
    flow = F.ChangeFlow(Sess(tenant), plan_update_user(resolve_user(tenant, "alice@contoso.com"), {"jobTitle": "P"}),
                        pim=PimService(tenant, sleep=lambda s: None), sleep=lambda s: None)
    flow.start()
    step = flow.confirm(True)
    step = flow.choose_role(step.candidate_roles[0])
    assert flow.justify("x").result.status == "ok"


# ---- PIM for Groups as an elevation path ---------------------------------------------------

def group_tenant(**kw):
    return FakeTenant(eligible=(), **kw).add_pim_group("g-uadm", "User Admins (PIM)", roles=["User Administrator"])


def test_a_group_whose_membership_grants_the_role_is_offered():
    env = make(group_tenant())
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.NeedsElevation)
    [candidate] = step.candidate_roles
    assert candidate.group_id == "g-uadm" and "grants User Administrator" in candidate.label


def test_roles_are_offered_before_groups():
    tenant = FakeTenant().add_pim_group("g-uadm", "User Admins (PIM)", roles=["User Administrator"])
    env = make(tenant)
    env.flow.start()
    names = [c.name for c in env.flow.confirm(True).candidate_roles]
    assert names == ["User Administrator", "User Admins (PIM) (member)"]


def test_activating_the_group_retries_and_succeeds():
    env = make(group_tenant(propagation_delay=1))
    env.flow.start()
    step = env.flow.confirm(True)
    env.flow.choose_role(step.candidate_roles[0])
    step = env.flow.justify("INC-9")
    assert step.result.status == "ok" and env.tenant.users["u-alice"]["jobTitle"] == "Principal"
    body = [w for w in env.tenant.writes if w[1] == "group-pim"][0][2]
    assert body["groupId"] == "g-uadm" and body["justification"] == "INC-9"
    assert "User Admins (PIM) (member) is active for 60 minutes." in texts(env.reporter)


def test_an_active_group_membership_is_used_after_a_refresh_without_asking():
    tenant = group_tenant(propagation_delay=1)
    tenant.group_active[("g-uadm", "member")] = "activated"
    tenant._denied_after_activation = 1          # active, but not yet in the token
    env = make(tenant)
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.Done) and step.result.status == "ok" and env.sess.refreshes == 1


def test_a_group_that_grants_an_unrelated_role_is_not_offered():
    tenant = FakeTenant(eligible=()).add_pim_group("g-read", "Readers", roles=["Global Reader"])
    env = make(tenant)
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.Done) and step.result.status == "denied"


def test_without_group_pim_permissions_the_flow_still_offers_roles():
    class NoGroupPermission:
        def eligible(self, **kw):
            from entra_auditor.toolkit.pim import PimError
            raise PimError("Your PIM group assignments couldn't be read.")

        active = eligible

    env = make(group_pim=NoGroupPermission())
    env.flow.start()
    step = env.flow.confirm(True)
    assert [c.name for c in step.candidate_roles] == ["User Administrator"]


# ---- roles scoped to an administrative unit ----------------------------------------------

def scoped_tenant(members=("u-alice",), **kwargs):
    """Eligible for User Administrator in the Seattle unit only (and tenant-wide for nothing useful)."""
    kwargs.setdefault("eligible", ("Global Reader",))
    tenant = FakeTenant(**kwargs)
    tenant.add_admin_unit("au-sea", "Seattle", members=members)
    tenant.add_scoped_eligibility("User Administrator", "au-sea")
    return tenant


def test_a_role_scoped_to_a_unit_the_target_is_not_in_is_not_offered():
    env = make(scoped_tenant(members=("u-bob",)))            # the plan targets Alice
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.Done) and step.result.status == "denied"
    assert not env.tenant.scoped_active                       # nothing was activated for nothing
    said = texts(env.reporter)
    assert "scoped to an administrative unit" in said and "isn't in" in said


def test_a_role_scoped_to_a_unit_the_target_is_in_is_offered_and_works():
    env = make(scoped_tenant(members=("u-alice",)))
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.NeedsElevation)
    (role,) = step.candidate_roles
    assert role.scope == "/administrativeUnits/au-sea" and "Seattle" in role.label
    env.flow.choose_role(role)
    step = env.flow.justify("INC-7")
    assert step.result.status == "ok" and env.tenant.users["u-alice"]["jobTitle"] == "Principal"
    request = next(w[2] for w in env.tenant.writes if w[1] == "pim")
    assert request["directoryScopeId"] == "/administrativeUnits/au-sea"


def test_tenant_wide_eligibility_is_offered_before_a_scoped_one_and_never_hidden_by_it():
    tenant = scoped_tenant(members=("u-alice",), eligible=("User Administrator",))
    env = make(tenant)
    env.flow.start()
    step = env.flow.confirm(True)
    assert [r.scope for r in step.candidate_roles] == ["/", "/administrativeUnits/au-sea"]

    env = make(scoped_tenant(members=("u-bob",), eligible=("User Administrator",)))   # Alice is outside the unit
    env.flow.start()
    step = env.flow.confirm(True)
    assert [r.scope for r in step.candidate_roles] == ["/"]


def test_an_active_scoped_role_that_does_not_cover_the_target_is_not_mistaken_for_enough():
    tenant = scoped_tenant(members=("u-bob",), eligible=("User Administrator",))
    tenant.scoped_active[("r-user-administrator", "/administrativeUnits/au-sea")] = "User Administrator"
    env = make(tenant)
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.NeedsElevation), texts(env.reporter)       # not "you already have it; retrying"
    assert [r.scope for r in step.candidate_roles] == ["/"]              # the tenant-wide one is still offered
    env.flow.choose_role(step.candidate_roles[0])
    step = env.flow.justify("INC-8")                                     # ... and waiting isn't fooled either
    assert step.result.status == "ok" and "r-user-administrator" in tenant.active_roles


def test_an_active_scoped_role_that_covers_the_target_is_used_without_elevating():
    tenant = scoped_tenant(members=("u-alice",))
    tenant.scoped_active[("r-user-administrator", "/administrativeUnits/au-sea")] = "User Administrator"
    tenant._denied_after_activation = 1                                  # the first try is denied
    env = make(tenant)
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.Done) and step.result.status == "ok" and "already have" in texts(env.reporter)


def test_when_the_targets_units_cannot_be_read_scoped_roles_are_offered_last_with_a_caveat():
    tenant = scoped_tenant(members=("u-alice",), eligible=("User Administrator",))
    tenant.memberof_denied = True
    env = make(tenant)
    env.flow.start()
    step = env.flow.confirm(True)
    assert [r.scope for r in step.candidate_roles] == ["/", "/administrativeUnits/au-sea"]
    assert "Couldn't check which administrative units" in texts(env.reporter)


def test_a_scoped_role_never_counts_for_changing_the_unit_itself():
    from entra_auditor.toolkit.actions import plan_update_admin_unit
    from entra_auditor.toolkit.admin_units import get_admin_unit
    tenant = FakeTenant(eligible=("Global Reader",))
    tenant.add_admin_unit("au-sea", "Seattle")
    tenant.add_scoped_eligibility("Privileged Role Administrator", "au-sea")
    plan = plan_update_admin_unit(get_admin_unit(tenant, "au-sea"), {"description": "West coast"})
    env = make(tenant, plan=plan)
    env.flow.start()
    step = env.flow.confirm(True)
    assert isinstance(step, F.Done) and step.result.status == "denied" and not tenant.scoped_active


def test_a_pim_group_whose_role_is_scoped_to_another_unit_is_not_offered():
    from entra_auditor.toolkit.group_pim import GroupPimService
    for members, offered in ((("u-bob",), False), (("u-alice",), True)):
        tenant = FakeTenant(eligible=("Global Reader",))
        tenant.add_admin_unit("au-sea", "Seattle", members=members)
        tenant.add_pim_group("g-hd", "Seattle Helpdesk", roles=("User Administrator",), au="au-sea")
        env = make(tenant, group_pim=GroupPimService(tenant, sleep=lambda s: None))
        env.flow.start()
        step = env.flow.confirm(True)
        assert isinstance(step, F.NeedsElevation) is offered, members
        if offered:
            env.flow.choose_role(step.candidate_roles[0])
            assert env.flow.justify("INC-9").result.status == "ok"
