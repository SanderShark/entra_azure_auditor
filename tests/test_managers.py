"""Who can manage this user? (toolkit/managers.py): the rules, then the report built from a tenant."""

from __future__ import annotations

import pytest

from entra_auditor.graph.client import GraphAuthError
from entra_auditor.toolkit import managers as M
from entra_auditor.toolkit.managers import (
    AA, CAN_ACCOUNT, CAN_LICENCES, CAN_METHODS, CAN_PASSWORD, CAN_PROFILE, GA, HD, LA, PA, PAA, UA,
    capabilities, who_can_manage,
)
from tests.fakes import FakeTenant, U

NO_UNITS: frozenset = frozenset()
SEA, EXEC = "/administrativeUnits/au-sea", "/administrativeUnits/au-exec"


def can(role, scope="/", *, user_roles=(), protected=False, units=NO_UNITS, restricted=NO_UNITS):
    return capabilities(role, scope, user_roles=None if user_roles is None else list(user_roles),
                        protected=protected, unit_scopes=units, restricted_scopes=restricted)


# ---- the rules ---------------------------------------------------------------------------

def test_an_ordinary_user_can_be_managed_by_every_user_facing_role():
    assert can(GA) == ([CAN_PASSWORD, CAN_ACCOUNT, CAN_METHODS, CAN_PROFILE, CAN_LICENCES], None)
    assert can(UA) == ([CAN_PASSWORD, CAN_ACCOUNT, CAN_PROFILE, CAN_LICENCES], None)
    assert can(AA) == ([CAN_PASSWORD, CAN_ACCOUNT, CAN_METHODS], None)
    assert can(HD) == ([CAN_PASSWORD], None) and can(PA) == ([CAN_PASSWORD], None)
    assert can(LA) == ([CAN_LICENCES], None)


@pytest.mark.parametrize("held, resetters", [
    ("Directory Readers", {PA, HD, AA, UA}),
    ("Password Administrator", {PA, HD, AA, UA}),
    ("Message Center Reader", {HD, AA, UA}),          # one row below "everyone": not Password Administrator
    ("Helpdesk Administrator", {HD, UA}),
    ("Authentication Administrator", {AA}),
    ("User Administrator", {UA}),
    ("Groups Administrator", {UA}),
    ("Global Administrator", set()),
    ("Privileged Role Administrator", set()),
    ("Some Custom Role", set()),                       # anything not in Microsoft's table protects the user
])
def test_who_can_reset_the_password_of_an_admin_follows_microsofts_table(held, resetters):
    for role in (PA, HD, AA, UA):
        assert (CAN_PASSWORD in can(role, user_roles=[held])[0]) is (role in resetters), (role, held)
    for role in (PAA, GA):                             # never limited by the target's roles
        assert CAN_PASSWORD in can(role, user_roles=[held])[0]


def test_sensitive_actions_have_their_own_table():
    # a Helpdesk Administrator's account: User Administrators may disable it, Authentication Administrators not
    assert CAN_ACCOUNT in can(UA, user_roles=[HD])[0]
    assert CAN_ACCOUNT not in can(AA, user_roles=[HD])[0] and CAN_METHODS not in can(AA, user_roles=[HD])[0]
    # ... while a Message Center Reader is fair game for both
    assert CAN_ACCOUNT in can(AA, user_roles=["Message Center Reader"])[0]


def test_every_role_the_user_holds_must_allow_it():
    assert CAN_PASSWORD in can(HD, user_roles=["Directory Readers", HD])[0]
    caps, why = can(HD, user_roles=["Directory Readers", UA])
    assert caps == [] and "User Administrator" in why


def test_what_does_not_depend_on_the_users_roles_survives():
    caps, why = can(UA, user_roles=[GA])
    assert caps == [CAN_PROFILE, CAN_LICENCES] and why == "limited because the user holds Global Administrator"


def test_role_assignable_group_members_are_protected_like_admins():
    caps, why = can(HD, protected=True)
    assert caps == [] and "role-assignable group" in why
    assert CAN_PASSWORD in can(PAA, protected=True)[0] and CAN_PASSWORD in can(GA, protected=True)[0]


def test_a_restricted_unit_blocks_everyone_not_scoped_to_it_except_for_licences():
    inside = dict(units=frozenset({SEA, EXEC}), restricted=frozenset({EXEC}))
    caps, why = can(GA, **inside)
    assert caps == [CAN_LICENCES] and "restricted management unit" in why
    assert can(HD, **inside)[0] == []                                   # tenant-wide helpdesk: nothing
    assert can(HD, SEA, **inside)[0] == []                              # scoped to an ordinary unit: blocked too
    assert can(HD, EXEC, **inside) == ([CAN_PASSWORD], None)            # scoped to the restricted unit: allowed
    assert can(LA, SEA, **inside)[0] == [CAN_LICENCES]


def test_a_unit_scoped_role_needs_the_user_in_the_unit_and_not_an_admin():
    assert can(HD, SEA, units=frozenset({SEA})) == ([CAN_PASSWORD], None)
    caps, why = can(HD, SEA, units=frozenset({EXEC}))
    assert caps == [] and "isn't in that administrative unit" in why
    # tenant-wide, a Helpdesk Administrator may reset another Helpdesk Administrator; unit-scoped, no admins
    assert can(HD, SEA, units=frozenset({SEA}), user_roles=[HD])[0] == []
    assert can(UA, SEA, units=frozenset({SEA}), user_roles=["Directory Readers"])[0] == [CAN_PROFILE, CAN_LICENCES]


def test_unknown_roles_of_the_user_leave_only_what_is_certain():
    caps, why = can(UA, user_roles=None)
    assert caps == [CAN_PROFILE, CAN_LICENCES] and "couldn't be read" in why
    assert can(GA, user_roles=None) == ([CAN_PASSWORD, CAN_ACCOUNT, CAN_METHODS, CAN_PROFILE, CAN_LICENCES], None)


# ---- the report ----------------------------------------------------------------------------

def tenant():
    t = FakeTenant()
    for uid, name in (("a-ga", "Gail Global"), ("a-hd", "Hank Helpdesk"), ("a-hd-sea", "Sally Seattle"),
                      ("a-ua-pim", "Uma Eligible"), ("a-exec", "Eve Executive-Support")):
        t.users[uid] = U(uid, name, f"{uid}@contoso.com")
    t.add_admin_unit("au-sea", "Seattle", members=("u-alice",))
    t.add_admin_unit("au-exec", "Executives", members=("u-bob",), isMemberManagementRestricted=True)
    t.add_role_holder(GA, "a-ga").add_role_holder(HD, "a-hd").add_role_holder(UA, "a-ua-pim", state="eligible")
    t.add_role_holder(HD, "a-hd-sea", au="au-sea").add_role_holder(HD, "a-exec", au="au-exec")
    return t


def rows(report, effective=True):
    return [(m.principal_name.split(" (")[0], m.role, m.scope_label, m.assignment_label)
            for m in (report.effective if effective else report.ineffective)]


def test_an_ordinary_user_lists_tenant_wide_admins_and_those_of_their_unit():
    report = who_can_manage(tenant(), "u-alice")
    assert [u.label for u in report.units] == ["Seattle"] and report.user_roles == [] and not report.notes
    assert rows(report) == [
        ("Gail Global", GA, "Whole tenant", "Active"),
        ("Uma Eligible", UA, "Whole tenant", "Eligible (PIM)"),
        ("Hank Helpdesk", HD, "Whole tenant", "Active"),
        ("Sally Seattle", HD, "Unit: Seattle", "Active"),
    ]
    assert report.ineffective == []                    # the Executives admin isn't about Alice at all


def test_a_user_in_a_restricted_unit_is_shielded_from_tenant_wide_admins():
    report = who_can_manage(tenant(), "u-bob")
    assert [u.label for u in report.restricted_units] == ["Executives"]
    assert "restricted management unit Executives" in report.notes[0]
    assert ("Eve Executive-Support", HD, "Unit: Executives", "Active") in rows(report)
    gail = next(m for m in report.managers if m.principal_id == "a-ga")
    assert gail.can == [CAN_LICENCES] and "restricted" in gail.why_not
    assert rows(report, effective=False) == [("Hank Helpdesk", HD, "Whole tenant", "Active")]


def test_an_admins_own_roles_limit_who_can_touch_them():
    report = who_can_manage(tenant(), "u-admin")       # the fake's Global Administrator
    assert report.user_roles == [GA] and "is an admin (Global Administrator)" in report.notes[0]
    hank = next(m for m in report.managers if m.principal_id == "a-hd")
    assert hank.can == [] and hank.why_not == "limited because the user holds Global Administrator"
    assert next(m for m in report.managers if m.principal_id == "a-ga").can[0] == CAN_PASSWORD


def test_the_users_own_assignment_is_not_listed_as_someone_managing_them():
    t = tenant().add_role_holder(HD, "u-alice")
    report = who_can_manage(t, "u-alice")
    assert report.user_roles == [HD] and all(m.principal_id != "u-alice" for m in report.managers)


def test_role_assignable_group_membership_protects_and_groups_show_as_groups():
    t = tenant()
    t.members["g-role"] = {"u-alice"}
    t.add_role_holder(PA, "g-role")
    report = who_can_manage(t, "u-alice")
    assert report.protected_by == ["member of the role-assignable group Role Group"]
    group = next(m for m in report.managers if m.principal_id == "g-role")
    assert group.principal_kind == "group" and "its members hold the role" in group.who and group.can == []


def test_unreadable_sources_are_unknown_not_empty():
    t = tenant()
    t.eligibility_denied = True
    report = who_can_manage(t, "u-alice")
    assert not report.eligible_known and all(m.state == "active" for m in report.managers)
    assert any("PIM-eligible admins couldn't be read" in n for n in report.notes)

    t = tenant()
    t.assignments_denied = True
    report = who_can_manage(t, "u-alice")
    assert report.managers is None and any("Role assignments couldn't be read" in w for w in report.warnings)

    t = tenant()
    t.memberof_denied = True
    report = who_can_manage(t, "u-alice")
    assert report.units is None and any("units couldn't be read" in n for n in report.notes)
    sally = next(m for m in report.managers if m.principal_id == "a-hd-sea")   # can't be ruled out, so shown
    assert "only if the user is in that unit" in sally.why_not


def test_an_auth_failure_aborts_instead_of_becoming_a_warning():
    t = tenant()
    t.get_paged = lambda *a, **k: (_ for _ in ()).throw(GraphAuthError("401", status_code=401))
    with pytest.raises(GraphAuthError):
        who_can_manage(t, "u-alice")


def test_nothing_is_written():
    t = tenant()
    who_can_manage(t, "u-bob")
    assert t.writes == [] and all(method == "GET" for method, _path in t.calls)
    assert M.MANAGER_ROLES[0] == GA
