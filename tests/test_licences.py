"""Licences: reading what a user holds and where from, and the plan that changes it."""

from __future__ import annotations

import pytest

from entra_auditor.toolkit.actions import PlanError, execute_plan, plan_change_licences
from entra_auditor.toolkit.licences import Sku, list_skus, load_user_licences
from entra_auditor.toolkit.search import resolve_user
from tests.fakes import FakeTenant

E3, P1, VISIO = "sku-e3", "sku-p1", "sku-visio"


def tenant():
    t = FakeTenant()
    t.add_sku(E3, "SPE_E3", total=3).add_sku(P1, "AAD_PREMIUM", total=1).add_sku(VISIO, "CONTOSO_ODD_SKU", total=5)
    t.users["u-alice"]["usageLocation"] = "US"
    t.give_licence("u-alice", E3).give_licence("u-alice", P1, group="g-fin").give_licence("u-bob", E3)
    t.active_roles["r"] = "License Administrator"
    return t


def setup(t, uid="u-alice"):
    report = load_user_licences(t, uid)
    user = resolve_user(t, t.users[uid]["userPrincipalName"])
    return report, user, {s.sku_id: s for s in report.skus}


def change(t, uid="u-alice", add=(), remove=(), **kw):
    report, user, skus = setup(t, uid)
    return plan_change_licences(user, [skus[s] for s in add], [skus[s] for s in remove], current=report.licences,
                                usage_location=report.usage_location, **kw)


def test_subscriptions_show_friendly_names_and_what_is_free():
    skus = {s.sku_id: s for s in list_skus(tenant())}
    assert skus[E3].name == "Microsoft 365 E3 (SPE_E3)" and skus[E3].usage == "1 of 3 free"
    assert skus[VISIO].name == "CONTOSO_ODD_SKU"                       # unknown product: the part number
    assert skus[P1].available == 0 and skus[P1].assignable
    assert Sku(sku_id="x").usage == "availability unknown" and Sku(sku_id="x").name == "x"
    assert not Sku(sku_id="x", status="Suspended").assignable and Sku(sku_id="x", status="Warning").assignable


def test_a_users_licences_say_whether_they_are_direct_or_inherited():
    report, _user, _skus = setup(tenant())
    assert report.usage_location == "US"
    assert [lic.label for lic in report.licences] == [
        "Microsoft 365 E3 (SPE_E3)  -  direct", "Microsoft Entra ID P1 (AAD_PREMIUM)  -  from group Finance Share"]
    t = tenant().give_licence("u-alice", P1)                            # both ways at once
    assert load_user_licences(t, "u-alice").licences[1].source == "direct, from group Finance Share"
    assert load_user_licences(tenant(), "u-guest").licences == []


def test_unreadable_subscriptions_leave_ids_and_a_warning():
    t = tenant()
    t.skus_denied = True
    report = load_user_licences(t, "u-alice")
    assert report.skus is None and [lic.name for lic in report.licences] == [E3, P1]
    assert "subscriptions couldn't be read" in report.warnings[0]


def test_assigning_and_removing_is_one_request(tmp_path):
    t = tenant()
    plan = change(t, add=[VISIO], remove=[E3])
    assert plan.details == ["+ CONTOSO_ODD_SKU", "- Microsoft 365 E3 (SPE_E3)"]
    assert [(r.method, r.path) for r in plan.requests] == [("POST", "/users/u-alice/assignLicense")]
    assert plan.requests[0].json == {"addLicenses": [{"skuId": VISIO, "disabledPlans": []}], "removeLicenses": [E3]}
    assert plan.suggested_roles == ("License Administrator", "User Administrator") and "retention" in plan.warnings[0]
    assert execute_plan(t, plan, log_path=tmp_path / "log").status == "ok"
    assert set(t.licences["u-alice"]) == {VISIO, P1}


def test_the_last_free_licence_can_be_assigned_but_not_one_more():
    t = tenant()
    t.users["u-bob"]["usageLocation"] = "GB"
    assert change(t, "u-bob", add=[VISIO]).details == ["+ CONTOSO_ODD_SKU"]
    t.give_licence("u-guest", E3)                                       # E3 is now 3 of 3 in use
    with pytest.raises(PlanError, match=r"No Microsoft 365 E3 \(SPE_E3\) licences are left \(3 of 3 in use\)"):
        change(t, "u-sync", add=[E3], set_usage_location="US")


def test_an_inherited_licence_is_removed_through_its_group_not_here():
    with pytest.raises(PlanError, match="comes from the group Finance Share"):
        change(tenant(), remove=[P1])
    t = tenant().give_licence("u-alice", P1)                            # direct as well: the direct one can go
    plan = change(t, remove=[P1])
    assert "Still inherited from a group afterwards" in plan.warnings[-1]


def test_a_licence_inherited_from_a_group_can_also_be_assigned_directly():
    t = tenant()
    t.skus[P1]["prepaidUnits"]["enabled"] = 2
    assert change(t, add=[P1]).details == ["+ Microsoft Entra ID P1 (AAD_PREMIUM)"]


def test_nothing_to_do_and_impossible_changes_are_refused():
    t = tenant()
    with pytest.raises(PlanError, match="Nothing to change"):
        change(t, add=[E3])                                             # already held directly
    with pytest.raises(PlanError, match="doesn't have"):
        change(t, remove=[VISIO])
    t.skus[VISIO]["capabilityStatus"] = "Suspended"
    with pytest.raises(PlanError, match="can't be assigned .*Suspended"):
        change(t, add=[VISIO])


def test_a_user_without_a_usage_location_gets_one_in_the_same_plan(tmp_path):
    t = tenant()
    with pytest.raises(PlanError, match="usage location"):
        change(t, "u-bob", add=[VISIO])
    with pytest.raises(PlanError, match="two-letter"):
        change(t, "u-bob", add=[VISIO], set_usage_location="USA")
    plan = change(t, "u-bob", add=[VISIO], set_usage_location="gb")
    assert [(r.method, r.path, r.json) for r in plan.requests][0] == ("PATCH", "/users/u-bob", {"usageLocation": "GB"})
    assert execute_plan(t, plan, log_path=tmp_path / "log").status == "ok"
    assert t.users["u-bob"]["usageLocation"] == "GB" and VISIO in t.licences["u-bob"]
    # removing never needs a usage location
    assert change(t, "u-bob", remove=[E3]).requests[0].method == "POST"


def test_the_fake_enforces_what_entra_enforces(tmp_path):
    from entra_auditor.graph.client import GraphError, GraphPermissionError
    t = tenant()
    with pytest.raises(GraphError, match="usage location"):
        t.post("/users/u-bob/assignLicense", {"addLicenses": [{"skuId": VISIO, "disabledPlans": []}], "removeLicenses": []})
    with pytest.raises(GraphError, match="inherited"):
        t.post("/users/u-alice/assignLicense", {"addLicenses": [], "removeLicenses": [P1]})
    t.active_roles.clear()
    with pytest.raises(GraphPermissionError):
        t.post("/users/u-alice/assignLicense", {"addLicenses": [], "removeLicenses": [E3]})
