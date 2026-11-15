"""Conditional Access policy analysis: plain-English summaries, purpose tags, resolved exclusions."""

import pytest

from entra_auditor.checks._common import CRITICAL_ADMIN_ROLES, GLOBAL_ADMIN_ID
from entra_auditor.checks.ca_analysis import Tag, analyze_policies
from entra_auditor.models import GroupInfo, NamedLocation
from tests.builders import NOW, cfg, policy, snapshot, user


def profile(**kw):
    snap_kw = {k: kw.pop(k) for k in ("users", "ca_groups", "named_locations") if k in kw}
    p = policy(**{"include_users": ["All"], "include_applications": ["All"], **kw})
    return analyze_policies(snapshot(ca_policies=[p], **snap_kw), cfg(), NOW)[0]


# ---- summaries ---------------------------------------------------------------------------

def test_legacy_auth_block_reads_naturally():
    p = profile(client_app_types=["exchangeActiveSync", "other"], grant_controls=["block"])
    assert p.action == "block"
    assert p.summary.startswith("BLOCK access for All users accessing All cloud apps when Client apps: Exchange ActiveSync clients")


@pytest.mark.parametrize("operator,joiner", [("OR", " OR "), ("AND", " AND ")])
def test_requirements_are_joined_with_the_policys_logic(operator, joiner):
    p = profile(grant_controls=["mfa", "compliantDevice"], grant_operator=operator)
    expected = "multifactor authentication" + joiner + "device to be marked compliant"
    assert p.summary.startswith("REQUIRE " + expected) and p.requirement_logic == ("any" if operator == "OR" else "all")


def test_session_only_and_do_nothing_policies():
    session = profile(session_controls={"signInFrequency": {"isEnabled": True, "type": "hours", "value": 4}})
    assert session.action == "session_only" and session.summary.startswith("APPLY session controls (Sign-in frequency: every 4 hours)")
    assert profile().action == "no_effect" and profile().summary.startswith("Does nothing")


def test_exclusions_are_named_with_group_sizes_and_roles():
    p = profile(grant_controls=["mfa"], exclude_users=["u1", "u2"], exclude_groups=["g1"], exclude_roles=[GLOBAL_ADMIN_ID],
                users=[user("u1", "alice@contoso.com")], ca_groups=[GroupInfo(id="g1", display_name="Exclusions", member_count=250)])
    assert "(except 2 user(s); group Exclusions (250 members); role Global Administrator)" in p.summary
    assert [u.label for u in p.exclusions.users] == ["alice@contoso.com", "u2 (unresolved: deleted?)"]


def test_locations_are_resolved_to_their_names():
    locations = [NamedLocation(id="hq", display_name="HQ", kind="ip", is_trusted=True),
                 NamedLocation(id="eu", display_name="Europe", kind="country", countries=["DE", "FR"])]
    p = profile(grant_controls=["block"], include_locations=["eu"], exclude_locations=["hq", "AllTrusted"], named_locations=locations)
    assert "Location: Europe (countries: DE, FR) except HQ (trusted IP ranges), all trusted locations" in p.conditions


def test_conditions_describe_platforms_risk_devices_and_flows():
    p = profile(grant_controls=["mfa"], include_platforms=["all"], exclude_platforms=["linux"], sign_in_risk_levels=["high"],
                device_filter_mode="exclude", device_filter_rule="device.isCompliant -eq True", authentication_flows=["deviceCodeFlow"])
    assert "Any platform except linux" in p.conditions and "Sign-in risk: high" in p.conditions
    assert "Device filter (exclude): device.isCompliant -eq True" in p.conditions
    assert "Authentication flows: device code flow" in p.conditions


def test_well_known_apps_and_user_actions_are_named():
    p = profile(include_applications=["797f4846-ba00-4fd7-ba43-dac1f8f63013", "Office365"], include_user_actions=["urn:user:registersecurityinfo"], grant_controls=["mfa"])
    assert p.applications == ["Microsoft Azure Management", "Office 365", "User action: Register security information"]


# ---- strict MFA --------------------------------------------------------------------------

@pytest.mark.parametrize("controls,operator,strength,strict", [
    (["mfa"], "OR", None, True),
    (["mfa", "compliantDevice"], "OR", None, False),       # can be skipped by satisfying the other control
    (["mfa", "compliantDevice"], "AND", None, True),
    ([], "OR", "strength-1", True),                          # an authentication strength is MFA
    (["compliantDevice"], "OR", None, False),
    (["block"], "OR", None, False),
    (["passwordChange"], "OR", None, False)])
def test_when_mfa_is_really_mandatory(controls, operator, strength, strict):
    assert profile(grant_controls=controls, grant_operator=operator, authentication_strength_id=strength).strict_mfa is strict


# ---- admin role coverage -----------------------------------------------------------------

def test_all_user_policies_cover_every_admin_role_minus_exclusions():
    p = profile(grant_controls=["mfa"], exclude_roles=[GLOBAL_ADMIN_ID])
    assert set(p.covered_admin_role_ids) == set(CRITICAL_ADMIN_ROLES) - {GLOBAL_ADMIN_ID}


def test_role_targeted_policies_cover_only_critical_roles_they_name():
    p = profile(include_users=[], include_roles=[GLOBAL_ADMIN_ID, "not-a-critical-role"], grant_controls=["mfa"])
    assert p.covered_admin_role_ids == [GLOBAL_ADMIN_ID]


# ---- narrowing ---------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs,reason", [
    (dict(include_platforms=["windows"]), "platforms"), (dict(exclude_locations=["AllTrusted"]), "locations"),
    (dict(include_locations=["hq"]), "locations"), (dict(device_filter_rule="x"), "device filter"),
    (dict(client_app_types=["browser"]), "client app types"), (dict(authentication_flows=["deviceCodeFlow"]), "authentication flows")])
def test_conditions_that_shrink_a_policys_scope_are_recorded(kwargs, reason):
    assert reason in profile(grant_controls=["mfa"], **kwargs).narrowing


def test_legacy_client_targeting_and_risk_levels_are_not_counted_as_narrowing():
    assert profile(grant_controls=["block"], client_app_types=["other"]).narrowing == []
    risky = profile(grant_controls=["mfa"], sign_in_risk_levels=["high"])
    assert risky.narrowing == [] and risky.risk_based


def test_covering_all_client_types_is_not_narrowing():
    assert profile(grant_controls=["mfa"], client_app_types=["browser", "mobileAppsAndDesktopClients"]).narrowing == []


# ---- purpose tags ------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs,tag", [
    (dict(grant_controls=["block"], client_app_types=["exchangeActiveSync"]), Tag.BLOCK_LEGACY_AUTH),
    (dict(grant_controls=["block"], authentication_flows=["deviceCodeFlow"]), Tag.BLOCK_DEVICE_CODE),
    (dict(grant_controls=["block"], include_locations=["eu"]), Tag.BLOCK_BY_LOCATION),
    (dict(grant_controls=["block"], include_platforms=["android"]), Tag.BLOCK_BY_PLATFORM),
    (dict(include_users=["GuestsOrExternalUsers"], grant_controls=["block"]), Tag.BLOCK_GUESTS),
    (dict(grant_controls=["block"]), Tag.BLOCK_ALL_ACCESS),
    (dict(grant_controls=["mfa"]), Tag.MFA_ALL_USERS), (dict(grant_controls=["mfa"]), Tag.MFA_ADMINS),
    (dict(grant_controls=["mfa"]), Tag.MFA_GUESTS), (dict(grant_controls=["mfa"]), Tag.MFA_AZURE_MANAGEMENT),
    (dict(authentication_strength_id="s"), Tag.AUTH_STRENGTH),
    (dict(grant_controls=["compliantDevice"]), Tag.REQUIRE_COMPLIANT_DEVICE),
    (dict(grant_controls=["domainJoinedDevice"]), Tag.REQUIRE_MANAGED_DEVICE),
    (dict(grant_controls=["compliantApplication"]), Tag.REQUIRE_APP_PROTECTION),
    (dict(grant_controls=["approvedApplication"]), Tag.REQUIRE_APPROVED_APP),
    (dict(grant_controls=["passwordChange"]), Tag.PASSWORD_CHANGE), (dict(terms_of_use=["t"]), Tag.TERMS_OF_USE),
    (dict(sign_in_risk_levels=["high"], grant_controls=["mfa"]), Tag.SIGNIN_RISK),
    (dict(user_risk_levels=["high"], grant_controls=["mfa"]), Tag.USER_RISK),
    (dict(insider_risk_levels=["elevated"], grant_controls=["block"]), Tag.INSIDER_RISK),
    (dict(include_users=[], include_service_principals=["ServicePrincipalsInMyTenant"], grant_controls=["block"]), Tag.WORKLOAD_IDENTITY),
    (dict(include_user_actions=["urn:user:registersecurityinfo"], grant_controls=["mfa"]), Tag.SECURITY_INFO_REGISTRATION),
    (dict(include_user_actions=["urn:user:registerdevice"], grant_controls=["mfa"]), Tag.DEVICE_REGISTRATION),
    (dict(session_controls={"signInFrequency": {"isEnabled": True}}), Tag.SESSION_SIGNIN_FREQUENCY),
    (dict(session_controls={"persistentBrowser": {"isEnabled": True, "mode": "never"}}), Tag.SESSION_PERSISTENT_BROWSER),
    (dict(session_controls={"cloudAppSecurity": {"isEnabled": True}}), Tag.SESSION_APP_CONTROL),
    (dict(session_controls={"applicationEnforcedRestrictions": {"isEnabled": True}}), Tag.SESSION_APP_RESTRICTIONS),
    (dict(session_controls={"continuousAccessEvaluation": {"mode": "strictEnforcement"}}), Tag.SESSION_CAE)])
def test_tags_describe_what_a_policy_is_for(kwargs, tag):
    assert tag in profile(**kwargs).tags


@pytest.mark.parametrize("kwargs,tag", [
    (dict(grant_controls=["mfa"], include_platforms=["windows"]), Tag.MFA_ALL_USERS),     # narrowed: not "all users"
    (dict(grant_controls=["mfa", "compliantDevice"]), Tag.MFA_ALL_USERS),                   # bypassable
    (dict(grant_controls=["mfa"], include_applications=["Office365"]), Tag.MFA_ADMINS),     # not all apps
    (dict(grant_controls=["mfa"], exclude_roles=list(CRITICAL_ADMIN_ROLES)), Tag.MFA_ADMINS)])
def test_tags_are_withheld_when_the_policy_does_not_really_deliver_it(kwargs, tag):
    assert tag not in profile(**kwargs).tags
