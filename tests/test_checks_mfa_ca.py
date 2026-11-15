"""MFA registration and Conditional Access: baseline coverage, per-policy concerns, exclusions."""

import pytest

from entra_auditor.checks._common import CRITICAL_ADMIN_ROLES, GLOBAL_ADMIN_ID
from entra_auditor.checks.mfa_ca import check_mfa_ca
from entra_auditor.models import GroupInfo
from tests.builders import NOW, ago, cfg, ids, mfa, only, policy, snapshot, user

ALL_ROLES = list(CRITICAL_ADMIN_ROLES)


def good_policies():
    """A complete, well-formed baseline: every recommended protection present, no weaknesses."""
    return [
        policy("mfa-all", "MFA all users", include_users=["All"], include_applications=["All"],
               grant_controls=["mfa"], grant_operator="OR"),
        policy("admins", "Admins: phishing-resistant", include_roles=ALL_ROLES, include_applications=["All"],
               authentication_strength_id="strength-1"),
        policy("legacy", "Block legacy auth", include_users=["All"], include_applications=["All"],
               client_app_types=["exchangeActiveSync", "other"], grant_controls=["block"], grant_operator="OR"),
        policy("secinfo", "Protect security info", include_users=["All"], include_user_actions=["urn:user:registersecurityinfo"],
               grant_controls=["mfa"], grant_operator="OR"),
        policy("signin-risk", "Sign-in risk", include_users=["All"], include_applications=["All"],
               sign_in_risk_levels=["medium", "high"], grant_controls=["mfa"], grant_operator="OR"),
        policy("user-risk", "User risk", include_users=["All"], include_applications=["All"],
               user_risk_levels=["high"], grant_controls=["passwordChange", "mfa"], grant_operator="AND"),
        policy("devcode", "Block device code", include_users=["All"], include_applications=["All"],
               authentication_flows=["deviceCodeFlow"], grant_controls=["block"], grant_operator="OR"),
        policy("compliant", "Compliant devices", include_users=["All"], include_applications=["Office365"],
               grant_controls=["compliantDevice"], grant_operator="OR"),
    ]


def run(policies, **snap):
    snap.setdefault("mfa_registrations", [])
    return check_mfa_ca(snapshot(ca_policies=policies, **snap), NOW, cfg())


def replaced(pid, **kw):
    """The good baseline with one policy changed."""
    return [policy(pid, **{**{k: v for k, v in p.model_dump().items() if k not in ("id", "display_name", "raw")}, **kw})
            if p.id == pid else p for p in good_policies()]


def without(pid):
    return [p for p in good_policies() if p.id != pid]


# ---- the baseline ------------------------------------------------------------------------

def test_a_complete_baseline_has_no_findings():
    assert run(good_policies()) == []


def test_removing_all_user_mfa_is_reported_with_its_consequences():
    findings = run(without("mfa-all"))
    assert only(findings, "CA_NO_MFA_ALL_USERS").severity == "high"
    assert only(findings, "CA_NO_AZURE_MANAGEMENT_MFA").severity == "high"
    assert only(findings, "CA_NO_GUEST_PROTECTION").severity == "medium"
    assert "CA_NO_MFA_ADMINS" not in ids(findings)          # the admin policy still covers admins


@pytest.mark.parametrize("pid,missing", [
    ("legacy", "CA_NO_LEGACY_AUTH_BLOCK"), ("secinfo", "CA_NO_SECURITY_INFO_PROTECTION"),
    ("signin-risk", "CA_NO_SIGNIN_RISK_POLICY"), ("user-risk", "CA_NO_USER_RISK_POLICY"),
    ("devcode", "CA_NO_DEVICE_CODE_BLOCK"), ("compliant", "CA_NO_DEVICE_CONTROLS"),
    ("admins", "CA_NO_ADMIN_AUTH_STRENGTH")])
def test_each_missing_protection_is_named(pid, missing):
    assert missing in ids(run(without(pid)))


def test_no_admin_mfa_at_all_is_critical():
    findings = run([p for p in good_policies() if p.id not in ("mfa-all", "admins")])
    assert only(findings, "CA_NO_MFA_ADMINS").severity == "critical"


def test_a_matching_policy_that_is_only_report_only_is_reported_one_level_lower():
    findings = run(replaced("mfa-all", state="enabledForReportingButNotEnforced"))
    finding = only(findings, "CA_NO_MFA_ALL_USERS")
    assert finding.severity == "medium" and "report-only" in finding.title and finding.evidence["status"] == "report_only"
    assert only(findings, "CA_POLICY_REPORT_ONLY").severity == "low"


def test_a_policy_narrowed_by_conditions_counts_as_partial_coverage():
    findings = run(replaced("mfa-all", include_platforms=["windows"]))
    finding = only(findings, "CA_NO_MFA_ALL_USERS")
    assert finding.severity == "medium" and "narrowed by conditions" in finding.title and finding.evidence["status"] == "partial"
    assert only(findings, "CA_MFA_NARROW_SCOPE").severity == "low"


@pytest.mark.parametrize("controls,severity", [
    (["mfa", "compliantDevice"], "low"),           # MFA OR a managed device: a deliberate, common design
    (["mfa", "approvedApplication"], "medium")])
def test_mfa_that_can_be_skipped_is_not_counted_and_is_explained(controls, severity):
    findings = run(replaced("mfa-all", grant_controls=controls))
    assert only(findings, "CA_NO_MFA_ALL_USERS").severity == "high"
    assert only(findings, "CA_MFA_BYPASSABLE").severity == severity


def test_requiring_all_controls_is_strict_mfa_even_with_several_controls():
    assert run(replaced("mfa-all", grant_controls=["mfa", "compliantDevice"], grant_operator="AND")) == []


def test_the_deprecated_approved_app_control_is_called_out():
    assert only(run(replaced("compliant", grant_controls=["approvedApplication"])), "CA_DEPRECATED_CONTROL").severity == "low"


# ---- exclusions --------------------------------------------------------------------------

def users(n):
    return [user(f"u{i}", f"user{i}@contoso.com") for i in range(n)]


def test_individual_user_exclusions_are_low_for_break_glass_pairs_and_medium_beyond():
    low = run(replaced("mfa-all", exclude_users=["u0", "u1"]), users=users(3))
    assert only(low, "CA_EXCLUDES_USERS").severity == "low"
    medium = run(replaced("mfa-all", exclude_users=["u0", "u1", "u2"]), users=users(3))
    assert only(medium, "CA_EXCLUDES_USERS").severity == "medium"


def test_excluded_users_are_named_and_deleted_ones_are_noticed():
    findings = run(replaced("mfa-all", exclude_users=["u0", "gone"]), users=users(2))
    assert "user0@contoso.com" in only(findings, "CA_EXCLUDES_USERS").title
    assert only(findings, "CA_ORPHANED_EXCLUSIONS").evidence["ids"] == ["gone"]


@pytest.mark.parametrize("info,severity", [
    (GroupInfo(id="g1", display_name="Exclusions", member_count=250), "high"),   # large
    (GroupInfo(id="g1", display_name="Exclusions", member_count=5), "medium"),
    (GroupInfo(id="g1", exists=False), "low"),                                   # deleted group
    (None, "medium")])                                                           # size unknown
def test_excluded_groups_are_rated_by_size(info, severity):
    findings = run(replaced("mfa-all", exclude_groups=["g1"]), ca_groups=[info] if info else None)
    assert only(findings, "CA_EXCLUDES_GROUPS").severity == severity


def test_excluded_group_names_and_sizes_appear():
    findings = run(replaced("mfa-all", exclude_groups=["g1"]), ca_groups=[GroupInfo(id="g1", display_name="Exclusions", member_count=250)])
    assert "Exclusions (250 members)" in only(findings, "CA_EXCLUDES_GROUPS").title


@pytest.mark.parametrize("role,severity", [(GLOBAL_ADMIN_ID, "high"), ("some-other-role", "medium")])
def test_excluding_admin_roles_is_serious(role, severity):
    assert only(run(replaced("mfa-all", exclude_roles=[role])), "CA_EXCLUDES_ADMIN_ROLES").severity == severity


def test_excluding_apps_guests_and_trusted_locations():
    assert only(run(replaced("mfa-all", exclude_applications=["app-x"])), "CA_EXCLUDES_APPS").severity == "medium"
    assert only(run(replaced("mfa-all", excludes_guests_or_external=True)), "CA_EXCLUDES_GUESTS").severity == "medium"
    trusted = run(replaced("mfa-all", exclude_locations=["AllTrusted"]))
    assert only(trusted, "CA_MFA_SKIPPED_FROM_TRUSTED_LOCATIONS").severity == "medium"


def two_all_user_policies(**second):
    return [policy("a", include_users=["All"], include_applications=["All"], grant_controls=["mfa"], exclude_users=["bg"]),
            policy("b", include_users=["All"], include_applications=["All"], grant_controls=["block"],
                   client_app_types=["other"], exclude_users=["bg"], **second)]


def test_accounts_excluded_from_every_policy_are_flagged_medium_when_it_looks_like_break_glass():
    finding = only(run(two_all_user_policies(), users=[user("bg", "breakglass@contoso.com")]), "CA_EXCLUDED_FROM_ALL_POLICIES")
    assert finding.severity == "medium" and "breakglass@contoso.com" in finding.evidence["excluded"][0]


def test_more_than_two_accounts_or_any_group_excluded_everywhere_is_high():
    many = [policy(p, include_users=["All"], include_applications=["All"], grant_controls=["mfa"], exclude_users=["a", "b", "c"]) for p in ("x", "y")]
    assert only(run(many), "CA_EXCLUDED_FROM_ALL_POLICIES").severity == "high"
    grouped = [policy(p, include_users=["All"], include_applications=["All"], grant_controls=["mfa"], exclude_groups=["g"]) for p in ("x", "y")]
    assert only(run(grouped), "CA_EXCLUDED_FROM_ALL_POLICIES").severity == "high"


def test_exclusions_shared_by_only_one_policy_or_with_report_only_policies_do_not_count():
    assert "CA_EXCLUDED_FROM_ALL_POLICIES" not in ids(run(two_all_user_policies()[:1]))
    report_only = two_all_user_policies()
    report_only[1] = policy("b", state="enabledForReportingButNotEnforced", include_users=["All"], include_applications=["All"],
                            grant_controls=["block"], exclude_users=["bg"])
    assert "CA_EXCLUDED_FROM_ALL_POLICIES" not in ids(run(report_only))


# ---- other per-policy findings -----------------------------------------------------------

def test_report_only_policies_are_medium_once_they_have_been_stuck_for_a_while():
    stuck = run(replaced("compliant", state="enabledForReportingButNotEnforced", modified_at=ago(60)))
    assert only(stuck, "CA_POLICY_REPORT_ONLY").severity == "medium"
    recent = run(replaced("compliant", state="enabledForReportingButNotEnforced", modified_at=ago(5)))
    assert only(recent, "CA_POLICY_REPORT_ONLY").severity == "low"


def test_disabled_policies_are_noted_and_nothing_else_is_said_about_them():
    findings = run(good_policies() + [policy("old", "Old", state="disabled", include_users=["All"], exclude_users=["x", "y", "z"], grant_controls=["block"])])
    old = [f for f in findings if f.resource_id == "old"]
    assert [f.check_id for f in old] == ["CA_POLICY_DISABLED"] and old[0].severity == "info"


def test_policies_that_do_nothing_or_target_nobody():
    extra = policy("noop", include_users=["All"], include_applications=["All"])
    assert only(run(good_policies() + [extra]), "CA_POLICY_NO_EFFECT").severity == "low"
    nobody = policy("nobody", include_users=["None"], include_applications=["All"], grant_controls=["block"])
    assert only(run(good_policies() + [nobody]), "CA_POLICY_TARGETS_NOBODY").severity == "low"


def test_a_block_everything_policy_is_a_lockout_risk():
    everything = policy("all", include_users=["All"], include_applications=["All"], grant_controls=["block"])
    assert only(run(good_policies() + [everything]), "CA_BLOCKS_EVERYTHING").severity == "high"
    guarded = policy("all", include_users=["All"], include_applications=["All"], grant_controls=["block"], exclude_users=["bg"])
    assert only(run(good_policies() + [guarded]), "CA_BLOCKS_EVERYTHING").severity == "medium"


@pytest.mark.parametrize("roles,severity", [([r for r in ALL_ROLES if r != GLOBAL_ADMIN_ID], "high"), ([r for r in ALL_ROLES if r != ALL_ROLES[-1]], "medium")])
def test_admin_roles_missing_from_every_mfa_policy_are_listed(roles, severity):
    policies = [policy("admins", include_roles=roles, include_applications=["All"], grant_controls=["mfa"])]
    finding = only(run(policies), "CA_ADMIN_MFA_ROLE_GAP")
    assert finding.severity == severity and len(finding.evidence["uncovered_roles"]) == 1


def test_a_policy_for_all_users_that_excludes_one_admin_role_leaves_a_gap():
    policies = [policy("all", include_users=["All"], include_applications=["All"], grant_controls=["mfa"], exclude_roles=[GLOBAL_ADMIN_ID])]
    finding = only(run(policies), "CA_ADMIN_MFA_ROLE_GAP")
    assert finding.severity == "high" and "Global Administrator" in finding.title


# ---- no policies / no data ---------------------------------------------------------------

@pytest.mark.parametrize("defaults,check_id,severity", [
    (True, "CA_SECURITY_DEFAULTS_ONLY", "low"), (False, "CA_NO_MFA_ENFORCEMENT", "critical"), (None, "CA_NO_MFA_ENFORCEMENT", "high")])
def test_a_tenant_with_no_policies(defaults, check_id, severity):
    findings = run([], security_defaults_enabled=defaults)
    assert only(findings, check_id).severity == severity and len(findings) == 1


def test_unreadable_policies_are_reported_not_assumed_empty():
    findings = check_mfa_ca(snapshot(ca_policies=None, mfa_registrations=[]), NOW, cfg())
    assert ids(findings) == ["CA_DATA_UNAVAILABLE"]


# ---- MFA registration --------------------------------------------------------------------

def registration(total, not_capable, **kw):
    people = users(total)
    regs = [mfa(u.id, capable=i >= not_capable, registered=i >= not_capable) for i, u in enumerate(people)]
    return run(good_policies(), users=people, mfa_registrations=regs, **kw)


@pytest.mark.parametrize("total,bad,severity", [(100, 1, "low"), (20, 1, "medium"), (20, 4, "medium"), (20, 5, "high"), (4, 4, "high")])
def test_registration_gap_severity_follows_the_share_of_users(total, bad, severity):
    finding = only(registration(total, bad), "MFA_REGISTRATION_GAP")
    assert finding.severity == severity and finding.evidence["not_capable_count"] == bad


def test_everyone_capable_means_no_finding():
    assert registration(10, 0) == []


def test_guests_disabled_accounts_and_unknown_users_are_not_counted():
    people = [user("m1"), user("g1", user_type="Guest"), user("d1", account_enabled=False)]
    regs = [mfa("m1"), mfa("g1", capable=False), mfa("d1", capable=False), mfa("ghost", capable=False)]
    assert run(good_policies(), users=people, mfa_registrations=regs) == []


def test_unavailable_registration_data_is_reported_as_unavailable():
    assert "MFA_DATA_UNAVAILABLE" in ids(check_mfa_ca(snapshot(ca_policies=good_policies(), mfa_registrations=None), NOW, cfg()))


def test_registration_evidence_is_capped():
    people = users(150)
    regs = [mfa(u.id, capable=False, registered=False) for u in people]
    finding = only(run(good_policies(), users=people, mfa_registrations=regs), "MFA_REGISTRATION_GAP")
    assert len(finding.evidence["users"]) == 100 and finding.evidence["users_truncated"] is True
