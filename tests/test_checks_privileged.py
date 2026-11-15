import pytest

from entra_auditor.checks._common import GLOBAL_ADMIN_ID
from entra_auditor.checks.privileged import check_privileged
from tests.builders import GA, NOW, ago, cfg, ids, mfa, only, role, snapshot, user

PRA = "e8611ab8-c189-46e8-94e1-60213ab1f814"        # tier 0
SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"   # critical but not tier 0


def admin(uid="u1", **kw):
    return user(uid, last_sign_in=ago(1), **kw)


def run(assignments, users=None, regs="strong", **snap):
    assignments = list(assignments)
    if users is None:
        users = [admin(a.principal_id) for a in assignments if a.principal_type == "user"]
    if regs == "strong":
        regs = [mfa(u.id) for u in users]
    return check_privileged(snapshot(role_assignments=assignments, users=users, mfa_registrations=regs, **snap), NOW, cfg())


def for_resource(findings, rid):
    return [f for f in findings if f.resource_id == rid]


def test_data_unavailable():
    assert ids(check_privileged(snapshot(role_assignments=None), NOW, cfg())) == ["PRIV_DATA_UNAVAILABLE"]


# ---- how many Global Administrators ------------------------------------------------------

def global_admins(n):
    return [role(f"ga{i}") for i in range(n)]


@pytest.mark.parametrize("count,expected,severity", [(6, "PRIV_TOO_MANY_GLOBAL_ADMINS", "high"), (1, "PRIV_TOO_FEW_GLOBAL_ADMINS", "medium")])
def test_too_many_or_too_few_global_admins(count, expected, severity):
    assert only(run(global_admins(count), eligible_roles_available=False), expected).severity == severity


@pytest.mark.parametrize("count", [2, 5])
def test_two_to_five_global_admins_is_fine(count):
    found = ids(run(global_admins(count), eligible_roles_available=False))
    assert "PRIV_TOO_MANY_GLOBAL_ADMINS" not in found and "PRIV_TOO_FEW_GLOBAL_ADMINS" not in found


def test_disabled_global_admins_are_not_counted():
    assignments = global_admins(6)
    users = [admin(a.principal_id, account_enabled=(a.principal_id != "ga0")) for a in assignments]
    assert "PRIV_TOO_MANY_GLOBAL_ADMINS" not in ids(run(assignments, users, eligible_roles_available=False))


def test_a_person_holding_the_role_directly_and_through_a_group_counts_once():
    finding = only(run([role("ga0"), role("ga0", via_group_id="g1")], eligible_roles_available=False),
                   "PRIV_TOO_FEW_GLOBAL_ADMINS")
    assert finding.evidence["count"] == 1


def test_eligible_admins_count_toward_the_total():
    found = ids(run([role("ga0"), role("ga1", state="eligible")], eligible_roles_available=False))
    assert "PRIV_TOO_FEW_GLOBAL_ADMINS" not in found     # two people hold it


# ---- MFA ---------------------------------------------------------------------------------

def mfa_findings(regs, assignments=None, **kw):
    assignments = assignments or [role("u1")]
    return for_resource(run(assignments, regs=regs, eligible_roles_available=False, **kw), "u1")


def test_an_active_admin_without_mfa_is_critical_and_an_eligible_one_high():
    no_mfa = [mfa("u1", registered=False, methods=())]
    assert only(mfa_findings(no_mfa), "PRIV_ADMIN_NO_MFA").severity == "critical"
    assert only(mfa_findings(no_mfa, [role("u1", state="eligible")]), "PRIV_ADMIN_NO_MFA").severity == "high"


@pytest.mark.parametrize("role_id,name,severity", [(GA, "Global Administrator", "high"), (SECURITY_ADMIN, "Security Administrator", "medium")])
def test_phone_only_mfa_is_weak(role_id, name, severity):
    findings = mfa_findings([mfa("u1", methods=("mobilePhone", "email"))], [role("u1", role_id=role_id, name=name)])
    assert only(findings, "PRIV_ADMIN_WEAK_MFA").severity == severity


def test_a_strong_method_or_a_missing_registration_record_raises_nothing():
    assert "PRIV_ADMIN_WEAK_MFA" not in ids(mfa_findings([mfa("u1", methods=("mobilePhone", "fido2SecurityKey"))]))
    assert not any(i.startswith("PRIV_ADMIN") and "MFA" in i for i in ids(mfa_findings([])))
    assert not any("MFA" in i for i in ids(mfa_findings(None)))


# ---- inactivity --------------------------------------------------------------------------

def test_admins_have_the_strictest_inactivity_threshold():
    quiet = [user("u1", last_sign_in=ago(46))]
    assert only(for_resource(run([role("u1")], quiet, eligible_roles_available=False), "u1"), "PRIV_INACTIVE_ADMIN").severity == "high"
    eligible_only = for_resource(run([role("u1", state="eligible")], quiet, eligible_roles_available=False), "u1")
    assert only(eligible_only, "PRIV_INACTIVE_ADMIN").severity == "medium"
    assert "PRIV_INACTIVE_ADMIN" not in ids(run([role("u1")], [user("u1", last_sign_in=ago(45))], eligible_roles_available=False))


def test_an_admin_who_never_signed_in_is_flagged():
    findings = run([role("u1")], [user("u1", created_at=ago(100))], eligible_roles_available=False)
    assert only(for_resource(findings, "u1"), "PRIV_INACTIVE_ADMIN").evidence["never_signed_in"] is True


def test_inactivity_is_skipped_without_sign_in_data():
    findings = run([role("u1")], [user("u1", last_sign_in=ago(400))], sign_in_data_available=False, eligible_roles_available=False)
    assert "PRIV_INACTIVE_ADMIN" not in ids(findings)


# ---- standing access and PIM -------------------------------------------------------------

def permanent(assignments):
    return [f for f in run(assignments) if f.check_id == "PRIV_PERMANENT_ASSIGNMENT"]


def test_standing_access_is_flagged_more_severely_for_tier_zero_roles():
    assert [f.severity for f in permanent([role("u1")])] == ["high"]
    assert [f.severity for f in permanent([role("u1", role_id=SECURITY_ADMIN, name="Security Administrator")])] == ["medium"]
    assert [f.severity for f in permanent([role("u1", role_id=PRA, name="Privileged Role Administrator")])] == ["high"]


def test_scoped_assignments_are_one_level_lower():
    assert [f.severity for f in permanent([role("u1", directory_scope_id="/administrativeUnits/au1")])] == ["medium"]


@pytest.mark.parametrize("kwargs", [
    dict(activated_via_pim=True), dict(end_date_time=ago(-30)), dict(state="eligible")])
def test_pim_activations_time_bound_and_eligible_assignments_are_not_standing(kwargs):
    assert permanent([role("u1", **kwargs)]) == []


def test_without_pim_standing_access_is_not_reported_per_assignment():
    findings = run([role("u1")], eligible_roles_available=False)
    assert "PRIV_PERMANENT_ASSIGNMENT" not in ids(findings)
    assert only(findings, "PRIV_PIM_UNAVAILABLE").severity == "info"


# ---- who holds the role ------------------------------------------------------------------

def test_guest_admins_are_critical_for_tier_zero_and_high_otherwise():
    guest = user("u1", user_type="Guest", last_sign_in=ago(1))
    assert only(for_resource(run([role("u1")], [guest], eligible_roles_available=False), "u1"), "PRIV_GUEST_ADMIN").severity == "critical"
    other = run([role("u1", role_id=SECURITY_ADMIN, name="Security Administrator")], [guest], eligible_roles_available=False)
    assert only(for_resource(other, "u1"), "PRIV_GUEST_ADMIN").severity == "high"


def test_service_principals_holding_roles():
    sp = role("sp1", ptype="servicePrincipal")
    assert only(run([sp], users=[]), "PRIV_SERVICE_PRINCIPAL_ROLE").severity == "high"
    sec = role("sp1", ptype="servicePrincipal", role_id=SECURITY_ADMIN, name="Security Administrator")
    assert only(run([sec], users=[]), "PRIV_SERVICE_PRINCIPAL_ROLE").severity == "medium"


def test_a_disabled_account_still_holding_a_role_stops_further_checks():
    findings = for_resource(run([role("u1")], [user("u1", account_enabled=False)], regs=[mfa("u1", registered=False)]), "u1")
    assert ids(findings) == ["PRIV_DISABLED_ACCOUNT"] and findings[0].severity == "medium"


@pytest.mark.parametrize("role_id,name,severity", [(GA, "Global Administrator", "medium"), (SECURITY_ADMIN, "Security Administrator", "low")])
def test_admins_synced_from_on_premises(role_id, name, severity):
    findings = run([role("u1", role_id=role_id, name=name)], [admin("u1", on_prem_synced=True)], eligible_roles_available=False)
    assert only(for_resource(findings, "u1"), "PRIV_SYNCED_ADMIN").severity == severity


def test_too_many_roles_on_one_account():
    names = [("194ae4cb-b126-40b2-bd5b-6091b380977d", "Security Administrator"), ("29232cdf-9323-42fd-ade2-1d097af3e4de", "Exchange Administrator"),
             ("f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "SharePoint Administrator"), ("fe930be7-5e62-47db-91af-98c3a49a38b1", "User Administrator")]
    many = [role("u1", role_id=i, name=n) for i, n in names]
    finding = only(for_resource(run(many, eligible_roles_available=False), "u1"), "PRIV_EXCESSIVE_ROLES")
    assert finding.severity == "low" and finding.evidence["role_count"] == 4
    assert "PRIV_EXCESSIVE_ROLES" not in ids(run(many[:3], eligible_roles_available=False))


def test_roles_for_principals_that_no_longer_exist():
    orphan = role("gone", ptype="unknown", principal_upn=None)
    assert only(run([orphan], users=[]), "PRIV_ORPHANED_ASSIGNMENT").severity == "low"


def test_unprivileged_roles_and_group_objects_produce_no_holder_findings():
    harmless = role("u1", role_id="some-other-role", name="Reports Reader", is_privileged_role=False)
    group = role("g1", ptype="group")
    findings = run([harmless, group], users=[admin("u1")], eligible_roles_available=False)
    assert for_resource(findings, "u1") == [] and for_resource(findings, "g1") == []


def test_microsofts_own_privileged_flag_also_counts():
    flagged = role("u1", role_id="custom-privileged", name="Custom privileged role", is_privileged_role=True)
    assert "PRIV_PERMANENT_ASSIGNMENT" in ids(run([flagged]))


def test_findings_carry_the_roles_as_evidence():
    finding = only(permanent([role("u1")]), "PRIV_PERMANENT_ASSIGNMENT")
    assert finding.evidence["roles"][0]["role"] == "Global Administrator" and finding.evidence["roles"][0]["permanent"] is True
    assert finding.key == f"{GLOBAL_ADMIN_ID}:/"
