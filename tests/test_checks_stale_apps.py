import pytest

from entra_auditor.checks.stale_apps import check_stale_apps
from entra_auditor.models import MICROSOFT_TENANT_ID
from tests.builders import NOW, ago, app, cfg, cred, ids, later, only, snapshot, sp


def run(apps=None, sps=None, sign_ins=True, **snap):
    return check_stale_apps(snapshot(applications=apps, service_principals=sps, sp_sign_in_data_available=sign_ins, **snap), NOW, cfg())


# ---- credentials -------------------------------------------------------------------------

def with_creds(*creds):
    return run([app(credentials=list(creds))], sps=[])


def test_an_expired_credential_with_no_replacement_is_medium_and_with_one_low():
    assert only(with_creds(cred(end=ago(40))), "APP_CREDENTIAL_EXPIRED").severity == "medium"
    both = with_creds(cred(end=ago(40), key="old"), cred(end=later(300), key="new"))
    assert only(both, "APP_CREDENTIAL_EXPIRED").severity == "low"


@pytest.mark.parametrize("days_left,severity", [(5, "high"), (7, "high"), (8, "medium"), (29, "medium")])
def test_credentials_about_to_expire(days_left, severity):
    finding = only(with_creds(cred(end=later(days_left) + (NOW - NOW))), "APP_CREDENTIAL_EXPIRING")
    assert finding.severity == severity and finding.evidence["has_replacement"] is False


def test_credentials_beyond_the_warning_window_or_without_an_end_are_fine():
    assert "APP_CREDENTIAL_EXPIRING" not in ids(with_creds(cred(end=later(90))))
    assert with_creds(cred(end=None)) == []


def test_a_successor_credential_means_rotation_is_underway_so_one_level_lower():
    rotating = with_creds(cred(end=later(5), key="old"), cred(end=later(300), key="new"))
    finding = only(rotating, "APP_CREDENTIAL_EXPIRING")
    assert finding.severity == "medium" and finding.evidence["has_replacement"] is True


def test_a_replacement_that_expires_sooner_does_not_count():
    findings = with_creds(cred(end=later(20), key="a"), cred(end=later(10), key="b"))
    assert [f.evidence["days_left"] for f in findings if f.check_id == "APP_CREDENTIAL_EXPIRING"] == [20, 10]
    assert next(f for f in findings if f.evidence["days_left"] == 20).evidence["has_replacement"] is False


def test_long_lived_secrets_are_flagged_but_certificates_and_expired_ones_are_not():
    assert only(with_creds(cred(start=ago(10), end=later(1000))), "APP_SECRET_LONG_LIVED").severity == "low"
    assert "APP_SECRET_LONG_LIVED" not in ids(with_creds(cred(kind="certificate", start=ago(10), end=later(1000))))
    assert "APP_SECRET_LONG_LIVED" not in ids(with_creds(cred(start=ago(2000), end=ago(10))))
    assert "APP_SECRET_LONG_LIVED" not in ids(with_creds(cred(start=ago(10), end=later(700))))


def test_service_principal_credentials_such_as_saml_certificates_are_checked_too():
    findings = run(sps=[sp(credentials=[cred(kind="certificate", end=ago(3))])], apps=[])
    finding = only(findings, "APP_CREDENTIAL_EXPIRED")
    assert finding.resource_type == "servicePrincipal"


# ---- service principals ------------------------------------------------------------------

def inactive(**kw):
    return only(run(sps=[sp(**kw)], apps=[]), "SP_INACTIVE")


@pytest.mark.parametrize("days,flagged", [(90, False), (91, True)])
def test_inactivity_threshold_is_strict(days, flagged):
    assert ("SP_INACTIVE" in ids(run(sps=[sp(last_sign_in=ago(days))], apps=[]))) is flagged


def test_never_signed_in_counts_once_the_service_principal_is_old_enough():
    assert inactive().severity == "low"
    assert "SP_INACTIVE" not in ids(run(sps=[sp(created_at=ago(30))], apps=[]))


@pytest.mark.parametrize("roles,severity", [
    ([], "low"), (["Mail.Read"], "medium"), (["User.ReadWrite.All"], "high"), (["Directory.ReadWrite.All"], "high")])
def test_an_inactive_app_that_can_still_change_the_directory_is_worse(roles, severity):
    assert inactive(graph_app_roles=roles).severity == severity


@pytest.mark.parametrize("kwargs", [
    dict(service_principal_type="ManagedIdentity"), dict(account_enabled=False),
    dict(app_owner_organization_id=MICROSOFT_TENANT_ID)])
def test_managed_identities_disabled_and_microsoft_apps_are_not_reported_inactive(kwargs):
    assert "SP_INACTIVE" not in ids(run(sps=[sp(**kwargs)], apps=[]))


def test_without_sign_in_data_inactivity_is_skipped_with_an_info_finding():
    findings = run(sps=[sp()], apps=[], sign_ins=False)
    assert "SP_INACTIVE" not in ids(findings) and only(findings, "SP_SIGNIN_DATA_UNAVAILABLE").severity == "info"


@pytest.mark.parametrize("permission,severity", [
    ("RoleManagement.ReadWrite.Directory", "critical"), ("AppRoleAssignment.ReadWrite.All", "critical"),
    ("Mail.Send", "high"), ("Directory.Read.All", "medium")])
def test_powerful_graph_permissions_are_rated_by_what_they_allow(permission, severity):
    finding = only(run(sps=[sp(graph_app_roles=[permission], last_sign_in=ago(1))], apps=[]), "SP_HIGH_PRIVILEGE_GRANT")
    assert finding.severity == severity and finding.evidence["permissions"][0]["permission"] == permission


def test_ordinary_permissions_and_microsoft_apps_are_not_flagged():
    assert "SP_HIGH_PRIVILEGE_GRANT" not in ids(run(sps=[sp(graph_app_roles=["User.Read"], last_sign_in=ago(1))], apps=[]))
    first_party = sp(graph_app_roles=["Directory.ReadWrite.All"], app_owner_organization_id=MICROSOFT_TENANT_ID, last_sign_in=ago(1))
    assert run(sps=[first_party], apps=[]) == []


def test_managed_identities_with_powerful_permissions_are_still_reported():
    managed = sp(service_principal_type="ManagedIdentity", graph_app_roles=["Directory.ReadWrite.All"])
    assert "SP_HIGH_PRIVILEGE_GRANT" in ids(run(sps=[managed], apps=[]))


# ---- app registrations -------------------------------------------------------------------

def test_apps_without_owners():
    assert only(run(apps=[app(owner_count=0)], sps=[]), "APP_NO_OWNER").severity == "low"
    assert run(apps=[app(owner_count=None)], sps=[]) == []        # unknown is never flagged
    assert run(apps=[app(owner_count=2)], sps=[]) == []


def test_an_app_with_only_expired_credentials_and_an_inactive_service_principal_is_probably_abandoned():
    a = app("a1", credentials=[cred(end=ago(50))])
    findings = run(apps=[a], sps=[sp("s1", app_id=a.app_id)])
    assert only(findings, "APP_LIKELY_ABANDONED").severity == "medium"


@pytest.mark.parametrize("a,s", [
    (app("a1", credentials=[cred(end=ago(50)), cred(end=later(100), key="k2")]), sp("s1", app_id="app-a1")),   # a valid credential
    (app("a1", credentials=[cred(end=ago(50))]), sp("s1", app_id="app-a1", last_sign_in=ago(2))),            # still signing in
    (app("a1", credentials=[]), sp("s1", app_id="app-a1")),                                                   # no credentials at all
    (app("a1", credentials=[cred(end=ago(50))]), sp("s9", app_id="someone-else")),                            # no matching SP
])
def test_apps_that_are_not_abandoned(a, s):
    assert "APP_LIKELY_ABANDONED" not in ids(run(apps=[a], sps=[s]))


def test_abandonment_needs_sign_in_data():
    a = app("a1", credentials=[cred(end=ago(50))])
    assert "APP_LIKELY_ABANDONED" not in ids(run(apps=[a], sps=[sp("s1", app_id=a.app_id)], sign_ins=False))


def test_data_unavailable_only_when_nothing_was_collected():
    assert ids(check_stale_apps(snapshot(), NOW, cfg())) == ["APPS_DATA_UNAVAILABLE"]
    assert "APPS_DATA_UNAVAILABLE" not in ids(run(apps=[app()], sps=None))
