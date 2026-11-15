import pytest

from entra_auditor.checks.inactive_users import check_inactive_users
from tests.builders import NOW, ago, cfg, ids, only, snapshot, user


def run(users, config=None, **snap):
    return check_inactive_users(snapshot(users=users, **snap), NOW, config or cfg())


def test_a_member_inactive_beyond_the_threshold_is_flagged_low():
    finding = only(run([user(last_sign_in=ago(91))]), "INACTIVE_USER")
    assert finding.severity == "low" and finding.evidence["days_inactive"] == 91 and finding.evidence["threshold_days"] == 90


@pytest.mark.parametrize("days,flagged", [(89, False), (90, False), (91, True)])
def test_the_threshold_is_strict(days, flagged):
    assert ("INACTIVE_USER" in ids(run([user(last_sign_in=ago(days))]))) is flagged


@pytest.mark.parametrize("days,flagged", [(60, False), (61, True)])
def test_guests_use_a_stricter_threshold_and_are_medium(days, flagged):
    findings = run([user(user_type="Guest", last_sign_in=ago(days))])
    assert ("INACTIVE_USER" in ids(findings)) is flagged
    if flagged:
        assert only(findings, "INACTIVE_USER").severity == "medium"


def test_the_newest_sign_in_of_any_kind_counts():
    # interactive sign-in is old, but a non-interactive one (e.g. a mail client) was recent
    assert run([user(last_sign_in=ago(200), last_non_interactive_sign_in=ago(5))]) == []


def test_never_signed_in_accounts_are_flagged_once_old_enough():
    assert only(run([user(created_at=ago(120))]), "NEVER_SIGNED_IN").evidence["account_age_days"] == 120


@pytest.mark.parametrize("age", [10, 90])
def test_new_accounts_get_time_to_sign_in(age):
    assert run([user(created_at=ago(age))]) == []


def test_accounts_of_unknown_age_are_not_guessed_about():
    assert run([user(created_at=None)]) == []


def test_disabled_accounts_are_ignored_but_unknown_status_counts_as_enabled():
    assert run([user(account_enabled=False, last_sign_in=ago(400))]) == []
    assert "INACTIVE_USER" in ids(run([user(account_enabled=None, last_sign_in=ago(400))]))


def test_thresholds_are_configurable():
    users = [user(last_sign_in=ago(40))]
    assert run(users) == [] and "INACTIVE_USER" in ids(run(users, cfg(inactive_days=30)))


def pending(changed_days=None, created_days=100):
    return user("g1", user_type="Guest", external_user_state="PendingAcceptance", created_at=ago(created_days),
                external_user_state_changed_at=ago(changed_days) if changed_days is not None else None)


def test_stale_guest_invitations_are_flagged_and_not_double_reported():
    findings = run([pending(changed_days=45)])
    assert ids(findings) == ["GUEST_INVITE_PENDING"] and findings[0].evidence["days_pending"] == 45


@pytest.mark.parametrize("changed,created,flagged", [(30, 100, False), (31, 100, True), (None, 31, True), (None, 20, False)])
def test_invitation_age_uses_the_state_change_then_the_creation_date(changed, created, flagged):
    assert bool(run([pending(changed, created)])) is flagged


def test_accepted_invitations_are_ordinary_guests():
    accepted = user("g1", user_type="Guest", external_user_state="Accepted", last_sign_in=ago(10))
    assert run([accepted]) == []


def test_without_sign_in_data_only_an_info_finding_and_invitations_remain():
    findings = run([user(last_sign_in=ago(400)), pending(changed_days=45)], sign_in_data_available=False)
    assert sorted(ids(findings)) == ["GUEST_INVITE_PENDING", "SIGNIN_DATA_UNAVAILABLE"]
    assert only(findings, "SIGNIN_DATA_UNAVAILABLE").severity == "info"


def test_findings_identify_the_user():
    finding = only(run([user("u7", "bob@contoso.com", last_sign_in=ago(200))]), "INACTIVE_USER")
    assert (finding.resource_type, finding.resource_id, finding.resource_name) == ("user", "u7", "bob@contoso.com")
    assert finding.fingerprint == "INACTIVE_USER|user|u7|"
