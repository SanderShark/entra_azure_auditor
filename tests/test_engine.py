import pytest

from entra_auditor import engine
from entra_auditor.auth import AuthenticationError
from entra_auditor.checks import CHECKS
from entra_auditor.engine import RunStatus, analyze_snapshot, diff_runs, required_permissions, resolve_checks, run_audit
from entra_auditor.graph.client import GraphAuthError, GraphError
from tests.builders import NOW, ago, finding, make_run, snapshot, user
from tests.fakes import FakeGraph


def clock():
    return NOW


def snap():
    return snapshot(users=[user("u1", last_sign_in=ago(200)), user("u2", last_sign_in=ago(1)), user("g1", user_type="Guest", last_sign_in=ago(5))])


# ---- selecting checks --------------------------------------------------------------------

def test_resolve_checks_accepts_none_all_csv_and_lists():
    everything = list(CHECKS)
    assert resolve_checks(None) == resolve_checks("all") == resolve_checks("") == everything
    assert resolve_checks("privileged,inactive") == ["inactive", "privileged"]       # canonical order
    assert resolve_checks(["mfa_ca", "mfa_ca", " groups "]) == ["mfa_ca", "groups"]  # de-duplicated, trimmed


def test_resolve_checks_rejects_unknown_names():
    with pytest.raises(ValueError, match="Unknown check.*bogus"):
        resolve_checks("inactive,bogus")


def test_required_permissions_are_the_union():
    assert {"User.Read.All", "Policy.Read.All"} <= required_permissions(["inactive", "mfa_ca"])
    assert required_permissions([]) == set()


def test_every_check_declares_its_data_and_permissions():
    assert set(CHECKS) == set(engine.CHECK_SECTIONS) == set(engine.REQUIRED_PERMISSIONS)


# ---- analysing a snapshot ----------------------------------------------------------------

def test_analysis_produces_a_complete_run():
    run = analyze_snapshot(snap(), checks=["inactive"], identity="app:x", clock=clock)
    assert run.status is RunStatus.COMPLETED and run.identity == "app:x" and run.checks == ["inactive"]
    assert [f.check_id for f in run.findings] == ["INACTIVE_USER"]
    assert run.inventory["users"] == 3 and run.inventory["guests"] == 1 and run.inventory["applications"] is None
    assert run.config["inactive_days"] == 90


def test_ages_are_measured_from_when_the_data_was_collected():
    old = snapshot(collected_at=ago(300), users=[user("u1", last_sign_in=ago(320))])       # 20 days quiet back then
    assert analyze_snapshot(old, checks=["inactive"], clock=clock).findings == []


def test_findings_are_sorted_worst_first_and_summarised():
    run = analyze_snapshot(snapshot(users=[user("u1", last_sign_in=ago(200)), user("g1", user_type="Guest", last_sign_in=ago(200))]),
                           checks=["inactive"], clock=clock)
    assert [f.severity for f in run.findings] == ["medium", "low"]
    summary = run.summary()
    assert summary.total == 2 and summary.by_severity["medium"] == 1 and summary.highest_severity == "medium"
    assert [f.severity for f in run.findings_at_or_above("medium")] == ["medium"]


def test_a_crashing_check_is_isolated_and_the_run_is_marked_partial(monkeypatch):
    def broken(snapshot_, now, config):
        raise RuntimeError("boom")

    monkeypatch.setitem(CHECKS, "privileged", broken)
    run = analyze_snapshot(snap(), checks=["inactive", "privileged"], clock=clock)
    assert run.status is RunStatus.PARTIAL
    assert any("'privileged' crashed" in w and "boom" in w for w in run.warnings)
    assert [f.check_id for f in run.findings] == ["INACTIVE_USER"]       # the other check still ran


def test_collection_warnings_are_carried_into_the_run():
    run = analyze_snapshot(snapshot(warnings=["a", "b", "a"]), checks=["inactive"], clock=clock)
    assert run.warnings == ["a", "b"]


def test_policy_profiles_are_included_when_the_ca_check_runs():
    from tests.builders import policy
    run = analyze_snapshot(snapshot(ca_policies=[policy(include_users=["All"], grant_controls=["mfa"])], mfa_registrations=[]),
                           checks=["mfa_ca"], clock=clock)
    assert len(run.policies) == 1 and run.policies[0].action == "grant"


# ---- running an audit --------------------------------------------------------------------

def test_an_audit_of_one_check_collects_only_what_that_check_needs():
    # FakeGraph fails the test if any other endpoint is requested
    graph = FakeGraph({"/users": [{"id": "u1", "userPrincipalName": "a@x.com", "accountEnabled": True,
                                   "createdDateTime": "2020-01-01T00:00:00Z"}]})
    run = run_audit(graph, "tenant", checks=["inactive"], clock=clock)
    assert run.status is RunStatus.COMPLETED and [f.check_id for f in run.findings] == ["NEVER_SIGNED_IN"]
    assert [call[0] for call in graph.calls] == ["/users"]


@pytest.mark.parametrize("error", [GraphAuthError("401 expired", status_code=401), GraphError("500 broke", status_code=500),
                                   AuthenticationError("no cached sign-in")])
def test_a_failure_to_collect_gives_a_failed_run_instead_of_an_exception(error):
    run = run_audit(FakeGraph({"/users": error}), "tenant", checks=["inactive"], clock=clock)
    assert run.status is RunStatus.FAILED and run.findings == [] and str(error) in run.error


# ---- comparing runs ----------------------------------------------------------------------

def test_diff_runs_finds_new_resolved_persisting_and_changed():
    old = make_run([finding(rid="a"), finding(rid="b"), finding(rid="c", severity="low")], checks=["inactive"])
    new = make_run([finding(rid="b"), finding(rid="c", severity="high"), finding(rid="d")], checks=["inactive"])
    diff = diff_runs(old, new)
    assert [f.resource_id for f in diff.new] == ["d"] and [f.resource_id for f in diff.resolved] == ["a"]
    assert sorted(f.resource_id for f in diff.persisting) == ["b", "c"]
    assert [(c.old, c.new) for c in diff.severity_changed] == [("low", "high")] and not diff.checks_differ


def test_diff_warns_when_the_two_runs_used_different_checks():
    assert diff_runs(make_run(checks=["inactive"]), make_run(checks=["inactive", "groups"])).checks_differ
