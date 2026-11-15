import csv
import io
import json
import os
import stat

import pytest

from entra_auditor import reports
from entra_auditor.checks.ca_analysis import analyze_policies
from tests.builders import NOW, ago, cfg, finding, make_run, policy, snapshot


def group_finding(check_id, name, gid, severity, **evidence):
    base = {"kind_label": "Security", "owners": 0, "user_members": 0, "other_members": 0, "created": "2024-01-01",
            "age_days": 800, "synced_from_ad": False, "dynamic_rule": None, "usage": []}
    return finding(check_id, severity, gid, resource_type="group", resource_name=name, evidence={**base, **evidence})


def policy_run(**kw):
    policies = analyze_policies(snapshot(ca_policies=[
        policy("p1", "MFA all", include_users=["All"], include_applications=["All"], grant_controls=["mfa"], exclude_users=["bg"]),
        policy("p2", "Block legacy", include_users=["All"], include_applications=["All"], client_app_types=["other"], grant_controls=["block"])]), cfg(), NOW)
    return make_run(policies=policies, **kw)


# ---- JSON --------------------------------------------------------------------------------

def test_json_contains_summary_and_everything_needed_to_reload(tmp_path):
    run = policy_run(findings=[finding(evidence={"days": 3}), finding("X", "high", "u2")])
    data = json.loads(reports.render_json(run))
    assert data["schema_version"] == 1 and data["summary"]["total"] == 2 and data["summary"]["highest_severity"] == "high"
    assert data["findings"][0]["evidence"] == {"days": 3} and len(data["policies"]) == 2


def test_a_saved_run_loads_back_identically(tmp_path):
    run = policy_run(findings=[finding(evidence={"days": 3}), finding("X", "high", "u2", key="k")])
    loaded = reports.load_run(reports.write_json(run, tmp_path / "run.json"))
    assert [f.fingerprint for f in loaded.findings] == [f.fingerprint for f in run.findings]
    assert loaded.findings[0].evidence == {"days": 3} and loaded.started_at == run.started_at
    assert [p.name for p in loaded.policies] == ["MFA all", "Block legacy"]
    assert [t.value for t in loaded.policies[0].tags] == [t.value for t in run.policies[0].tags]
    assert loaded.policies[0].exclusions.users[0].id == "bg" and loaded.status == run.status


def test_runs_written_by_a_newer_version_are_refused(tmp_path):
    path = tmp_path / "run.json"
    path.write_text(json.dumps({"schema_version": 99}))
    with pytest.raises(ValueError, match="newer version"):
        reports.load_run(path)


def test_reports_are_owner_only_and_leave_no_temp_files(tmp_path):
    path = reports.write_json(make_run(), tmp_path / "out" / "run.json")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert list(path.parent.glob("*.tmp")) == []


# ---- CSV ---------------------------------------------------------------------------------

def read_csv(text):
    return list(csv.DictReader(io.StringIO(text)))


@pytest.mark.parametrize("payload", ['=HYPERLINK("http://evil","click")', "+cmd|' /C calc'!A0", "-2+3", "@SUM(1+1)", "\tTAB", "\rCR"])
def test_spreadsheet_formulas_are_neutralised(payload):
    run = make_run([finding(title=payload, remediation=payload, resource_name=payload)])
    row = read_csv(reports.render_findings_csv(run))[0]
    assert row["title"] == "'" + payload and row["remediation"] == "'" + payload and row["resource_name"] == "'" + payload


def test_ordinary_text_is_left_alone_and_evidence_is_json():
    run = make_run([finding(title="Bob is inactive", evidence={"days": 3, "list": [1, 2]})])
    row = read_csv(reports.render_findings_csv(run))[0]
    assert row["title"] == "Bob is inactive" and json.loads(row["evidence"]) == {"days": 3, "list": [1, 2]}
    assert row["fingerprint"] == "INACTIVE_USER|user|u1|" and list(row) == reports.FINDING_COLUMNS


def test_policy_csv_describes_each_policy_in_plain_language():
    rows = read_csv(reports.render_policies_csv(policy_run()))
    assert [r["name"] for r in rows] == ["MFA all", "Block legacy"]
    assert rows[0]["action"] == "grant" and "REQUIRE multifactor authentication" in rows[0]["summary"]
    assert "users: bg (unresolved: deleted?)" in rows[0]["excluded"] and rows[1]["action"] == "block"
    assert "mfa_all_users" in rows[0]["tags"]


def test_group_rows_merge_findings_per_group_worst_first():
    run = make_run([group_finding("GROUP_UNOWNED", "Old", "g1", "low"), group_finding("GROUP_EMPTY", "Old", "g1", "medium"),
                    group_finding("GROUP_UNOWNED", "Team", "g2", "high", usage=["grants access to 1 app(s)"], kind_label="Microsoft 365")])
    rows = reports.groups_rows(run)
    assert [r["group"] for r in rows] == ["Team", "Old"] and rows[1]["issues"] == "unowned, empty" and rows[1]["worst_severity"] == "medium"
    assert rows[0]["in_use_by"] == "grants access to 1 app(s)" and rows[0]["kind"] == "Microsoft 365"
    assert read_csv(reports.render_groups_csv(run))[0]["group"] == "Team"


def test_group_rows_ignore_other_findings():
    assert reports.groups_rows(make_run([finding()])) == []


# ---- writing everything ------------------------------------------------------------------

def test_all_formats_with_policies_and_groups(tmp_path):
    run = policy_run(findings=[finding(), group_finding("GROUP_UNOWNED", "Old", "g1", "low")])
    paths = reports.write_reports(run, tmp_path, ["json", "csv", "html", "mermaid"])
    stem = reports.base_name(run)
    assert sorted(p.name.removeprefix(stem) for p in paths) == [
        "-ca-diagram.md", "-ca-report.html", "-findings.csv", "-groups.csv", "-policies.csv", ".json"]
    assert all(p.exists() and p.parent == tmp_path for p in paths)


def test_ca_and_group_files_are_only_written_when_there_is_something_to_report(tmp_path):
    paths = reports.write_reports(make_run([finding()]), tmp_path, ["json", "csv", "html", "mermaid"])
    assert sorted(p.suffix for p in paths) == [".csv", ".json"]


def test_unsupported_formats_are_refused(tmp_path):
    with pytest.raises(ValueError, match="Unsupported format.*pdf"):
        reports.write_reports(make_run(), tmp_path, ["json", "pdf"])


def test_file_names_identify_tenant_and_time(tmp_path):
    name = reports.base_name(make_run())
    assert name == "entra-audit-tenant-20261005T120000Z"
    assert reports._slug("a b/c") == "a-b-c"


# ---- local run store ---------------------------------------------------------------------

def save(run_id, days_ago):
    return reports.save_run(make_run([finding()], run_id=run_id, started_at=ago(days_ago)))


def test_runs_list_newest_first_with_a_cheap_summary():
    save("aaaa1111-0000", 3)
    save("bbbb2222-0000", 1)
    save("cccc3333-0000", 2)
    listing = reports.list_runs()
    assert [r.id[:4] for r in listing] == ["bbbb", "cccc", "aaaa"]
    assert listing[0].total_findings == 1 and listing[0].highest_severity == "low" and listing[0].status == "completed"


def test_resolving_runs_by_name_prefix_or_path():
    oldest, newest = save("aaaa1111-0000", 3), save("bbbb2222-0000", 1)
    assert reports.resolve_run("latest") == newest and reports.resolve_run(None) == newest
    assert reports.resolve_run("previous") == oldest
    assert reports.resolve_run("aaaa") == oldest
    assert reports.resolve_run(str(oldest)) == oldest


def test_resolution_errors_are_explained():
    with pytest.raises(FileNotFoundError, match="No saved runs"):
        reports.resolve_run("latest")
    save("aaaa1111-0000", 3)
    with pytest.raises(FileNotFoundError, match="no previous"):
        reports.resolve_run("previous")
    save("aaaa2222-0000", 2)
    with pytest.raises(FileNotFoundError, match="ambiguous"):
        reports.resolve_run("aaaa")
    with pytest.raises(FileNotFoundError, match="No run matches"):
        reports.resolve_run("zzzz")


def test_unreadable_files_in_the_store_are_skipped(isolated_env):
    save("aaaa1111-0000", 1)
    (isolated_env.runs / "junk.json").write_text("{not json")
    (isolated_env.runs / "other.json").write_text('{"unrelated": true}')
    assert [r.id[:4] for r in reports.list_runs()] == ["aaaa"]


def test_the_default_store_honours_the_environment(isolated_env):
    assert reports.default_runs_dir() == isolated_env.runs
