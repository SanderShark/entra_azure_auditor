"""Command wiring under the REAL Typer: every command builds, parses its options, and reaches our code.

These use Typer's own test runner, so they are skipped where it isn't available. They are the tests
most likely to catch an option-definition mistake that only the real library notices."""

import pytest

typer_testing = pytest.importorskip("typer.testing")

import typer  # noqa: E402

import entra_auditor.cli as maincli  # noqa: E402
from entra_auditor import __version__  # noqa: E402
from entra_auditor.cli import app  # noqa: E402

runner = typer_testing.CliRunner()


@pytest.fixture(autouse=True)
def no_dotenv(monkeypatch):
    """The CLI callback loads a .env from the working directory; tests must not pick up a real one."""
    monkeypatch.setattr(maincli, "_load_dotenv", lambda: None)


def invoke(*args):
    result = runner.invoke(app, list(args))
    return result.exit_code, result.output, result


def walk(command, path=()):
    yield path
    # Duck-typed: newer Typer releases vendor click privately, so `click.Group` is not always importable.
    for name, sub in getattr(command, "commands", {}).items():
        yield from walk(sub, path + (name,))


def test_every_command_builds_and_documents_itself():
    root = typer.main.get_command(app)
    paths = list(walk(root))
    assert len(paths) > 25
    for path in paths:
        code, out, result = invoke(*path, "--help")
        assert code == 0 and "Usage" in out, (path, out, result.exception)


def test_the_expected_commands_exist():
    root = typer.main.get_command(app)
    assert {"run", "findings", "policies", "ca-report", "compare", "runs", "export", "permissions", "login", "logout",
            "whoami", "menu", "toolkit", "id", "group", "pim", "check", "sync"} <= set(root.commands)
    assert {"search", "show", "edit", "enable", "disable", "revoke", "password", "cert-list", "cert-add", "cert-remove",
            "log"} <= set(root.commands["id"].commands)
    assert {"show", "add-member", "remove-member", "add-owner", "remove-owner", "stale"} <= set(root.commands["group"].commands)
    assert {"list", "activate", "deactivate"} <= set(root.commands["pim"].commands)


def test_the_module_entry_point_runs():
    import pathlib
    import subprocess
    import sys

    root = pathlib.Path(maincli.__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, "-m", "entra_auditor", "--version"], capture_output=True, text=True,
                            cwd=root, timeout=120)
    assert result.returncode == 0, result.stderr
    assert __version__ in result.stdout


def test_version_flag():
    code, out, _ = invoke("--version")
    assert code == 0 and __version__ in out


def test_unknown_options_are_usage_errors():
    assert invoke("id", "search", "x", "--bogus")[0] == 2


def test_help_shows_friendly_argument_names():
    out = invoke("id", "cert-add", "--help")[1]
    assert "USER" in out and "[DATA]..." in out and "--type" in out
    assert "USER..." in invoke("group", "add-member", "--help")[1]


# ---- options and arguments reach our code ------------------------------------------------

def test_search_options(tk):
    tk.use()
    code, out, _ = invoke("id", "search", "alice@contoso.com")
    assert code == 0 and "alice@contoso.com" in out
    code, out, _ = invoke("id", "search", "Finance", "--type", "all", "--limit", "5")
    assert code == 0 and "Finance Share" in out


def test_repeated_set_options_and_flags(tk):
    tk.use()
    code, out, result = invoke("id", "edit", "alice@contoso.com", "--set", "title=Principal", "--set", "dept=", "--dry-run")
    assert code == 0, (out, result.exception)
    assert "jobTitle: 'Engineer' -> 'Principal'" in out and "department: 'IT' -> (empty)" in out


def test_the_exact_command_that_failed_in_the_first_live_run(tk):
    tk.use()
    code, out, result = invoke("id", "cert-add", "alice@contoso.com", "--type", "ski", "444", "--dry-run")
    assert code == 0, (out, result.exception)
    assert "X509:<SKI>444" in out


def test_two_part_certificate_data_as_positional_arguments(tk):
    tk.use()
    code, out, result = invoke("id", "cert-add", "alice@contoso.com", "-t", "issuer-serial", "CN=CA", "1122", "--dry-run")
    assert code == 0, (out, result.exception)
    assert "X509:<I>CN=CA<SR>1122" in out


def test_several_users_as_positional_arguments(tk):
    tk.use()
    code, out, result = invoke("group", "add-member", "Finance Share", "alice@contoso.com", "bob@contoso.com", "--dry-run")
    assert code == 0, (out, result.exception)
    assert "+ alice@contoso.com" in out and "+ bob@contoso.com" in out


def test_the_elevate_flags_are_three_state(tk):
    tenant = tk.use().graph
    code, out, _ = invoke("id", "edit", "alice@contoso.com", "--set", "title=P", "--yes", "--no-elevate")
    assert code == 1 and "your current permissions aren't enough" in out and not tenant.active_roles
    code, out, result = invoke("id", "edit", "alice@contoso.com", "--set", "title=P", "--yes", "--elevate", "--reason", "INC-1")
    assert code == 0, (out, result.exception)
    assert tenant.users["u-alice"]["jobTitle"] == "P" and tenant.active_roles


def test_pim_options(tk):
    tenant = tk.use().graph
    code, out, result = invoke("pim", "activate", "user adm", "--reason", "INC-1", "--minutes", "30")
    assert code == 0, (out, result.exception)
    assert [w for w in tenant.writes if w[1] == "pim"][-1][2]["scheduleInfo"]["expiration"]["duration"] == "PT30M"


def test_password_reset_preview(tk):
    tk.use()
    code, out, result = invoke("id", "password", "alice@contoso.com", "--dry-run")
    assert code == 0, (out, result.exception)
    assert "Alice Ng (alice@contoso.com)" in out


def test_show_log_and_stale_commands(tk):
    tk.use()
    assert invoke("id", "show", "alice@contoso.com")[0] == 0
    assert invoke("id", "log")[0] == 0
    code, out, _ = invoke("group", "stale")
    assert code == 1 and "No saved runs" in out


def test_gui_without_qt_says_how_to_install_it(monkeypatch):
    import entra_auditor.gui as gui

    monkeypatch.setattr(gui, "qt_available", lambda: False)
    code, out, _ = invoke("gui")
    assert code == 1 and "PySide6" in out and ".[gui]" in out


def test_gui_starts_the_desktop_app(monkeypatch):
    pytest.importorskip("PySide6")
    import entra_auditor.gui.app as gui_app

    started = []
    monkeypatch.setattr(gui_app, "run", lambda *a, **k: started.append(True) or 0)
    code, _out, _ = invoke("gui")
    assert code == 0 and started == [True]


# ---- sync rules (offline) -----------------------------------------------------------------------

def _sync_files(tmp_path):
    import json
    base = {"Name": "In from AD - Do not sync", "Identifier": "r1", "Direction": "Inbound", "Precedence": 50,
            "SourceObjectType": "user", "TargetObjectType": "person",
            "ScopeFilter": [{"ScopeConditionList": [{"Attribute": "extensionAttribute14", "ComparisonOperator": "EQUAL",
                                                     "ComparisonValue": "no0365sync"}]}],
            "AttributeFlowMappings": [{"Destination": "cloudFiltered", "Source": ["True"], "FlowType": "Constant"}]}
    wider = json.loads(json.dumps(base))
    wider["ScopeFilter"][0]["ScopeConditionList"][0]["ComparisonOperator"] = "STARTSWITH"
    wider["ScopeFilter"][0]["ScopeConditionList"][0]["ComparisonValue"] = "no"
    old, new, people = tmp_path / "old.json", tmp_path / "new.json", tmp_path / "users.csv"
    old.write_text(json.dumps([base]))
    new.write_text(json.dumps([wider]))
    people.write_text("userPrincipalName,extensionAttribute14\na@x.com,\nsvc@x.com,no0365sync\nold@x.com,nosync-legacy\n")
    return str(old), str(new), str(people)


def test_sync_rules_are_described_linted_and_explained_without_signing_in(tmp_path, monkeypatch):
    monkeypatch.setattr(maincli, "build_settings", lambda *a, **k: pytest.fail("sync commands must not sign in"), raising=False)
    old, _new, people = _sync_files(tmp_path)
    code, out, _ = invoke("sync", "describe", old)
    assert code == 0 and "extensionAttribute14 equals 'no0365sync'" in out and "FILTERS FROM THE CLOUD" in out
    code, out, _ = invoke("sync", "lint", old)
    assert code == 0 and "0 error(s)" in out
    code, out, _ = invoke("sync", "explain", old, "--set", "extensionAttribute14=no0365sync")
    assert code == 0 and "Not synchronised" in out
    code, out, _ = invoke("sync", "explain", old, "--csv", people, "--who", "a@x.com")
    assert code == 0 and "Synchronised as far as these rules say" in out
    code, out, _ = invoke("sync", "explain", "tests/data/connect_sample", "--set", "sAMAccountName=MSOL_abc",
                          "--set", "distinguishedName=CN=MSOL_abc,OU=CORP,DC=contoso,DC=com")
    assert code == 0 and "Not synchronised" in out and "In from AD - User Join" in out
    code, out, _ = invoke("sync", "describe", "tests/data/connect_sample", "--filters")
    assert code == 0 and "5 of 62 rules shown" in out and "OU=CORP,DC=contoso,DC=com" in out
    code, out, _ = invoke("sync", "explain", old, "--set", "displayName=X", "--excluded-ou", "OU=Gone,DC=x",
                          "--set", "distinguishedName=CN=X,OU=Gone,DC=x")
    assert code == 0 and "excluded organisational unit" in out
    assert invoke("sync", "explain", old)[0] == 2 and invoke("sync", "describe", str(tmp_path / "missing"))[0] == 2


def test_sync_impact_is_a_validator_with_an_exit_code(tmp_path):
    old, new, people = _sync_files(tmp_path)
    code, out, _ = invoke("sync", "diff", old, new)
    assert code == 0 and "Scope changed" in out and "1 change(s) can alter who is synchronised" in out
    code, out, _ = invoke("sync", "impact", old, new, people)
    assert code == 1 and "1 would STOP synchronising" in out and "old@x.com" in out and "FAIL" in out
    code, out, _ = invoke("sync", "impact", old, new, people, "--max-changes", "1")
    assert code == 0 and "PASS" in out
    assert invoke("sync", "impact", old, old, people)[0] == 0
    assert invoke("sync", "impact", old, new, people, "--max-percent", "34")[0] == 0
    assert invoke("sync", "impact", old, new, people, "--max-percent", "33")[0] == 1


def test_the_check_command_exists_and_documents_itself():
    code, out, _ = invoke("check", "--help")
    assert code == 0 and "names no user or tenant" in out
