import pathlib
import subprocess
import sys

import entra_auditor

PACKAGE_DIR = pathlib.Path(entra_auditor.__file__).parent


def test_running_the_package_directory_as_a_script_explains_the_right_command():
    """`python entra_auditor` (no -m) used to die with 'attempted relative import with no known parent package'."""
    result = subprocess.run([sys.executable, str(PACKAGE_DIR)], capture_output=True, text=True, timeout=60)
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "python -m entra_auditor" in output and "relative import" not in output


# ---- the example configuration files must not drift from the code ----------------------------------

def _repo(name):
    from pathlib import Path
    return Path(__file__).resolve().parent.parent / name


def test_env_example_lists_exactly_the_settings_the_code_reads():
    import re
    code = "\n".join(p.read_text(encoding="utf-8") for p in _repo("entra_auditor").rglob("*.py"))
    read = set(re.findall(r"""(?:environ|env|values)\)?\.get\(\s*["']([A-Z][A-Z_]+)["']""", code))
    read |= set(re.findall(r"""environ\[["']([A-Z][A-Z_]+)["']\]""", code))
    documented = set(re.findall(r"^#?\s*([A-Z][A-Z_]+)=", _repo(".env.example").read_text(encoding="utf-8"), re.M))
    assert read - documented == set(), "settings the code reads that .env.example doesn't mention"
    assert documented - read == set(), ".env.example mentions settings the code no longer reads"
    assert "AUDITOR_TOOLKIT_SCOPES" in read and "AZURE_TENANT_ID" in read           # the scan itself works


def test_the_example_tenants_file_is_valid():
    from entra_auditor.tenants import parse_tenants
    tenants = parse_tenants(_repo("tenants.example.json").read_text(encoding="utf-8"))
    assert [t.user_scope for t in tenants] == ["all", "synced", "all"] and tenants[1].hide_external
    assert tenants[2].authority_host == "https://login.microsoftonline.us"


def test_every_runtime_requirement_is_imported_and_nothing_else_is_listed():
    import re
    listed = set(re.findall(r"^([A-Za-z0-9_.-]+)\s*[<>=]", _repo("requirements.txt").read_text(encoding="utf-8"), re.M))
    assert listed == {"msal", "httpx", "pydantic", "typer", "rich", "questionary", "python-dotenv"}
    code = "\n".join(p.read_text(encoding="utf-8") for p in _repo("entra_auditor").rglob("*.py"))
    for package in listed:
        module = {"python-dotenv": "dotenv"}.get(package, package)
        assert re.search(rf"^\s*(?:import|from) {module}\b", code, re.M), f"{package} is listed but never imported"
    pyproject = _repo("pyproject.toml").read_text(encoding="utf-8")
    assert 'dependencies = { file = ["requirements.txt"] }' in pyproject           # still the single source
