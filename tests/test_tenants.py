"""tenants.json and the per-tenant token caches."""

import json

import pytest

from entra_auditor.auth import AuthMode
from entra_auditor.tenants import (
    TenantConfig,
    TenantConfigError,
    load_tenants,
    parse_tenants,
    tenants_file,
    token_cache_path,
    user_settings,
)

GUID = "11111111-2222-3333-4444-555555555555"


def write(isolated_env, data):
    path = isolated_env.config / "tenants.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return path


def test_the_file_lives_in_the_config_dir_and_can_be_overridden(isolated_env, monkeypatch, tmp_path):
    assert tenants_file() == isolated_env.config / "tenants.json"
    monkeypatch.setenv("AUDITOR_TENANTS_FILE", str(tmp_path / "elsewhere.json"))
    assert tenants_file() == tmp_path / "elsewhere.json"


def test_tenants_are_read_from_the_file(isolated_env):
    write(isolated_env, {"tenants": [
        {"name": "Contoso", "tenant_id": GUID, "client_id": "c1"},
        {"name": "Gov", "tenant_id": "gov.onmicrosoft.us", "client_id": "c2",
         "authority_host": "https://login.microsoftonline.us/"}]})
    contoso, gov = load_tenants()
    assert contoso == TenantConfig("Contoso", GUID, "c1")
    assert gov.authority_host == "https://login.microsoftonline.us"


def test_without_a_file_the_env_tenant_is_offered(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", GUID)
    monkeypatch.setenv("AZURE_CLIENT_ID", "c1")
    [tenant] = load_tenants()
    assert tenant.tenant_id == GUID and tenant.client_id == "c1" and ".env" in tenant.name


def test_without_a_file_or_env_there_are_no_tenants():
    assert load_tenants() == []


def test_the_file_wins_over_the_env(isolated_env, monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "other.onmicrosoft.com")
    monkeypatch.setenv("AZURE_CLIENT_ID", "x")
    write(isolated_env, {"tenants": [{"name": "Contoso", "tenant_id": GUID, "client_id": "c1"}]})
    assert [t.name for t in load_tenants()] == ["Contoso"]


@pytest.mark.parametrize("data, message", [
    ("{not json", "not valid JSON"),
    ({"tenants": []}, "non-empty"),
    ([], "non-empty"),
    ({"tenants": ["Contoso"]}, "must be an object"),
    ({"tenants": [{"name": "A", "tenant_id": GUID}]}, "'client_id' is missing"),
    ({"tenants": [{"name": " ", "tenant_id": GUID, "client_id": "c"}]}, "'name' is missing"),
    ({"tenants": [{"name": "A", "tenant_id": "../../etc", "client_id": "c"}]}, "GUID or a domain"),
    ({"tenants": [{"name": "A", "tenant_id": GUID, "client_id": "c", "client_secret": "s"}]}, "must not hold credentials"),
    ({"tenants": [{"name": "A", "tenant_id": GUID, "client_id": "c", "authority_host": "http://x"}]}, "https://"),
    ({"tenants": [{"name": "A", "tenant_id": GUID, "client_id": "c"},
                  {"name": "a", "tenant_id": "b.com", "client_id": "c"}]}, "used twice"),
])
def test_a_malformed_file_says_what_is_wrong(data, message):
    with pytest.raises(TenantConfigError, match=message):
        parse_tenants(data if isinstance(data, str) else json.dumps(data))


def test_each_tenant_gets_its_own_cache_inside_the_config_dir(isolated_env):
    a = token_cache_path(TenantConfig("A", GUID, "c"))
    b = token_cache_path(TenantConfig("B", "Fabrikam.onmicrosoft.com", "c"))
    assert a != b and a.parent == b.parent == isolated_env.config / "tenants"
    assert b.name == "fabrikam.onmicrosoft.com.token_cache.json"     # case-insensitive, like tenant ids


def test_a_tenant_id_that_could_escape_the_cache_dir_is_refused():
    with pytest.raises(TenantConfigError):
        token_cache_path(TenantConfig("X", "../evil", "c"))


def test_user_settings_use_the_tenants_cache_and_never_app_mode(isolated_env):
    tenant = TenantConfig("A", GUID, "c", "https://login.microsoftonline.us")
    settings = user_settings(tenant, AuthMode.DEVICE_CODE, ["User.Read.All"])
    assert settings.token_cache_path == token_cache_path(tenant) and settings.scopes == ("User.Read.All",)
    assert settings.authority == f"https://login.microsoftonline.us/{GUID}"
    with pytest.raises(ValueError):
        user_settings(tenant, AuthMode.APP, [])


def test_a_tenant_can_name_the_users_to_load_and_a_wrong_name_is_refused():
    import pytest

    from entra_auditor.tenants import USER_SCOPE_NAMES, TenantConfigError, parse_tenants
    from entra_auditor.toolkit.directory import USER_SCOPES
    base = '{"tenants": [{"name": "Big", "tenant_id": "contoso.com", "client_id": "c1"%s}]}'
    assert parse_tenants(base % "")[0].user_scope == "all"
    assert parse_tenants(base % ', "user_scope": "synced"')[0].user_scope == "synced"
    with pytest.raises(TenantConfigError, match="user_scope must be one of"):
        parse_tenants(base % ', "user_scope": "everyone"')
    assert set(USER_SCOPE_NAMES) == set(USER_SCOPES)            # the two lists must not drift apart
