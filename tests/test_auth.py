"""Authentication: settings validation, token handling, provider flows. MSAL is faked; no network."""

import base64
import json
import os
import stat

import pytest

from entra_auditor.auth import (
    APP_SCOPES,
    DEFAULT_USER_SCOPES,
    TOOLKIT_SCOPES,
    AppTokenProvider,
    AuthenticationError,
    AuthMode,
    AuthSettings,
    UserTokenProvider,
    missing_permissions,
    toolkit_scopes,
    token_permissions,
)


def jwt(claims: dict) -> str:
    def b64(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'none'})}.{b64(claims)}.sig"


# ---- settings ----------------------------------------------------------------------------

def test_app_mode_needs_exactly_one_credential():
    AuthSettings(tenant_id="t", client_id="c", client_secret="s")  # fine
    with pytest.raises(AuthenticationError, match="exactly one credential|OR a certificate"):
        AuthSettings(tenant_id="t", client_id="c")
    with pytest.raises(AuthenticationError):
        AuthSettings(tenant_id="t", client_id="c", client_secret="s", cert_path="/x.pem", cert_thumbprint="ab")


def test_certificate_needs_a_thumbprint(tmp_path):
    with pytest.raises(AuthenticationError, match="thumbprint"):
        AuthSettings(tenant_id="t", client_id="c", cert_path=tmp_path / "k.pem")


@pytest.mark.parametrize("tenant,client", [("", "c"), ("t", "")])
def test_tenant_and_client_are_required(tenant, client):
    with pytest.raises(AuthenticationError, match="required"):
        AuthSettings(tenant_id=tenant, client_id=client, client_secret="s")


def test_user_modes_must_not_carry_an_app_secret():
    with pytest.raises(AuthenticationError, match="public client"):
        AuthSettings(tenant_id="t", client_id="c", mode=AuthMode.DEVICE_CODE, client_secret="s")
    AuthSettings(tenant_id="t", client_id="c", mode=AuthMode.BROWSER)  # fine


def test_secrets_are_not_in_repr():
    settings = AuthSettings(tenant_id="t", client_id="c", client_secret="TOPSECRET")
    assert "TOPSECRET" not in repr(settings)


def test_from_env_reads_everything():
    settings = AuthSettings.from_env({
        "AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AUDITOR_AUTH_MODE": "DEVICE",
        "GRAPH_SCOPES": "User.Read.All, Policy.Read.All", "AUDITOR_TOKEN_CACHE": "/tmp/x.json"})
    assert settings.mode is AuthMode.DEVICE_CODE
    assert settings.scopes == ("User.Read.All", "Policy.Read.All")
    assert str(settings.token_cache_path) == "/tmp/x.json"


def test_from_env_rejects_unknown_mode():
    with pytest.raises(AuthenticationError, match="AUDITOR_AUTH_MODE"):
        AuthSettings.from_env({"AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AUDITOR_AUTH_MODE": "magic"})


def test_effective_scopes_per_mode():
    app = AuthSettings(tenant_id="t", client_id="c", client_secret="s")
    assert app.effective_scopes == list(APP_SCOPES)
    user = AuthSettings(tenant_id="t", client_id="c", mode=AuthMode.BROWSER)
    assert user.effective_scopes == list(DEFAULT_USER_SCOPES)
    custom = AuthSettings(tenant_id="t", client_id="c", mode=AuthMode.BROWSER, scopes=("A.Read",))
    assert custom.effective_scopes == ["A.Read"]


def test_authority_includes_the_tenant_and_honours_sovereign_clouds():
    settings = AuthSettings(tenant_id="tid", client_id="c", client_secret="s", authority_host="https://login.microsoftonline.us/")
    assert settings.authority == "https://login.microsoftonline.us/tid"


def test_toolkit_scopes_default_and_override():
    assert toolkit_scopes({}) == TOOLKIT_SCOPES
    assert toolkit_scopes({"AUDITOR_TOOLKIT_SCOPES": "User.ReadWrite.All,Group.Read.All"}) == ("User.ReadWrite.All", "Group.Read.All")


def test_the_read_only_audit_never_asks_for_toolkit_write_scopes():
    assert not any("ReadWrite" in scope for scope in DEFAULT_USER_SCOPES)


# ---- token claims ------------------------------------------------------------------------

def test_application_tokens_carry_roles_and_delegated_tokens_carry_scp():
    assert token_permissions(jwt({"roles": ["User.Read.All", "Policy.Read.All"]})) == {"User.Read.All", "Policy.Read.All"}
    assert token_permissions(jwt({"scp": "User.Read.All Group.Read.All"})) == {"User.Read.All", "Group.Read.All"}
    assert token_permissions(jwt({})) == set()


@pytest.mark.parametrize("bad", ["not-a-jwt", "a.b", ""])
def test_garbage_tokens_are_rejected(bad):
    with pytest.raises(AuthenticationError):
        token_permissions(bad)


def test_missing_permissions():
    assert missing_permissions({"A", "B"}, {"B", "C"}) == {"C"}


# ---- app provider ------------------------------------------------------------------------

class FakeConfidentialApp:
    def __init__(self, result):
        self.result, self.calls = result, []

    def acquire_token_for_client(self, scopes):
        self.calls.append(list(scopes))
        return self.result


def app_settings():
    return AuthSettings(tenant_id="t", client_id="client-1", client_secret="TOPSECRET")


def test_app_provider_returns_the_token_and_asks_for_default_scope():
    fake = FakeConfidentialApp({"access_token": "tok"})
    provider = AppTokenProvider(app_settings(), app=fake)
    assert provider.get_token() == "tok"
    assert fake.calls == [["https://graph.microsoft.com/.default"]]
    assert provider.identity() == "app:client-1"


def test_app_provider_error_message_has_the_cause_but_never_the_secret():
    fake = FakeConfidentialApp({"error": "invalid_client", "error_description": "AADSTS7000215: bad secret\nTrace ID: x"})
    with pytest.raises(AuthenticationError) as info:
        AppTokenProvider(app_settings(), app=fake).get_token()
    assert "invalid_client" in str(info.value) and "AADSTS7000215" in str(info.value)
    assert "Trace ID" not in str(info.value) and "TOPSECRET" not in str(info.value)


def test_app_provider_refuses_a_user_mode_configuration():
    with pytest.raises(AuthenticationError):
        AppTokenProvider(AuthSettings(tenant_id="t", client_id="c", mode=AuthMode.DEVICE_CODE))


# ---- user provider -----------------------------------------------------------------------

ACCOUNT = {"username": "me@contoso.com"}


class FakeCache:
    has_state_changed = True

    def serialize(self):
        return '{"tokens": 1}'


class FakePublicApp:
    def __init__(self, *, accounts=(), silent=None, device=None, interactive=None):
        self.accounts, self.silent, self.device, self.interactive = list(accounts), silent, device, interactive
        self.calls = []

    def get_accounts(self):
        return list(self.accounts)

    def acquire_token_silent(self, scopes, account, force_refresh=False):
        self.calls.append(("silent", force_refresh))
        return self.silent

    def initiate_device_flow(self, scopes):
        return {"user_code": "ABC123", "message": "Go to https://microsoft.com/devicelogin and enter ABC123"}

    def acquire_token_by_device_flow(self, flow):
        self.calls.append(("device",))
        self.accounts.append(ACCOUNT)
        return self.device

    def acquire_token_interactive(self, scopes):
        self.calls.append(("browser",))
        self.accounts.append(ACCOUNT)
        return self.interactive

    def remove_account(self, account):
        self.accounts.remove(account)


def user_provider(tmp_path, app, mode=AuthMode.DEVICE_CODE, **kw):
    settings = AuthSettings(tenant_id="t", client_id="c", mode=mode, token_cache_path=tmp_path / "cache.json")
    return UserTokenProvider(settings, app=app, cache=FakeCache(), **kw), settings


def test_cached_session_is_used_silently(tmp_path):
    app = FakePublicApp(accounts=[ACCOUNT], silent={"access_token": "cached"})
    provider, _ = user_provider(tmp_path, app)
    assert provider.get_token() == "cached" and app.calls == [("silent", False)]
    assert provider.identity() == "user:me@contoso.com"


def test_device_code_sign_in_shows_the_instructions_and_caches_privately(tmp_path):
    shown = []
    app = FakePublicApp(device={"access_token": "fresh"})
    provider, settings = user_provider(tmp_path, app, prompt=shown.append)
    assert provider.get_token() == "fresh"
    assert shown and "devicelogin" in shown[0]
    cache_file = settings.token_cache_path
    assert cache_file.read_text() == '{"tokens": 1}'
    assert stat.S_IMODE(os.stat(cache_file).st_mode) == 0o600   # refresh tokens: owner only


def test_browser_sign_in(tmp_path):
    app = FakePublicApp(interactive={"access_token": "b"})
    provider, _ = user_provider(tmp_path, app, mode=AuthMode.BROWSER)
    assert provider.get_token() == "b" and app.calls == [("browser",)]


def test_non_interactive_provider_refuses_to_prompt(tmp_path):
    provider, _ = user_provider(tmp_path, FakePublicApp(), allow_interactive=False)
    with pytest.raises(AuthenticationError, match="No cached sign-in"):
        provider.get_token()


def test_refresh_forces_a_new_token(tmp_path):
    app = FakePublicApp(accounts=[ACCOUNT], silent={"access_token": "new"})
    provider, _ = user_provider(tmp_path, app)
    assert provider.refresh() == "new" and app.calls == [("silent", True)]


def test_refresh_falls_back_to_sign_in_when_silent_fails(tmp_path):
    app = FakePublicApp(accounts=[ACCOUNT], silent=None, device={"access_token": "again"})
    provider, _ = user_provider(tmp_path, app, prompt=lambda message: None)
    assert provider.refresh() == "again"


def test_logout_removes_accounts_and_deletes_the_cache(tmp_path):
    app = FakePublicApp(accounts=[ACCOUNT], silent={"access_token": "t"})
    provider, settings = user_provider(tmp_path, app)
    provider.get_token()
    assert settings.token_cache_path.exists()
    provider.logout()
    assert app.get_accounts() == [] and not settings.token_cache_path.exists()
    assert provider.identity() == "user:<not signed in>"


def test_device_flow_that_cannot_start_is_reported(tmp_path):
    class Broken(FakePublicApp):
        def initiate_device_flow(self, scopes):
            return {"error": "x", "error_description": "public client flows are disabled"}

    provider, _ = user_provider(tmp_path, Broken())
    with pytest.raises(AuthenticationError, match="public client flows are disabled"):
        provider.get_token()


def test_user_provider_refuses_app_mode_settings():
    with pytest.raises(AuthenticationError):
        UserTokenProvider(app_settings())


def test_granted_permissions_come_from_the_token(tmp_path):
    app = FakePublicApp(accounts=[ACCOUNT], silent={"access_token": jwt({"scp": "A B"})})
    provider, _ = user_provider(tmp_path, app)
    assert provider.granted_permissions() == {"A", "B"}
