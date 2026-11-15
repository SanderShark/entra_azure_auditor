"""The tenants the desktop app can sign in to, each with its own token cache.

``tenants.json`` lives in the config directory (``~/.entra_auditor``; override with ``AUDITOR_CONFIG_DIR``,
or point ``AUDITOR_TENANTS_FILE`` at the file itself)::

    {"tenants": [
        {"name": "Contoso", "tenant_id": "00000000-...", "client_id": "00000000-..."},
        {"name": "Fabrikam (GCC High)", "tenant_id": "fabrikam.onmicrosoft.us", "client_id": "...",
         "authority_host": "https://login.microsoftonline.us"},
        {"name": "Big tenant", "tenant_id": "...", "client_id": "...", "user_scope": "synced"}
    ]}

``user_scope`` (optional) is which users the desktop app loads at start: ``all`` (default), ``members``,
``guests`` or ``synced`` (synced from on-premises AD). Set it for tenants with far more user objects than
people; it can still be switched in the app.

It holds no secrets: the desktop app signs in as a user, so each app registration is a public client.
Without the file, the tenant from the environment (``AZURE_TENANT_ID`` / ``AZURE_CLIENT_ID``, usually
from ``.env``) is offered as the only one.

Each tenant gets its own cache file (``<config dir>/tenants/<tenant id>.token_cache.json``), so signing
out of, or switching away from, one tenant never touches another's sign-in.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .auth import DEFAULT_AUTHORITY_HOST, AuthMode, AuthSettings

DEFAULT_CONFIG_DIR = Path.home() / ".entra_auditor"
# A tenant id is a GUID or a domain; anything else could escape the cache directory as a file name.
USER_SCOPE_NAMES = ("all", "members", "guests", "synced")    # keep in step with toolkit.directory.USER_SCOPES
_TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


class TenantConfigError(ValueError):
    """tenants.json is missing something or malformed; the message says what and where."""


@dataclass(frozen=True)
class TenantConfig:
    name: str
    tenant_id: str
    client_id: str
    authority_host: str = DEFAULT_AUTHORITY_HOST
    user_scope: str = "all"

    @property
    def key(self) -> str:
        """Stable identifier (used for the cache file name and to remember the last tenant)."""
        return self.tenant_id.lower()


def _env(env: Optional[Mapping[str, str]]) -> Mapping[str, str]:
    return os.environ if env is None else env


def config_dir(env: Optional[Mapping[str, str]] = None) -> Path:
    raw = _env(env).get("AUDITOR_CONFIG_DIR")
    return Path(raw).expanduser() if raw else DEFAULT_CONFIG_DIR


def tenants_file(env: Optional[Mapping[str, str]] = None) -> Path:
    raw = _env(env).get("AUDITOR_TENANTS_FILE")
    return Path(raw).expanduser() if raw else config_dir(env) / "tenants.json"


def _validated(entry: object, where: str) -> TenantConfig:
    if not isinstance(entry, dict):
        raise TenantConfigError(f"{where}: each tenant must be an object with name, tenant_id and client_id.")
    values = {}
    for key in ("name", "tenant_id", "client_id"):
        value = entry.get(key)
        if not isinstance(value, str) or not value.strip():
            raise TenantConfigError(f"{where}: '{key}' is missing or empty.")
        values[key] = value.strip()
    if not _TENANT_ID.match(values["tenant_id"]):
        raise TenantConfigError(f"{where}: tenant_id must be a GUID or a domain, not {values['tenant_id']!r}.")
    for secret in ("client_secret", "secret", "password", "cert_path"):
        if secret in entry:
            raise TenantConfigError(f"{where}: remove '{secret}'. The desktop app signs in as a user and "
                                    "tenants.json must not hold credentials.")
    host = entry.get("authority_host") or DEFAULT_AUTHORITY_HOST
    if not isinstance(host, str) or not host.startswith("https://"):
        raise TenantConfigError(f"{where}: authority_host must be an https:// URL.")
    scope = entry.get("user_scope", "all")
    if scope not in USER_SCOPE_NAMES:
        raise TenantConfigError(f"{where}: user_scope must be one of {', '.join(USER_SCOPE_NAMES)}, not {scope!r}.")
    return TenantConfig(values["name"], values["tenant_id"], values["client_id"], host.rstrip("/"), scope)


def parse_tenants(text: str, source: str = "tenants.json") -> list[TenantConfig]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise TenantConfigError(f"{source} is not valid JSON: {exc}") from exc
    entries = data.get("tenants") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise TenantConfigError(f"{source} needs a non-empty \"tenants\" list.")
    tenants = [_validated(entry, f"{source}, tenant {index}") for index, entry in enumerate(entries, 1)]
    seen: set[str] = set()
    for tenant in tenants:
        if tenant.name.lower() in seen:
            raise TenantConfigError(f"{source}: the name {tenant.name!r} is used twice; names must be unique.")
        seen.add(tenant.name.lower())
    return tenants


def load_tenants(env: Optional[Mapping[str, str]] = None) -> list[TenantConfig]:
    """Tenants from tenants.json, else the one from the environment, else an empty list."""
    path = tenants_file(env)
    if path.exists():
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise TenantConfigError(f"Cannot read {path}: {exc}") from exc
        return parse_tenants(text, str(path))
    values = _env(env)
    tenant_id, client_id = values.get("AZURE_TENANT_ID", "").strip(), values.get("AZURE_CLIENT_ID", "").strip()
    if tenant_id and client_id and _TENANT_ID.match(tenant_id):
        host = values.get("AZURE_AUTHORITY_HOST") or DEFAULT_AUTHORITY_HOST
        return [TenantConfig(f"{tenant_id} (from .env)", tenant_id, client_id, host.rstrip("/"))]
    return []


def token_cache_path(tenant: TenantConfig, env: Optional[Mapping[str, str]] = None) -> Path:
    if not _TENANT_ID.match(tenant.tenant_id):  # TenantConfig can be built directly, so check again
        raise TenantConfigError(f"Invalid tenant id {tenant.tenant_id!r}.")
    return config_dir(env) / "tenants" / f"{tenant.key}.token_cache.json"


def user_settings(tenant: TenantConfig, mode: AuthMode, scopes: Sequence[str],
                  env: Optional[Mapping[str, str]] = None) -> AuthSettings:
    """User sign-in settings for one tenant (never app mode: PIM needs a person)."""
    if not mode.is_user:
        raise ValueError("The desktop app signs in as a user (device code or browser).")
    return AuthSettings(tenant_id=tenant.tenant_id, client_id=tenant.client_id, mode=mode, scopes=tuple(scopes),
                        token_cache_path=token_cache_path(tenant, env), authority_host=tenant.authority_host)
