"""Authentication to Microsoft Graph: app registration OR interactive user login.

Modes
-----
app      Client-credentials flow (unattended). Uses *application* permissions
         granted to the app registration. Needs a client secret or certificate.
device   Delegated user sign-in via device code (works over SSH / headless).
browser  Delegated user sign-in via a local browser window.

In the two user modes the app registration is a *public client* (no secret).
Effective access = the app's delegated permissions ∩ what the signed-in user's
Entra roles allow (e.g. Global Reader / Security Reader is enough for auditing).

Environment variables (see ``AuthSettings.from_env``):

    AUDITOR_AUTH_MODE          app | device | browser      (default: app)
    AZURE_TENANT_ID            required
    AZURE_CLIENT_ID            required
    AZURE_CLIENT_SECRET        app mode: secret  (one of secret / certificate)
    AZURE_CLIENT_CERT_PATH     app mode: PEM file containing the private key
    AZURE_CLIENT_CERT_THUMBPRINT   app mode: SHA-1 thumbprint of uploaded cert
    AZURE_CLIENT_CERT_PASSPHRASE   app mode: optional key passphrase
    AZURE_AUTHORITY_HOST       optional, default https://login.microsoftonline.com
    GRAPH_SCOPES               user modes: space/comma separated delegated scopes
    AUDITOR_TOKEN_CACHE        user modes: token cache file path
"""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Protocol

import msal

DEFAULT_AUTHORITY_HOST = "https://login.microsoftonline.com"
APP_SCOPES = ("https://graph.microsoft.com/.default",)
DEFAULT_USER_SCOPES = (
    "User.Read.All",
    "AuditLog.Read.All",
    "Reports.Read.All",
    "RoleManagement.Read.Directory",
    "RoleEligibilitySchedule.Read.Directory",
    "Policy.Read.All",
    "Application.Read.All",
)
DEFAULT_CACHE_PATH = Path.home() / ".entra_auditor" / "token_cache.json"


class AuthenticationError(Exception):
    """Raised when a token cannot be obtained or configuration is invalid."""


class AuthMode(str, Enum):
    APP = "app"
    DEVICE_CODE = "device"
    BROWSER = "browser"

    @property
    def is_user(self) -> bool:
        return self is not AuthMode.APP


class TokenProvider(Protocol):
    """Anything that can hand the Graph client a bearer token.

    The Graph client depends on this protocol, so tests can pass a fake
    provider instead of talking to Entra ID.
    """

    def get_token(self) -> str: ...


@dataclass(frozen=True)
class AuthSettings:
    tenant_id: str
    client_id: str
    mode: AuthMode = AuthMode.APP
    # App-mode credentials. repr=False keeps secrets out of logs/tracebacks.
    client_secret: str | None = field(default=None, repr=False)
    cert_path: Path | None = None
    cert_thumbprint: str | None = None
    cert_passphrase: str | None = field(default=None, repr=False)
    # User-mode options.
    scopes: tuple[str, ...] | None = None
    token_cache_path: Path | None = None
    authority_host: str = DEFAULT_AUTHORITY_HOST

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.client_id:
            raise AuthenticationError("tenant_id and client_id are required")

        has_secret = bool(self.client_secret)
        has_cert = self.cert_path is not None

        if self.mode.is_user:
            if has_secret or has_cert:
                raise AuthenticationError(
                    "User sign-in uses a public client; remove the client secret/"
                    "certificate settings or use AUDITOR_AUTH_MODE=app"
                )
        else:
            if has_secret == has_cert:
                raise AuthenticationError(
                    "App mode needs exactly one credential: a client secret OR a certificate"
                )
            if has_cert and not self.cert_thumbprint:
                raise AuthenticationError(
                    "cert_thumbprint is required when using a certificate"
                )

    @property
    def authority(self) -> str:
        return f"{self.authority_host.rstrip('/')}/{self.tenant_id}"

    @property
    def effective_scopes(self) -> list[str]:
        if self.mode is AuthMode.APP:
            return list(APP_SCOPES)  # app perms are fixed by admin consent
        return list(self.scopes or DEFAULT_USER_SCOPES)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AuthSettings":
        env = os.environ if env is None else env

        try:
            mode = AuthMode(env.get("AUDITOR_AUTH_MODE", "app").strip().lower())
        except ValueError as exc:
            valid = ", ".join(m.value for m in AuthMode)
            raise AuthenticationError(f"AUDITOR_AUTH_MODE must be one of: {valid}") from exc

        cert_path = env.get("AZURE_CLIENT_CERT_PATH")
        raw_scopes = env.get("GRAPH_SCOPES", "").replace(",", " ").split()
        cache = env.get("AUDITOR_TOKEN_CACHE")

        return cls(
            tenant_id=env.get("AZURE_TENANT_ID", ""),
            client_id=env.get("AZURE_CLIENT_ID", ""),
            mode=mode,
            client_secret=env.get("AZURE_CLIENT_SECRET") or None,
            cert_path=Path(cert_path) if cert_path else None,
            cert_thumbprint=env.get("AZURE_CLIENT_CERT_THUMBPRINT") or None,
            cert_passphrase=env.get("AZURE_CLIENT_CERT_PASSPHRASE") or None,
            scopes=tuple(raw_scopes) or None,
            token_cache_path=Path(cache) if cache else None,
            authority_host=env.get("AZURE_AUTHORITY_HOST", DEFAULT_AUTHORITY_HOST),
        )


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

def _token_from_result(result: Mapping[str, object]) -> str:
    """MSAL returns error dicts instead of raising; convert them."""
    token = result.get("access_token")
    if not token:
        error = result.get("error", "unknown_error")
        description = str(result.get("error_description", "no description"))
        raise AuthenticationError(
            f"Token request failed ({error}): {description.splitlines()[0]}"
        )
    return str(token)


def token_permissions(token: str) -> set[str]:
    """Permissions carried by a JWT, without verifying its signature.

    App tokens carry them in ``roles``; delegated tokens in ``scp`` (space
    separated). Diagnostic use only: it's our own token and we only read claims.
    """
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # restore base64 padding
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (IndexError, ValueError) as exc:
        raise AuthenticationError("Access token is not a valid JWT") from exc
    return set(claims.get("roles", [])) | set(claims.get("scp", "").split())


def missing_permissions(granted: set[str], required: set[str]) -> set[str]:
    """Permissions the audit needs that haven't been granted."""
    return required - granted


# --------------------------------------------------------------------------- #
# App-only provider
# --------------------------------------------------------------------------- #

class AppTokenProvider:
    """Client-credentials flow for unattended runs (app registration)."""

    def __init__(
        self,
        settings: AuthSettings,
        app: msal.ConfidentialClientApplication | None = None,
    ) -> None:
        if settings.mode is not AuthMode.APP:
            raise AuthenticationError("AppTokenProvider requires mode=app")
        self._settings = settings
        self._app = app or self._build_app(settings)  # injectable for tests
        self._lock = threading.Lock()  # MSAL cache isn't documented as thread-safe

    @staticmethod
    def _build_app(s: AuthSettings) -> msal.ConfidentialClientApplication:
        credential: str | dict[str, str]
        if s.cert_path is not None:
            try:
                private_key = s.cert_path.read_text()
            except OSError as exc:
                raise AuthenticationError(
                    f"Cannot read certificate file {s.cert_path}: {exc}"
                ) from exc
            credential = {
                "private_key": private_key,
                "thumbprint": s.cert_thumbprint or "",
            }
            if s.cert_passphrase:
                credential["passphrase"] = s.cert_passphrase
        else:
            credential = s.client_secret or ""

        try:
            return msal.ConfidentialClientApplication(
                client_id=s.client_id,
                client_credential=credential,
                authority=s.authority,
            )
        except (ValueError, msal.exceptions.MsalError) as exc:
            raise AuthenticationError(f"Invalid auth configuration: {exc}") from exc

    def get_token(self) -> str:
        with self._lock:
            result = self._app.acquire_token_for_client(
                scopes=self._settings.effective_scopes
            )
        return _token_from_result(result)

    def granted_permissions(self) -> set[str]:
        return token_permissions(self.get_token())

    def identity(self) -> str:
        return f"app:{self._settings.client_id}"


# --------------------------------------------------------------------------- #
# Delegated user provider
# --------------------------------------------------------------------------- #

class UserTokenProvider:
    """Delegated sign-in (device code or browser) with a persistent token cache.

    The first call signs the user in; later calls (and later runs) reuse the
    cached refresh token silently until it expires or is revoked.
    """

    def __init__(
        self,
        settings: AuthSettings,
        app: msal.PublicClientApplication | None = None,
        cache: msal.SerializableTokenCache | None = None,
        allow_interactive: bool = True,
        prompt: Callable[[str], None] | None = None,
    ) -> None:
        if not settings.mode.is_user:
            raise AuthenticationError("UserTokenProvider requires mode=device or browser")
        self._settings = settings
        self._cache_path = settings.token_cache_path or DEFAULT_CACHE_PATH
        self._cache = cache or self._load_cache()
        self._app = app or self._build_app(settings, self._cache)
        self._allow_interactive = allow_interactive
        # Where device-code instructions go; stderr keeps stdout clean for JSON output.
        self._prompt = prompt or (lambda msg: print(msg, file=sys.stderr))
        self._lock = threading.Lock()

    # -- cache persistence -------------------------------------------------- #

    def _load_cache(self) -> msal.SerializableTokenCache:
        cache = msal.SerializableTokenCache()
        try:
            if self._cache_path.exists():
                cache.deserialize(self._cache_path.read_text())
        except (OSError, ValueError):
            pass  # unreadable/corrupt cache just means "sign in again"
        return cache

    def _save_cache(self) -> None:
        if not self._cache.has_state_changed:
            return
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            # The cache holds refresh tokens: create it owner-only (0600).
            fd = os.open(self._cache_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(self._cache.serialize())
        except OSError as exc:
            raise AuthenticationError(
                f"Cannot write token cache {self._cache_path}: {exc}"
            ) from exc

    @staticmethod
    def _build_app(
        s: AuthSettings, cache: msal.SerializableTokenCache
    ) -> msal.PublicClientApplication:
        try:
            return msal.PublicClientApplication(
                client_id=s.client_id,
                authority=s.authority,
                token_cache=cache,
            )
        except (ValueError, msal.exceptions.MsalError) as exc:
            raise AuthenticationError(f"Invalid auth configuration: {exc}") from exc

    # -- flows -------------------------------------------------------------- #

    def _first_account(self) -> dict | None:
        accounts = self._app.get_accounts()
        return accounts[0] if accounts else None

    def _acquire_silent(self) -> dict | None:
        account = self._first_account()
        if account is None:
            return None
        return self._app.acquire_token_silent(
            self._settings.effective_scopes, account=account
        )

    def _acquire_interactive(self) -> dict:
        scopes = self._settings.effective_scopes
        if self._settings.mode is AuthMode.DEVICE_CODE:
            flow = self._app.initiate_device_flow(scopes=scopes)
            if "user_code" not in flow:
                raise AuthenticationError(
                    "Could not start device-code flow: "
                    f"{flow.get('error_description', 'unknown error')}"
                )
            self._prompt(flow["message"])  # "Go to https://microsoft.com/devicelogin ..."
            return self._app.acquire_token_by_device_flow(flow)  # blocks until done
        return self._app.acquire_token_interactive(scopes=scopes)

    def get_token(self) -> str:
        with self._lock:
            result = self._acquire_silent()
            if not (result and "access_token" in result):
                if not self._allow_interactive:
                    raise AuthenticationError(
                        "No cached sign-in. Run the login command interactively first."
                    )
                result = self._acquire_interactive()
            self._save_cache()
        return _token_from_result(result)

    # -- convenience -------------------------------------------------------- #

    def login(self) -> str:
        """Force an explicit sign-in (for an `auditor login` command)."""
        with self._lock:
            result = self._acquire_interactive()
            self._save_cache()
        _token_from_result(result)
        return self.identity()

    def logout(self) -> None:
        """Remove cached accounts and delete the cache file."""
        with self._lock:
            for account in self._app.get_accounts():
                self._app.remove_account(account)
            try:
                self._cache_path.unlink(missing_ok=True)
            except OSError as exc:
                raise AuthenticationError(f"Cannot delete token cache: {exc}") from exc

    def identity(self) -> str:
        account = self._first_account()
        return f"user:{account['username']}" if account else "user:<not signed in>"

    def granted_permissions(self) -> set[str]:
        return token_permissions(self.get_token())


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #

def create_token_provider(
    settings: AuthSettings | None = None, **user_kwargs: object
) -> AppTokenProvider | UserTokenProvider:
    """Build the right provider for ``settings.mode`` (defaults to env config).

    ``user_kwargs`` (e.g. ``allow_interactive=False`` for the API server) are
    only used in device/browser mode.
    """
    settings = settings or AuthSettings.from_env()
    if settings.mode is AuthMode.APP:
        return AppTokenProvider(settings)
    return UserTokenProvider(settings, **user_kwargs)  # type: ignore[arg-type]