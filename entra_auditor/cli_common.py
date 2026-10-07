"""Helpers shared by the audit CLI (``cli.py``) and the identity toolkit CLI (``toolkit/cli.py``).

Kept separate so the two can import it without importing each other.
"""

import dataclasses
import os
from typing import Annotated, NoReturn, Optional, Sequence

import typer
from rich.console import Console
from rich.markup import escape
from rich.text import Text

from .auth import AuthenticationError, AuthMode, AuthSettings

console = Console()
err = Console(stderr=True)

SEV_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
USER_MODE_ONLY_ENV = (
    "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERT_PATH",
    "AZURE_CLIENT_CERT_THUMBPRINT", "AZURE_CLIENT_CERT_PASSPHRASE",
)

ModeOpt = Annotated[Optional[str], typer.Option(
    "--mode", "-m", help="Auth mode: app | device | browser (default: $AUDITOR_AUTH_MODE or app).")]


def fail(message: str, code: int = 1) -> NoReturn:
    err.print(f"[bold red]Error:[/] {escape(message)}")
    raise typer.Exit(code)


def t(value: object) -> Text:
    """Render data as literal text (never as Rich markup: names may contain [brackets])."""
    return Text(str(value))


def sev(severity: str) -> Text:
    return Text(severity.upper(), style=SEV_STYLE[severity])


def build_settings(mode: Optional[str], scopes: Optional[Sequence[str]] = None) -> AuthSettings:
    """Auth settings from the environment, optionally forcing a mode and (user modes) scopes."""
    env = dict(os.environ)
    if mode:
        try:
            chosen = AuthMode(mode.lower())
        except ValueError:
            fail("Mode must be one of: app, device, browser")
        env["AUDITOR_AUTH_MODE"] = chosen.value
        if chosen.is_user:  # the app secret/cert must not leak into a user sign-in
            for key in USER_MODE_ONLY_ENV:
                env.pop(key, None)
    try:
        settings = AuthSettings.from_env(env)
    except AuthenticationError as exc:
        fail(str(exc))
    if scopes is not None and settings.mode.is_user:
        settings = dataclasses.replace(settings, scopes=tuple(scopes))
    return settings
