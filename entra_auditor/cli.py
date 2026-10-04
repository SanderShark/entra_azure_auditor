"""Command line interface: scriptable commands plus an interactive menu.

    auditor run [--checks inactive,privileged] [--fail-on high] [--out ./reports]
    auditor findings [RUN] [--min-severity high] [--check ADMIN] [--search bob] [--detail]
    auditor policies [RUN] [--name "MFA"] [--concerns-only]
    auditor compare [OLD] [NEW]
    auditor runs | export | permissions | login | logout | whoami
    auditor menu                 # arrow-key menu over all of the above

Exit codes: 0 success, 1 the audit could not run (auth/Graph failure) or bad input,
2 findings at or above ``--fail-on`` exist (handy in CI).

Every command that touches Graph honours ``--mode app|device|browser`` (default:
``AUDITOR_AUTH_MODE`` or ``app``); see ``auth.py`` for the environment variables.
"""

import logging
import os
import sys
import webbrowser
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich import box
from rich.console import Console
from rich.json import JSON
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .auth import (
    AuthenticationError,
    AuthMode,
    AuthSettings,
    UserTokenProvider,
    create_token_provider,
    token_permissions,
)
from .checks import CHECKS
from .checks._common import SEVERITY_ORDER, AuditConfig
from .checks.ca_analysis import PolicyProfile
from .engine import (
    AuditRun,
    RunStatus,
    diff_runs,
    required_permissions,
    resolve_checks,
    run_audit,
)
from .graph.client import GraphClient
from .models import Finding
from .reports import (
    SUPPORTED_FORMATS,
    base_name,
    default_runs_dir,
    list_runs,
    load_run,
    resolve_run,
    save_run,
    write_ca_html,
    write_ca_mermaid,
    write_reports,
)

app = typer.Typer(
    name="auditor",
    help="Entra ID / Azure security auditor.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,  # tracebacks must never print tokens/secrets
)
console = Console()
err = Console(stderr=True)

SEV_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
STATE_LABEL = {
    "enabled": ("ON", "green"),
    "enabledForReportingButNotEnforced": ("REPORT-ONLY", "yellow"),
    "disabled": ("OFF", "dim"),
}
ACTION_LABEL = {
    "block": ("BLOCK", "bold red"),
    "grant": ("GRANT", "green"),
    "session_only": ("SESSION", "magenta"),
    "no_effect": ("NONE", "dim"),
}
USER_MODE_ONLY_ENV = (
    "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERT_PATH",
    "AZURE_CLIENT_CERT_THUMBPRINT", "AZURE_CLIENT_CERT_PASSPHRASE",
)

# --- shared option types ------------------------------------------------------
ModeOpt = Annotated[Optional[str], typer.Option(
    "--mode", "-m", help="Auth mode: app | device | browser (default: $AUDITOR_AUTH_MODE or app).")]
RunArg = Annotated[Optional[str], typer.Argument(
    help="Saved run: latest (default), previous, a run id prefix, or a .json file.")]


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _fail(message: str, code: int = 1) -> "typer.Exit":
    err.print(f"[bold red]Error:[/] {escape(message)}")
    raise typer.Exit(code)


def _t(value: object) -> Text:
    """Render data as literal text (never as Rich markup: names may contain [brackets])."""
    return Text(str(value))


def _sev(severity: str) -> Text:
    return Text(severity.upper(), style=SEV_STYLE[severity])


def _validate_severity(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.lower()
    if value not in SEVERITY_ORDER:
        _fail(f"Severity must be one of: {', '.join(reversed(SEVERITY_ORDER))}")
    return value


def _settings(mode: Optional[str]) -> AuthSettings:
    env = dict(os.environ)
    if mode:
        try:
            chosen = AuthMode(mode.lower())
        except ValueError:
            _fail("Mode must be one of: app, device, browser")
        env["AUDITOR_AUTH_MODE"] = chosen.value
        if chosen.is_user:  # the app secret/cert must not leak into a user sign-in
            for key in USER_MODE_ONLY_ENV:
                env.pop(key, None)
    try:
        return AuthSettings.from_env(env)
    except AuthenticationError as exc:
        _fail(str(exc))


def _load(ref: Optional[str]) -> AuditRun:
    try:
        return load_run(resolve_run(ref))
    except (FileNotFoundError, ValueError, OSError) as exc:
        _fail(str(exc))


def _audit_config(inactive_days: int, guest_days: int, admin_days: int) -> AuditConfig:
    return AuditConfig(
        inactive_days=inactive_days, guest_inactive_days=guest_days, admin_inactive_days=admin_days
    )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def print_summary(run: AuditRun) -> None:
    summary = run.summary()
    status_style = {"completed": "green", "partial": "yellow", "failed": "bold red"}[run.status.value]

    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold cyan", no_wrap=True)
    header.add_column()
    header.add_row("Tenant", _t(run.tenant_id))
    header.add_row("Identity", _t(run.identity or "-"))
    header.add_row("Status", Text(run.status.value, style=status_style))
    header.add_row("Duration", _t(f"{run.duration_seconds:.1f}s"))
    header.add_row("Checks", _t(", ".join(run.checks)))

    counts = Text()
    for sev in reversed(SEVERITY_ORDER):
        counts.append(f" {sev} ", style=SEV_STYLE[sev])
        counts.append(f"{summary.by_severity.get(sev, 0)}   ")
    header.add_row("Findings", Text(f"{summary.total}   ") + counts)
    console.print(Panel(header, title="Audit summary", border_style="cyan", box=box.ROUNDED))

    if run.error:
        console.print(Panel(_t(run.error), title="Audit failed", border_style="red"))
        return

    inventory = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    inventory.add_column(style="bold")
    inventory.add_column(justify="right")
    for name, value in run.inventory.items():
        inventory.add_row(name.replace("_", " "), "n/a" if value is None else str(value))
    console.print(inventory)

    if run.warnings:
        body = Text("\n".join(f"- {w}" for w in run.warnings[:10]))
        if len(run.warnings) > 10:
            body.append(f"\n... and {len(run.warnings) - 10} more")
        console.print(Panel(body, title="Warnings", border_style="yellow"))


def filter_findings(
    run: AuditRun,
    min_severity: Optional[str] = None,
    check: Optional[str] = None,
    search: Optional[str] = None,
) -> list[Finding]:
    items = run.findings_at_or_above(min_severity) if min_severity else list(run.findings)
    if check:
        items = [f for f in items if check.lower() in f.check_id.lower()]
    if search:
        needle = search.lower()
        items = [f for f in items
                 if needle in f.title.lower() or needle in (f.resource_name or "").lower()
                 or needle in f.resource_id.lower()]
    return items


def print_findings(findings: list[Finding], limit: int = 0, title: str = "Findings") -> None:
    if not findings:
        console.print("[green]No matching findings.[/]")
        return
    shown = findings[:limit] if limit else findings
    table = Table(title=f"{title} ({len(findings)})", box=box.SIMPLE_HEAD, header_style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Resource", overflow="fold", max_width=32)
    table.add_column("Finding", overflow="fold", ratio=1)
    for f in shown:
        table.add_row(_sev(f.severity), _t(f.check_id), _t(f.resource_name or f.resource_id), _t(f.title))
    console.print(table)
    if limit and len(findings) > limit:
        console.print(f"[dim]... {len(findings) - limit} more. Use `auditor findings` to see all.[/]")


def print_finding_detail(f: Finding) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()
    grid.add_row("Severity", _sev(f.severity))
    grid.add_row("Check", _t(f.check_id))
    grid.add_row("Resource", _t(f"{f.resource_type}: {f.resource_name or ''} ({f.resource_id})"))
    grid.add_row("Fix", _t(f.remediation or "-"))
    console.print(Panel(grid, title=_t(f.title), border_style=SEV_STYLE[f.severity].split()[-1]))
    if f.evidence:
        console.print(Panel(JSON.from_data(f.evidence, default=str), title="Evidence", border_style="dim"))


def _exclusion_lines(p: PolicyProfile) -> list[str]:
    ex, lines = p.exclusions, []
    if ex.users:
        lines.append("users: " + ", ".join(u.label for u in ex.users))
    if ex.groups:
        lines.append("groups: " + ", ".join(g.label for g in ex.groups))
    if ex.roles:
        lines.append("roles: " + ", ".join(r.label for r in ex.roles))
    if ex.guests_or_external:
        lines.append("guest and external users")
    if ex.applications:
        lines.append("apps: " + ", ".join(a.label for a in ex.applications))
    return lines


def _worst_concern(p: PolicyProfile) -> Optional[str]:
    if not p.concerns:
        return None
    return max((c.severity for c in p.concerns), key=SEVERITY_ORDER.index)


def print_policies(policies: list[PolicyProfile]) -> None:
    if not policies:
        console.print("[yellow]No Conditional Access policies in this run "
                      "(none exist, or the mfa_ca check was not run).[/]")
        return
    table = Table(title=f"Conditional Access policies ({len(policies)})",
                  box=box.SIMPLE_HEAD, header_style="bold")
    for column in ("Policy", "State", "Action", "Applies to", "Excludes", "Concerns"):
        table.add_column(column, overflow="fold", no_wrap=column in ("State", "Action"))
    for p in policies:
        state, state_style = STATE_LABEL.get(p.state, (p.state, "white"))
        action, action_style = ACTION_LABEL[p.action]
        worst = _worst_concern(p)
        ex = p.exclusions
        excludes = ", ".join(x for x in (
            f"{len(ex.users)} user(s)" if ex.users else "",
            f"{len(ex.groups)} group(s)" if ex.groups else "",
            f"{len(ex.roles)} role(s)" if ex.roles else "",
            "guests" if ex.guests_or_external else "",
            f"{len(ex.applications)} app(s)" if ex.applications else "",
        ) if x) or "-"
        concerns = Text("-", style="dim") if worst is None else (
            Text(f"{len(p.concerns)} ", style="bold") + Text(worst, style=SEV_STYLE[worst]))
        table.add_row(_t(p.name), Text(state, style=state_style), Text(action, style=action_style),
                      _t("; ".join(p.users)), _t(excludes), concerns)
    console.print(table)
    console.print("[dim]Use `auditor policies --name <text>` for a full plain-English breakdown.[/]")


def print_policy_detail(p: PolicyProfile) -> None:
    state, state_style = STATE_LABEL.get(p.state, (p.state, "white"))
    action, action_style = ACTION_LABEL[p.action]

    if p.action == "grant" and p.requirement_logic:
        rule = (" AND ".join(p.requirements) + "  (all must be satisfied)"
                if p.requirement_logic == "all"
                else " OR ".join(p.requirements) + "  (any one is enough)")
    else:
        rule = "; ".join(p.requirements) or "-"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()
    grid.add_row("In short", _t(p.summary))
    grid.add_row("", Text(""))
    grid.add_row("Who", _t("\n".join(p.users)))
    grid.add_row("Except", _t("\n".join(_exclusion_lines(p)) or "nobody is excluded"))
    grid.add_row("Apps", _t("\n".join(p.applications)))
    grid.add_row("When", _t("\n".join(p.conditions) or "always (no extra conditions)"))
    grid.add_row("Then", Text(action + ": ", style=action_style) + _t(rule))
    if p.session_controls:
        grid.add_row("Session", _t("\n".join(p.session_controls)))
    grid.add_row("Purpose", _t(", ".join(t.value for t in p.tags) or "-"))
    console.print(Panel(grid, title=_t(f"{p.name}  [{state}]"), border_style=state_style))

    if p.concerns:
        table = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Concerns")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Issue", overflow="fold")
        table.add_column("How to fix", overflow="fold")
        for c in sorted(p.concerns, key=lambda c: -SEVERITY_ORDER.index(c.severity)):
            table.add_row(_sev(c.severity), _t(c.text), _t(c.remediation or "-"))
        console.print(table)


def print_run(run: AuditRun, limit: int = 15) -> None:
    print_summary(run)
    if run.status is not RunStatus.FAILED:
        print_findings(run.findings, limit=limit, title="Top findings")


# --------------------------------------------------------------------------- #
# Running an audit
# --------------------------------------------------------------------------- #

def _execute_run(
    mode: Optional[str],
    checks: str,
    cfg: AuditConfig,
    save: bool = True,
) -> AuditRun:
    settings = _settings(mode)
    try:
        names = resolve_checks(checks)
    except ValueError as exc:
        _fail(str(exc))

    provider = create_token_provider(settings)

    # Sign in BEFORE the spinner starts: device-code/browser prompts must stay visible.
    try:
        token = provider.get_token()
    except AuthenticationError as exc:
        _fail(str(exc))
    try:
        missing = sorted(required_permissions(names) - token_permissions(token))
    except AuthenticationError:
        missing = []  # opaque token: can't preflight
    if missing:
        err.print("[yellow]Warning:[/] the token lacks permissions used by the selected checks "
                  "(a broader permission may cover them): " + escape(", ".join(missing))
                  + ". Affected checks will report their data as unavailable.")

    with GraphClient(provider) as graph, console.status("Starting...") as status:
        run = run_audit(
            graph, settings.tenant_id, cfg=cfg, checks=names, identity=provider.identity(),
            progress=lambda message: status.update(f"[bold]{escape(message)}[/]..."),
        )

    print_run(run)
    if save and run.status is not RunStatus.FAILED:
        path = save_run(run)
        console.print(f"[dim]Saved run to {escape(str(path))}[/]")
    return run


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def _load_dotenv() -> None:
    """Read a .env file from the working directory (never overrides real env vars)."""
    try:
        from dotenv import find_dotenv, load_dotenv
    except ImportError:  # optional convenience
        return
    load_dotenv(find_dotenv(usecwd=True), override=False)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"entra-auditor {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[bool, typer.Option(
        "--version", callback=_version_callback, is_eager=True, help="Show version and exit.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Log retries and warnings.")] = False,
) -> None:
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    _load_dotenv()


@app.command()
def run(
    mode: ModeOpt = None,
    checks: Annotated[str, typer.Option(
        "--checks", "-c", help=f"Comma-separated ({', '.join(CHECKS)}) or 'all'.")] = "all",
    inactive_days: Annotated[int, typer.Option(help="Inactivity threshold for member accounts.")] = 90,
    guest_days: Annotated[int, typer.Option(help="Inactivity threshold for guests.")] = 60,
    admin_days: Annotated[int, typer.Option(help="Inactivity threshold for privileged accounts.")] = 45,
    out: Annotated[Optional[Path], typer.Option(
        "--out", "-o", help="Also write reports into this directory.")] = None,
    formats: Annotated[str, typer.Option(help=f"Report formats: {', '.join(SUPPORTED_FORMATS)}.")] = "json,csv",
    save: Annotated[bool, typer.Option(help="Save the run for later browsing.")] = True,
    fail_on: Annotated[Optional[str], typer.Option(
        help="Exit with code 2 if any finding is at/above this severity (for CI).")] = None,
) -> None:
    """Run an audit against your tenant."""
    floor = _validate_severity(fail_on)
    result = _execute_run(mode, checks, _audit_config(inactive_days, guest_days, admin_days), save)

    if result.status is RunStatus.FAILED:
        raise typer.Exit(1)
    if out is not None:
        try:
            for path in write_reports(result, out, formats.split(",")):
                console.print(f"[green]Wrote[/] {escape(str(path))}")
        except ValueError as exc:
            _fail(str(exc))
    if floor and result.findings_at_or_above(floor):
        err.print(f"[red]{len(result.findings_at_or_above(floor))} finding(s) at or above "
                  f"'{floor}'.[/]")
        raise typer.Exit(2)


@app.command()
def findings(
    run_ref: RunArg = None,
    min_severity: Annotated[Optional[str], typer.Option("--min-severity", "-s")] = None,
    check: Annotated[Optional[str], typer.Option("--check", help="Filter by check id (substring).")] = None,
    search: Annotated[Optional[str], typer.Option("--search", help="Filter by title/resource text.")] = None,
    limit: Annotated[int, typer.Option(help="Max rows (0 = all).")] = 0,
    detail: Annotated[bool, typer.Option("--detail", "-d", help="Show evidence and fix for each.")] = False,
) -> None:
    """Browse findings from a saved run."""
    run_ = _load(run_ref)
    items = filter_findings(run_, _validate_severity(min_severity), check, search)
    if detail:
        for f in (items[:limit] if limit else items):
            print_finding_detail(f)
        console.print(f"[dim]{len(items)} finding(s)[/]")
    else:
        print_findings(items, limit)


@app.command()
def policies(
    run_ref: RunArg = None,
    name: Annotated[Optional[str], typer.Option("--name", "-n", help="Show full detail for matches.")] = None,
    concerns_only: Annotated[bool, typer.Option(help="Only policies that have concerns.")] = False,
) -> None:
    """Explain Conditional Access policies in plain English."""
    run_ = _load(run_ref)
    items = run_.policies
    if concerns_only:
        items = [p for p in items if p.concerns]
    if name:
        items = [p for p in items if name.lower() in p.name.lower()]
        if not items:
            _fail(f"No policy name contains '{name}'.")
        for p in items:
            print_policy_detail(p)
    else:
        print_policies(items)


def _write_ca_report(
    run_: AuditRun, out: Optional[Path], mermaid: bool, hide_disabled: bool
) -> list[Path]:
    """Write the HTML report (and optionally the Mermaid .md). ``out`` may be a file or directory."""
    if not run_.policies:
        _fail("This run has no Conditional Access policies (none exist, or the mfa_ca check was "
              "not run). Run `auditor run --checks mfa_ca` first.")
    if out is not None and out.suffix.lower() in (".html", ".htm"):
        html_path = out
    else:
        html_path = (out or Path("reports")) / f"{base_name(run_)}-ca-report.html"
    written = [write_ca_html(run_, html_path, include_disabled=not hide_disabled)]
    if mermaid:
        written.append(write_ca_mermaid(run_, html_path.with_name(
            html_path.stem.removesuffix("-ca-report") + "-ca-diagram.md")))
    return written


@app.command("ca-report")
def ca_report(
    run_ref: RunArg = None,
    out: Annotated[Optional[Path], typer.Option(
        "--out", "-o", help="Output .html file or directory (default: ./reports).")] = None,
    mermaid: Annotated[bool, typer.Option(
        "--mermaid", help="Also write the diagram as a Markdown file (renders on GitHub).")] = False,
    hide_disabled: Annotated[bool, typer.Option(
        "--hide-disabled", help="Leave disabled policies out of the report.")] = False,
    open_browser: Annotated[bool, typer.Option(
        "--open", help="Open the report in your browser.")] = False,
) -> None:
    """Generate a self-contained HTML report of your Conditional Access policies."""
    paths = _write_ca_report(_load(run_ref), out, mermaid, hide_disabled)
    for path in paths:
        console.print(f"[green]Wrote[/] {escape(str(path))}")
    if open_browser:
        webbrowser.open(paths[0].resolve().as_uri())


@app.command()
def compare(
    old: Annotated[str, typer.Argument(help="Older run.")] = "previous",
    new: Annotated[str, typer.Argument(help="Newer run.")] = "latest",
) -> None:
    """Show what changed between two runs (new, resolved, severity changes)."""
    old_run, new_run = _load(old), _load(new)
    diff = diff_runs(old_run, new_run)
    console.print(f"Comparing [bold]{old_run.started_at:%Y-%m-%d %H:%M}[/] -> "
                  f"[bold]{new_run.started_at:%Y-%m-%d %H:%M}[/]")
    if diff.checks_differ:
        console.print("[yellow]The two runs used different checks; new/resolved may reflect that.[/]")
    console.print(f"[red]{len(diff.new)} new[/]   [green]{len(diff.resolved)} resolved[/]   "
                  f"{len(diff.persisting)} unchanged   {len(diff.severity_changed)} changed severity")
    if diff.new:
        print_findings(diff.new, title="New findings")
    if diff.resolved:
        print_findings(diff.resolved, title="Resolved findings")
    for change in diff.severity_changed:
        console.print(f"  {_sev(change.old)} -> {_sev(change.new)}  {escape(change.title)}")


@app.command()
def runs() -> None:
    """List saved runs."""
    saved = list_runs()
    if not saved:
        console.print(f"[yellow]No saved runs in {escape(str(default_runs_dir()))}.[/]")
        return
    table = Table(box=box.SIMPLE_HEAD, header_style="bold")
    for column in ("Started (UTC)", "Run", "Status", "Findings", "Worst", "Tenant"):
        table.add_column(column, no_wrap=True)
    for r in saved:
        worst = _sev(r.highest_severity) if r.highest_severity else Text("-", style="dim")
        table.add_row(f"{r.started_at:%Y-%m-%d %H:%M}", r.id[:8], r.status, str(r.total_findings),
                      worst, r.tenant_id)
    console.print(table)


@app.command()
def export(
    run_ref: RunArg = None,
    out: Annotated[Path, typer.Option("--out", "-o", help="Output directory.")] = Path("reports"),
    formats: Annotated[str, typer.Option(help=f"{', '.join(SUPPORTED_FORMATS)}.")] = "json,csv",
) -> None:
    """Write JSON/CSV reports for a saved run."""
    run_ = _load(run_ref)
    try:
        for path in write_reports(run_, out, formats.split(",")):
            console.print(f"[green]Wrote[/] {escape(str(path))}")
    except ValueError as exc:
        _fail(str(exc))


def _permissions_table(mode: Optional[str], checks: str) -> None:
    settings = _settings(mode)
    try:
        names = resolve_checks(checks)
        provider = create_token_provider(settings)
        granted = token_permissions(provider.get_token())
    except (ValueError, AuthenticationError) as exc:
        _fail(str(exc))

    needed_by: dict[str, list[str]] = {}
    for name in names:
        for permission in required_permissions([name]):
            needed_by.setdefault(permission, []).append(name)

    table = Table(title=f"Permissions ({settings.mode.value} mode)", box=box.SIMPLE_HEAD,
                  header_style="bold")
    table.add_column("Permission")
    table.add_column("Needed by")
    table.add_column("Granted", justify="center")
    for permission in sorted(needed_by):
        ok = permission in granted
        table.add_row(permission, ", ".join(needed_by[permission]),
                      Text("yes", style="green") if ok else Text("MISSING", style="bold red"))
    console.print(table)
    console.print("[dim]A missing permission may still be covered by a broader one "
                  "(e.g. Directory.Read.All). Checks report unavailable data instead of failing.[/]")


@app.command()
def permissions(
    mode: ModeOpt = None,
    checks: Annotated[str, typer.Option("--checks", "-c")] = "all",
) -> None:
    """Show which Graph permissions the selected checks need, and which you have."""
    _permissions_table(mode, checks)


def _user_provider(mode: Optional[str], allow_interactive: bool) -> UserTokenProvider:
    if mode is None and os.environ.get("AUDITOR_AUTH_MODE", "app").strip().lower() == "app":
        mode = "device"  # login only makes sense for a user mode
    settings = _settings(mode)
    provider = create_token_provider(settings, allow_interactive=allow_interactive)
    if not isinstance(provider, UserTokenProvider):
        _fail("This command is for user sign-in. Use --mode device or --mode browser.")
    return provider


@app.command()
def login(mode: ModeOpt = None) -> None:
    """Sign in as a user (device code or browser) and cache the session."""
    provider = _user_provider(mode, True)
    try:
        identity = provider.login()
    except AuthenticationError as exc:
        _fail(str(exc))
    console.print(f"[green]Signed in as[/] {escape(identity)}")


@app.command()
def logout(mode: ModeOpt = None) -> None:
    """Forget the cached user session."""
    provider = _user_provider(mode, False)
    try:
        provider.logout()
    except AuthenticationError as exc:
        _fail(str(exc))
    console.print("Signed out and cleared the token cache.")


@app.command()
def whoami(mode: ModeOpt = None) -> None:
    """Show how the tool would authenticate right now."""
    settings = _settings(mode)
    console.print(f"Mode:   {settings.mode.value}\nTenant: {escape(settings.tenant_id)}")
    if settings.mode is AuthMode.APP:
        console.print(f"App:    {escape(settings.client_id)}")
        return
    provider = create_token_provider(settings, allow_interactive=False)
    console.print(f"User:   {escape(provider.identity())}")


# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #

def _pick_run(q, prompt: str = "Choose a run") -> Optional[Path]:
    saved = list_runs()
    if not saved:
        console.print("[yellow]No saved runs yet. Run an audit first.[/]")
        return None
    choices = [
        q.Choice(title=f"{r.started_at:%Y-%m-%d %H:%M}  {r.status:<9} {r.total_findings:>4} findings  {r.id[:8]}",
                 value=r.path)
        for r in saved[:30]
    ]
    return q.select(prompt, choices=choices).ask()


def _browse_findings(q, run_: AuditRun) -> None:
    label = q.select("Show which severities?", choices=[
        q.Choice("Everything", value=None), q.Choice("High and above", value="high"),
        q.Choice("Medium and above", value="medium"), q.Choice("Critical only", value="critical"),
    ]).ask()
    while True:
        items = filter_findings(run_, label)[:500]
        if not items:
            console.print("[green]No findings at that level.[/]")
            return
        picked = q.select(
            f"{len(items)} finding(s). Select one for details:",
            choices=[q.Choice(f"[{f.severity:<8}] {f.title[:100]}", value=i) for i, f in enumerate(items)]
                    + [q.Choice("<- Back", value=None)],
        ).ask()
        if picked is None:
            return
        print_finding_detail(items[picked])
        console.input("[dim]Press Enter to continue[/]")


def _browse_policies(q, run_: AuditRun) -> None:
    if not run_.policies:
        console.print("[yellow]This run has no Conditional Access policies.[/]")
        return
    print_policies(run_.policies)
    while True:
        picked = q.select("Explain which policy?", choices=[
            q.Choice(f"{p.name}  ({STATE_LABEL.get(p.state, (p.state,))[0]}, {ACTION_LABEL[p.action][0]})",
                     value=i) for i, p in enumerate(run_.policies)
        ] + [q.Choice("<- Back", value=None)]).ask()
        if picked is None:
            return
        print_policy_detail(run_.policies[picked])
        console.input("[dim]Press Enter to continue[/]")


@app.command()
def menu(mode: ModeOpt = None) -> None:
    """Interactive menu: run audits, browse findings and policies, export, compare."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        _fail("The interactive menu needs a terminal. Use the other commands in scripts.")
    try:
        import questionary as q
    except ImportError:
        _fail("The menu needs the 'questionary' package (pip install questionary).")

    current: Optional[AuditRun] = None
    saved = list_runs()
    if saved:
        try:
            current = load_run(saved[0].path)
        except (ValueError, OSError):
            current = None

    while True:
        console.rule("[bold cyan]Entra Security Auditor")
        if current:
            console.print(f"Current run: {current.started_at:%Y-%m-%d %H:%M} UTC, "
                          f"{len(current.findings)} findings ({current.status.value})")
        choice = q.select("What would you like to do?", choices=[
            q.Choice("Run a new audit", value="run"),
            q.Choice("Browse findings", value="findings"),
            q.Choice("Conditional Access policies (plain English)", value="policies"),
            q.Choice("Conditional Access report (HTML + diagram)", value="ca_report"),
            q.Choice("Export report (JSON / CSV)", value="export"),
            q.Choice("Compare two runs", value="compare"),
            q.Choice("Switch to a saved run", value="switch"),
            q.Choice("Check API permissions", value="permissions"),
            q.Choice("Quit", value="quit"),
        ]).ask()
        if choice in (None, "quit"):
            return

        try:
            if choice == "run":
                picked = q.checkbox("Checks to run", choices=[
                    q.Choice(name, value=name, checked=True) for name in CHECKS]).ask()
                if picked:
                    current = _execute_run(mode, ",".join(picked), AuditConfig(), save=True)
            elif choice == "permissions":
                _permissions_table(mode, "all")
            elif choice in ("findings", "policies", "ca_report", "export") and current is None:
                console.print("[yellow]No run loaded yet. Run an audit or switch to a saved run.[/]")
            elif choice == "findings":
                _browse_findings(q, current)
            elif choice == "policies":
                _browse_policies(q, current)
            elif choice == "ca_report":
                directory = q.text("Output directory:", default="reports").ask()
                if directory:
                    paths = _write_ca_report(current, Path(directory), True, False)
                    for path in paths:
                        console.print(f"[green]Wrote[/] {escape(str(path))}")
                    if q.confirm("Open the report in your browser?", default=True).ask():
                        webbrowser.open(paths[0].resolve().as_uri())
            elif choice == "export":
                chosen = q.checkbox("Formats", choices=[
                    q.Choice(f, checked=True) for f in SUPPORTED_FORMATS]).ask()
                directory = q.text("Output directory:", default="reports").ask()
                if chosen and directory:
                    for path in write_reports(current, Path(directory), chosen):
                        console.print(f"[green]Wrote[/] {escape(str(path))}")
            elif choice == "compare":
                old_path = _pick_run(q, "Older run")
                new_path = _pick_run(q, "Newer run") if old_path else None
                if old_path and new_path:
                    diff = diff_runs(load_run(old_path), load_run(new_path))
                    console.print(f"[red]{len(diff.new)} new[/]  [green]{len(diff.resolved)} resolved[/]  "
                                  f"{len(diff.persisting)} unchanged")
                    print_findings(diff.new, title="New findings")
                    print_findings(diff.resolved, title="Resolved findings")
            elif choice == "switch":
                path = _pick_run(q)
                if path:
                    current = load_run(path)
        except typer.Exit:
            continue  # a failed action reports its own error; stay in the menu
        except (ValueError, OSError) as exc:
            err.print(f"[red]{escape(str(exc))}[/]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
