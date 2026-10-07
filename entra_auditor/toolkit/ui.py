"""Terminal rendering for the toolkit and the one flow every change goes through:

    preview the plan -> confirm -> execute -> (if Entra says "forbidden": offer PIM elevation,
    wait for the role to take effect, refresh the token, retry)

Used by both the Typer commands and the interactive menu, so they behave identically.
"""

from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Optional, Sequence

import typer
from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..cli_common import console, err, fail, t
from ..graph.client import GraphClient, GraphError
from .actions import ActionPlan, ActionResult, execute_plan
from .models import AppSummary, GroupSummary, UserProfile, UserSummary
from .pim import PimError, PimRole, PimService
from .search import AmbiguousIdentity, IdentityNotFound, resolve_group, resolve_user

_sleep = time.sleep        # replaced in tests
RETRY_ATTEMPTS = 4         # tries after an elevation (the role takes a moment to take effect)
RETRY_WAIT = 8.0


# --------------------------------------------------------------------------- #
# Session
# --------------------------------------------------------------------------- #

@dataclass
class Session:
    graph: Any
    provider: Any
    settings: Any
    identity: str

    @property
    def user_mode(self) -> bool:
        return self.settings.mode.is_user

    def refresh(self) -> None:
        """Fetch a fresh token (a role activated moments ago may not be in the cached one)."""
        refresh = getattr(self.provider, "refresh", None)
        if refresh:
            try:
                refresh()
            except Exception as exc:  # noqa: BLE001 - a failed refresh must not hide the real result
                err.print(f"[yellow]Could not refresh the token: {escape(str(exc))}[/]")


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def toolkit_mode(mode: Optional[str]) -> Optional[str]:
    """The toolkit is meant for user sign-in (so PIM works); default to device code when the
    environment is set up for unattended app mode."""
    if mode is None and os.environ.get("AUDITOR_AUTH_MODE", "app").strip().lower() == "app":
        return "device"
    return mode


@contextmanager
def open_session(mode: Optional[str]) -> Iterator[Session]:
    from ..auth import AuthenticationError, create_token_provider, toolkit_scopes
    from ..cli_common import build_settings

    settings = build_settings(toolkit_mode(mode), scopes=toolkit_scopes())
    if not settings.mode.is_user:
        err.print("[yellow]Warning:[/] --mode app uses the app registration's own permissions for "
                  "every change, with no PIM and no per-person accountability. Prefer a user sign-in.")
    provider = create_token_provider(settings)
    try:
        provider.get_token()  # sign in BEFORE any spinner so prompts stay visible
    except AuthenticationError as exc:
        fail(str(exc))
    with GraphClient(provider) as graph:
        yield Session(graph, provider, settings, provider.identity())


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _status(enabled: bool | None) -> Text:
    if enabled is None:
        return Text("?", style="dim")
    return Text("enabled", style="green") if enabled else Text("disabled", style="bold red")


def print_users(users: Sequence[UserSummary], title: str = "Users", numbered: bool = False) -> None:
    table = Table(title=f"{title} ({len(users)})", box=box.SIMPLE_HEAD, header_style="bold")
    if numbered:
        table.add_column("#", justify="right")
    for column in ("User", "Name", "Type", "Status", "Title / department", "Matched by"):
        table.add_column(column, overflow="fold")
    for index, u in enumerate(users, 1):
        extra = " / ".join(x for x in (u.job_title, u.department) if x) or "-"
        row = [t(u.label), t(u.display_name or "-"), t(u.user_type or "-"), _status(u.account_enabled),
               t(extra), t(u.matched_by or "-")]
        table.add_row(*(([str(index)] if numbered else []) + row))
    console.print(table)


def print_groups(groups: Sequence[GroupSummary], title: str = "Groups", numbered: bool = False) -> None:
    table = Table(title=f"{title} ({len(groups)})", box=box.SIMPLE_HEAD, header_style="bold")
    if numbered:
        table.add_column("#", justify="right")
    for column in ("Group", "Kind", "Mail", "Notes"):
        table.add_column(column, overflow="fold")
    for index, g in enumerate(groups, 1):
        notes = ", ".join(x for x in (
            "dynamic" if g.is_dynamic else "", "synced from AD" if g.on_prem_synced else "",
            "role-assignable" if g.is_role_assignable else "") if x) or "-"
        row = [t(g.label), t(g.kind_label), t(g.mail or "-"), t(notes)]
        table.add_row(*(([str(index)] if numbered else []) + row))
    console.print(table)


def print_apps(apps: Sequence[AppSummary]) -> None:
    table = Table(title=f"Applications ({len(apps)})", box=box.SIMPLE_HEAD, header_style="bold")
    for column in ("Name", "App id", "Type", "Status"):
        table.add_column(column, overflow="fold")
    for a in apps:
        table.add_row(t(a.label), t(a.app_id or "-"), t(a.service_principal_type or "-"), _status(a.account_enabled))
    console.print(table)


def _lines(items: Sequence[str] | None, empty: str = "-", limit: int = 12) -> str:
    if items is None:
        return "(could not be read)"
    if not items:
        return empty
    shown = list(items[:limit])
    return "\n".join(shown) + (f"\n... and {len(items) - limit} more" if len(items) > limit else "")


def print_profile(p: UserProfile) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()

    def row(label: str, value: Any) -> None:
        grid.add_row(label, value if isinstance(value, Text) else t(value if value not in (None, "") else "-"))

    row("Name", p.display_name)
    row("UPN", p.upn)
    row("Email", p.mail)
    row("Object id", p.id)
    row("Type", p.user_type)
    row("Account", _status(p.account_enabled))
    row("Job", " / ".join(x for x in (p.job_title, p.department, p.company) if x) or "-")
    row("Office / phone", " / ".join(x for x in (p.office, p.mobile_phone) if x) or "-")
    row("Employee id", p.employee_id)
    row("Manager", p.manager)
    row("Created", f"{p.created_at:%Y-%m-%d}" if p.created_at else None)
    row("Password changed", f"{p.last_password_change:%Y-%m-%d}" if p.last_password_change else None)
    row("Last sign-in", (f"{p.last_sign_in:%Y-%m-%d %H:%M} UTC" if p.last_sign_in else
                         "never / unknown") if p.sign_in_available else "(needs Entra ID P1/P2)")
    row("Synced from AD", ("yes" + (f" ({p.on_prem_sam_account})" if p.on_prem_sam_account else ""))
        if p.on_prem_synced else "no (cloud only)")
    if p.is_guest:
        row("Invitation", p.external_user_state)
    row("Licences", p.license_count)
    row("Email aliases", _lines([a for a in p.proxy_addresses if a.lower().startswith("smtp:")]
                                + p.other_mails))
    row("Admin roles (active)", _lines(p.roles_active, "none"))
    row("Admin roles (eligible)", _lines(p.roles_eligible, "none"))
    row("Sign-in methods", _lines(p.auth_methods, "none registered"))
    row("Certificate IDs", _lines(p.cert_user_ids, "none"))
    row("Member of", _lines([g.label for g in p.groups] if p.groups is not None else None, "no groups"))
    row("Owns", _lines([o.label for o in p.owned] if p.owned is not None else None, "nothing"))
    console.print(Panel(grid, title=t(p.label), border_style="cyan"))
    for warning in p.warnings:
        console.print(Text(f"! {warning}", style="yellow"))


def print_group_detail(group: GroupSummary, detail: dict[str, Any]) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()
    grid.add_row("Kind", t(group.kind_label))
    grid.add_row("Mail", t(group.mail or "-"))
    grid.add_row("Description", t(group.description or "-"))
    grid.add_row("Object id", t(group.id))
    grid.add_row("Notes", t(", ".join(x for x in (
        "dynamic: " + (group.membership_rule or "") if group.is_dynamic else "",
        "synced from on-premises AD" if group.on_prem_synced else "",
        "role-assignable" if group.is_role_assignable else "") if x) or "-"))
    owners = [o.label for o in detail["owners"]]
    members = [m.label for m in detail["members"]]
    grid.add_row("Owners", t(_lines(owners, "NONE (unowned)") + ("\n(list truncated)" if detail["owners_truncated"] else "")))
    grid.add_row("Members", t(_lines(members, "none", limit=25)
                              + ("\n(list truncated; more exist)" if detail["members_truncated"] else "")))
    console.print(Panel(grid, title=t(group.label), border_style="cyan"))


def print_pim(eligible: Sequence[PimRole], active: Sequence[PimRole]) -> None:
    table = Table(title="Your roles (PIM)", box=box.SIMPLE_HEAD, header_style="bold")
    for column in ("Role", "State", "Until"):
        table.add_column(column, overflow="fold")
    active_ids = {r.role_id for r in active}
    for r in active:
        how = "active (activated)" if r.activated else "active (standing)"
        table.add_row(t(r.label), Text(how, style="green"), t(f"{r.ends:%Y-%m-%d %H:%M} UTC" if r.ends else "no end"))
    for r in eligible:
        if r.role_id not in active_ids:
            table.add_row(t(r.label), Text("eligible", style="cyan"), t(f"eligibility ends {r.ends:%Y-%m-%d}" if r.ends else "-"))
    if not eligible and not active:
        console.print("[yellow]You have no eligible or active directory roles.[/]")
        return
    console.print(table)


def print_plan(plan: ActionPlan) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()
    grid.add_row("Change", t(plan.title))
    grid.add_row("Target", t(f"{plan.target_type}: {plan.target_name}"))
    if plan.details:
        grid.add_row("Details", t("\n".join(plan.details)))
    if plan.suggested_roles:
        grid.add_row("Needs one of", t(", ".join(plan.suggested_roles)))
    console.print(Panel(grid, title="About to change your tenant", border_style="yellow"))
    requests = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Graph requests")
    for column in ("Method", "Path", "Body"):
        requests.add_column(column, overflow="fold")
    for r in plan.requests:
        body = r.redacted_json()
        requests.add_row(t(r.method), t(r.path), t("-" if body is None else str(body)))
    console.print(requests)
    for warning in plan.warnings:
        console.print(Text(f"! {warning}", style="yellow"))


def print_result(result: ActionResult) -> None:
    style = {"ok": "green", "dry_run": "yellow", "skipped": "yellow", "partial": "bold yellow"}.get(result.status, "bold red")
    console.print(Text(f"{result.status.upper()}: {result.message}", style=style))
    for line in result.lines:
        console.print(t(f"  - {line}"))
    password = result.secrets.get("password")
    if password:
        console.print(Panel(Text(password, style="bold"), title="New password (shown once, never logged)",
                            border_style="green"))
        console.print("[dim]The user must change it at next sign-in. Share it over a secure channel.[/]")


# --------------------------------------------------------------------------- #
# Picking among several matches (command-line flow)
# --------------------------------------------------------------------------- #

def _ask_number(count: int, what: str) -> int:
    while True:
        answer = typer.prompt(f"Which {what}? (1-{count})", type=int)
        if 1 <= answer <= count:
            return answer
        console.print(f"[red]Enter a number between 1 and {count}.[/]")


def resolve_user_or_pick(graph: Any, ident: str, by: str = "auto") -> UserSummary:
    try:
        return resolve_user(graph, ident, by)
    except IdentityNotFound as exc:
        fail(str(exc))
    except ValueError as exc:
        fail(str(exc))
    except AmbiguousIdentity as exc:
        print_users(exc.candidates, f"'{ident}' matches several users", numbered=True)
        if not is_interactive():
            fail("That matches several users; use the full UPN or the object id.")
        return exc.candidates[_ask_number(len(exc.candidates), "user") - 1]


def resolve_group_or_pick(graph: Any, ident: str) -> GroupSummary:
    try:
        return resolve_group(graph, ident)
    except IdentityNotFound as exc:
        fail(str(exc))
    except ValueError as exc:
        fail(str(exc))
    except AmbiguousIdentity as exc:
        print_groups(exc.candidates, f"'{ident}' matches several groups", numbered=True)
        if not is_interactive():
            fail("That matches several groups; use the exact name or the object id.")
        return exc.candidates[_ask_number(len(exc.candidates), "group") - 1]


# --------------------------------------------------------------------------- #
# PIM elevation
# --------------------------------------------------------------------------- #

def activate_role(sess: Session, pim: PimService, role: PimRole, reason: str, minutes: int) -> bool:
    """Activate and wait until it is effective. Returns True when the role is usable."""
    try:
        result = pim.activate(role, reason=reason, minutes=minutes)
    except PimError as exc:
        console.print(Text(f"Could not activate {role.name}: {exc}", style="bold red"))
        if exc.hint:
            console.print(t(exc.hint))
        return False
    if result.pending_approval:
        console.print(Text(f"{role.name} needs approval; the request was sent to the approvers.", style="yellow"))
        return False
    with console.status(f"Waiting for {role.name} to become active..."):
        active = pim.wait_until_active(role.role_id)
    if not active:
        console.print(Text(f"{role.name} was requested but isn't showing as active yet; try again shortly.", style="yellow"))
        return False
    sess.refresh()
    console.print(Text(f"{role.name} is active for {minutes} minutes.", style="green"))
    return True


def _elevation_hint(plan: ActionPlan) -> None:
    console.print(t("You can activate a role yourself with `auditor pim activate <role>`; this change needs one of: "
                    + ", ".join(plan.suggested_roles) + "."))


def offer_elevation(
    sess: Session, plan: ActionPlan, *, elevate: Optional[bool], reason: Optional[str],
    minutes: int, yes: bool,
) -> bool:
    """After a 'forbidden': offer to activate a suitable eligible role. True = try again."""
    console.print(Text("Entra says your current permissions aren't enough for this change.", style="yellow"))
    if not sess.user_mode:
        console.print("PIM only works with a user sign-in (--mode device or browser); in app mode the "
                      "app registration itself lacks the permission.")
        return False
    pim = PimService(sess.graph)
    try:
        eligible, active = pim.eligible(), pim.active()
    except GraphError as exc:
        console.print(t(f"Couldn't read your PIM roles ({exc})."))
        _elevation_hint(plan)
        return False

    wanted = {n.lower() for n in plan.suggested_roles}
    already = [r for r in active if r.name.lower() in wanted]
    if already:
        console.print(t(f"You already have {already[0].name} active; refreshing your token and retrying."))
        sess.refresh()
        return True

    matches = PimService.match(eligible, plan.suggested_roles, active)
    if not matches:
        console.print(t("You aren't eligible for any role that can do this ("
                        + ", ".join(plan.suggested_roles) + ")."))
        if eligible:
            console.print(t("You are eligible for: " + ", ".join(r.name for r in eligible)))
        return False

    role = matches[0]
    if len(matches) > 1 and is_interactive() and not yes and elevate is not False:
        for index, candidate in enumerate(matches, 1):
            console.print(t(f"  {index}. {candidate.label}"))
        role = matches[_ask_number(len(matches), "role to activate") - 1]

    if elevate is False:
        _elevation_hint(plan)
        return False
    if elevate is None:
        if yes or not is_interactive():
            _elevation_hint(plan)
            return False
        if not typer.confirm(f"Activate {role.label} for {minutes} minutes and retry?", default=True):
            return False

    why = (reason or "").strip()
    if not why and is_interactive():
        why = str(typer.prompt("Justification for activating the role (ticket or task)")).strip()
    if not why:
        console.print("[red]A justification is required: pass --reason.[/]")
        return False
    return activate_role(sess, pim, role, why, minutes)


# --------------------------------------------------------------------------- #
# The shared change flow
# --------------------------------------------------------------------------- #

def _execute(sess: Session, plan: ActionPlan) -> ActionResult:
    return execute_plan(sess.graph, plan, actor=sess.identity)


def run_action(
    sess: Session,
    plan: ActionPlan,
    *,
    yes: bool = False,
    dry_run: bool = False,
    elevate: Optional[bool] = None,
    reason: Optional[str] = None,
    minutes: int = 60,
    extra_secrets: Optional[dict[str, str]] = None,
) -> ActionResult:
    print_plan(plan)
    if dry_run:
        result = execute_plan(sess.graph, plan, actor=sess.identity, dry_run=True)
        print_result(result)
        return result
    if not yes and not typer.confirm("Apply this change?", default=False):
        console.print("[yellow]Cancelled. Nothing was changed.[/]")
        return ActionResult("skipped", "Cancelled by the user.")

    result = _execute(sess, plan)
    if result.status == "denied" and offer_elevation(
        sess, plan, elevate=elevate, reason=reason, minutes=minutes, yes=yes
    ):
        for attempt in range(RETRY_ATTEMPTS):
            result = _execute(sess, plan)
            if result.status != "denied" or attempt == RETRY_ATTEMPTS - 1:
                break
            if attempt == 1:
                sess.refresh()
            with console.status("Waiting for the role to take effect..."):
                _sleep(RETRY_WAIT)
    if result.status == "ok" and extra_secrets:
        result.secrets.update(extra_secrets)  # e.g. a password generated locally: shown once
    print_result(result)
    return result
