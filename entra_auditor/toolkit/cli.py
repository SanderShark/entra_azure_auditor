"""Identity toolkit commands.

    auditor id search|show|edit|enable|disable|revoke|password|cert-list|cert-add|cert-remove|log
    auditor group show|add-member|remove-member|add-owner|remove-owner|stale
    auditor pim list|activate|deactivate
    auditor toolkit            interactive menu over all of it

Every change is previewed first, needs confirmation (``--yes`` skips only the prompt, never the
preview), can be rehearsed with ``--dry-run``, and is recorded in the local action log. If Entra
says you lack the role, the tool offers to activate a suitable PIM role and retries.
"""

import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich import box
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from ..cli_common import ModeOpt, console, err, fail, sev, t
from ..graph.client import GraphError, GraphPermissionError
from ..reports import groups_rows, load_run, resolve_run, write_groups_csv
from . import audit_log
from .actions import (
    PlanError,
    parse_assignments,
    plan_add_group_members,
    plan_add_group_owners,
    plan_remove_group_members,
    plan_remove_group_owners,
    plan_reset_password,
    plan_revoke_sessions,
    plan_set_certificate_user_ids,
    plan_set_enabled,
    plan_update_user,
    EDITABLE_USER_FIELDS,
)
from .certids import (
    BINDINGS,
    CertIdError,
    build_cert_id,
    describe_entry,
    get_binding,
    merge_cert_ids,
    normalise_full_entry,
    remove_cert_ids,
)
from .models import GroupSummary, UserSummary
from .passwords import generate_password
from .pim import PimError, PimService
from .profile import (
    get_certificate_user_ids,
    group_detail,
    holds_admin_roles,
    list_group_people,
    load_user_profile,
    profile_current_values,
)
from .search import (
    IdentityNotFound,
    find_apps,
    find_groups,
    find_users,
    get_group,
    get_user,
)
from .ui import (
    Session,
    activate_role,
    is_interactive,
    open_session,
    print_apps,
    print_group_detail,
    print_groups,
    print_pim,
    print_profile,
    print_users,
    resolve_group_or_pick,
    resolve_user_or_pick,
    run_action,
)

id_app = typer.Typer(help="Search, inspect and edit identities.", no_args_is_help=True, add_completion=False)
group_app = typer.Typer(help="Group tools: show, change membership/owners, find stale groups.",
                        no_args_is_help=True, add_completion=False)
pim_app = typer.Typer(help="Activate your eligible roles (PIM) just-in-time.", no_args_is_help=True,
                      add_completion=False)

# --- shared option types ------------------------------------------------------
ByOpt = Annotated[str, typer.Option(
    "--by", help="How to look the user up: auto | upn | mail | id | name | alias | employee | proxy.")]
YesOpt = Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt (the preview is still shown).")]
DryRunOpt = Annotated[bool, typer.Option("--dry-run", help="Show exactly what would be sent; change nothing.")]
ElevateOpt = Annotated[Optional[bool], typer.Option(
    "--elevate/--no-elevate", help="If Entra says you lack the role, activate a suitable PIM role and retry (default: ask).")]
ReasonOpt = Annotated[Optional[str], typer.Option("--reason", help="Justification used if a PIM role is activated.")]
MinutesOpt = Annotated[int, typer.Option("--minutes", help="How long a PIM role stays active, in minutes.")]
RunRef = Annotated[Optional[str], typer.Argument(
    help="Saved audit run: latest (default), previous, a run id prefix, or a .json file.")]

_FAILED = ("denied", "failed", "partial")


@contextmanager
def graph_errors():
    """Turn Graph failures into a readable message instead of a traceback."""
    try:
        yield
    except GraphPermissionError as exc:
        fail(f"Not permitted: {exc}\nCheck the app registration has the delegated permission (with admin "
             "consent) and that your account can read this; activate a role with `auditor pim activate`.")
    except GraphError as exc:
        fail(str(exc))


def _finish(result) -> None:
    if result.status in _FAILED:
        raise typer.Exit(1)


# =========================================================================== #
# auditor id ...
# =========================================================================== #

@id_app.command("search")
def id_search(
    query: Annotated[str, typer.Argument(help="UPN, email or alias address, name, employee id, mail alias or object id.")],
    by: ByOpt = "auto",
    kind: Annotated[str, typer.Option("--type", "-t", help="What to search: user | group | app | all.")] = "user",
    limit: Annotated[int, typer.Option(help="Maximum results per type.")] = 25,
    mode: ModeOpt = None,
) -> None:
    """Find identities. Typing a plain name also surfaces exact alias matches, so look-alikes are visible."""
    if kind not in ("user", "group", "app", "all"):
        fail("--type must be one of: user, group, app, all")
    with open_session(mode) as sess, graph_errors():
        found = False
        try:
            if kind in ("user", "all"):
                users = find_users(sess.graph, query, by=by, limit=limit)
                found |= bool(users)
                if users:
                    print_users(users)
            if kind in ("group", "all"):
                groups = find_groups(sess.graph, query, limit=limit)
                found |= bool(groups)
                if groups:
                    print_groups(groups)
            if kind in ("app", "all"):
                apps = find_apps(sess.graph, query, limit=limit)
                found |= bool(apps)
                if apps:
                    print_apps(apps)
        except ValueError as exc:
            fail(str(exc))
        if not found:
            console.print("[yellow]No matches.[/]")


@id_app.command("show")
def id_show(
    ident: Annotated[str, typer.Argument(help="UPN, email, name, employee id, alias or object id.")],
    by: ByOpt = "auto",
    mode: ModeOpt = None,
) -> None:
    """Show everything about one user: attributes, sign-in, groups, roles, auth methods, certificate IDs."""
    with open_session(mode) as sess, graph_errors():
        user = resolve_user_or_pick(sess.graph, ident, by)
        with console.status("Loading profile..."):
            profile = load_user_profile(sess.graph, user.id)
        print_profile(profile)


@id_app.command("edit")
def id_edit(
    ident: Annotated[str, typer.Argument(help="The user to edit.")],
    set_: Annotated[Optional[list[str]], typer.Option(
        "--set", "-s", help="field=value, repeatable; an empty value clears it. Fields: "
        + ", ".join(sorted(EDITABLE_USER_FIELDS)))] = None,
    by: ByOpt = "auto",
    yes: YesOpt = False,
    dry_run: DryRunOpt = False,
    elevate: ElevateOpt = None,
    reason: ReasonOpt = None,
    minutes: MinutesOpt = 60,
    mode: ModeOpt = None,
) -> None:
    """Edit user attributes (title, department, phone, ...), e.g.  --set title="Staff Engineer" --set dept=IT"""
    try:
        changes = parse_assignments(set_ or [])
    except PlanError as exc:
        fail(str(exc))
    with open_session(mode) as sess, graph_errors():
        user = resolve_user_or_pick(sess.graph, ident, by)
        current = profile_current_values(load_user_profile(sess.graph, user.id))
        try:
            plan = plan_update_user(user, changes, current)
        except PlanError as exc:
            fail(str(exc))
        _finish(run_action(sess, plan, yes=yes, dry_run=dry_run, elevate=elevate, reason=reason, minutes=minutes))


def _toggle(ident: str, enabled: bool, by: str, yes: bool, dry_run: bool, elevate: Optional[bool],
            reason: Optional[str], minutes: int, mode: Optional[str]) -> None:
    with open_session(mode) as sess, graph_errors():
        user = resolve_user_or_pick(sess.graph, ident, by)
        try:
            plan = plan_set_enabled(user, enabled)
        except PlanError as exc:
            fail(str(exc))
        _finish(run_action(sess, plan, yes=yes, dry_run=dry_run, elevate=elevate, reason=reason, minutes=minutes))


@id_app.command("enable")
def id_enable(ident: Annotated[str, typer.Argument(help="The user.")], by: ByOpt = "auto", yes: YesOpt = False,
              dry_run: DryRunOpt = False, elevate: ElevateOpt = None, reason: ReasonOpt = None,
              minutes: MinutesOpt = 60, mode: ModeOpt = None) -> None:
    """Enable a user account."""
    _toggle(ident, True, by, yes, dry_run, elevate, reason, minutes, mode)


@id_app.command("disable")
def id_disable(ident: Annotated[str, typer.Argument(help="The user.")], by: ByOpt = "auto", yes: YesOpt = False,
               dry_run: DryRunOpt = False, elevate: ElevateOpt = None, reason: ReasonOpt = None,
               minutes: MinutesOpt = 60, mode: ModeOpt = None) -> None:
    """Disable a user account (consider `revoke` as well to end live sessions)."""
    _toggle(ident, False, by, yes, dry_run, elevate, reason, minutes, mode)


@id_app.command("revoke")
def id_revoke(ident: Annotated[str, typer.Argument(help="The user.")], by: ByOpt = "auto", yes: YesOpt = False,
              dry_run: DryRunOpt = False, elevate: ElevateOpt = None, reason: ReasonOpt = None,
              minutes: MinutesOpt = 60, mode: ModeOpt = None) -> None:
    """Revoke all of a user's sign-in sessions."""
    with open_session(mode) as sess, graph_errors():
        user = resolve_user_or_pick(sess.graph, ident, by)
        _finish(run_action(sess, plan_revoke_sessions(user), yes=yes, dry_run=dry_run, elevate=elevate,
                           reason=reason, minutes=minutes))


@id_app.command("password")
def id_password(
    ident: Annotated[str, typer.Argument(help="The user.")],
    prompt_: Annotated[bool, typer.Option("--prompt", help="Type the new password (hidden) instead of generating one.")] = False,
    local: Annotated[bool, typer.Option("--local", help="Generate the password here instead of asking Entra to.")] = False,
    by: ByOpt = "auto",
    yes: YesOpt = False,
    dry_run: DryRunOpt = False,
    elevate: ElevateOpt = None,
    reason: ReasonOpt = None,
    minutes: MinutesOpt = 60,
    mode: ModeOpt = None,
) -> None:
    """Reset a user's password. By default Entra generates it; it is shown once and never logged."""
    if prompt_ and local:
        fail("Choose --prompt or --local, not both.")
    with open_session(mode) as sess, graph_errors():
        user = resolve_user_or_pick(sess.graph, ident, by)
        profile = load_user_profile(sess.graph, user.id)
        password: Optional[str] = None
        reveal: dict[str, str] = {}
        if prompt_:
            password = str(typer.prompt("New password", hide_input=True, confirmation_prompt=True))
        elif local or user.on_prem_synced:
            password = generate_password()
            reveal = {"password": password}
            if user.on_prem_synced and not local:
                console.print("[yellow]Synced account: Entra can't generate the password, so one is generated here.[/]")
        try:
            plan = plan_reset_password(user, password, target_is_admin=holds_admin_roles(profile))
        except PlanError as exc:
            fail(str(exc))
        _finish(run_action(sess, plan, yes=yes, dry_run=dry_run, elevate=elevate, reason=reason,
                           minutes=minutes, extra_secrets=reveal))


@id_app.command("cert-list")
def id_cert_list(ident: Annotated[str, typer.Argument(help="The user.")], by: ByOpt = "auto",
                 mode: ModeOpt = None) -> None:
    """List a user's certificate user IDs (certificate-based authentication bindings)."""
    with open_session(mode) as sess, graph_errors():
        user = resolve_user_or_pick(sess.graph, ident, by)
        entries = get_certificate_user_ids(sess.graph, user.id)
        if not entries:
            console.print("[yellow]No certificate user IDs.[/]")
            return
        table = Table(title=t(f"Certificate user IDs for {user.label}"), box=box.SIMPLE_HEAD, header_style="bold")
        table.add_column("Type")
        table.add_column("Value", overflow="fold")
        for entry in entries:
            table.add_row(t(describe_entry(entry)), t(entry))
        console.print(table)


def _collect_cert_entries(binding_key: Optional[str], values: list[str], full: list[str]) -> list[str]:
    """Build entries from --full / --type + --value, prompting (prefix pre-filled) for what's missing."""
    entries: list[str] = [normalise_full_entry(f) for f in full]
    if binding_key is None and (entries or values):
        if values and not entries:
            raise CertIdError("--value needs --type (pn, rfc822, ski, sha1, issuer-serial, issuer-subject, subject).")
        return entries
    if binding_key is None:
        if not is_interactive():
            raise CertIdError("Give --type and --value (or --full) when not running in a terminal.")
        table = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Binding types")
        for column in ("Type", "Stored as", "Notes"):
            table.add_column(column, overflow="fold")
        for b in BINDINGS.values():
            table.add_row(t(b.key), t(b.template), t(b.note or "-"))
        console.print(table)
        binding_key = str(typer.prompt("Type", default="pn"))
    binding = get_binding(binding_key)
    names = binding.fields
    if values:
        if len(values) % len(names):
            raise CertIdError(f"'{binding.key}' needs {len(names)} value(s) each: " + ", ".join(n for n, _ in names))
        for i in range(0, len(values), len(names)):
            entries.append(build_cert_id(binding.key, {n: v for (n, _), v in zip(names, values[i:i + len(names)])}))
    elif not entries:
        if not is_interactive():
            raise CertIdError("Pass --value (or --full) when not running in a terminal.")
        pasted = {n: str(typer.prompt(f"{binding.prefix}  <- paste the {label}")) for n, label in names}
        entries.append(build_cert_id(binding.key, pasted))
    return entries


@id_app.command("cert-add")
def id_cert_add(
    ident: Annotated[str, typer.Argument(help="The user.")],
    binding: Annotated[Optional[str], typer.Option("--type", "-t", help="pn | rfc822 | ski | sha1 | issuer-serial | issuer-subject | subject")] = None,
    value: Annotated[Optional[list[str]], typer.Option("--value", "-v", help="The pasted data (prefix is added for you). Repeat for two-part types (issuer, then serial/subject).")] = None,
    full: Annotated[Optional[list[str]], typer.Option("--full", help="A complete entry, e.g. X509:<PN>user@contoso.com")] = None,
    by: ByOpt = "auto",
    yes: YesOpt = False,
    dry_run: DryRunOpt = False,
    elevate: ElevateOpt = None,
    reason: ReasonOpt = None,
    minutes: MinutesOpt = 60,
    mode: ModeOpt = None,
) -> None:
    """Add a certificate user ID. The X509:<type> prefix is pre-filled; you only paste the data."""
    try:
        new_entries = _collect_cert_entries(binding, value or [], full or [])
    except CertIdError as exc:
        fail(str(exc))
    with open_session(mode) as sess, graph_errors():
        user = resolve_user_or_pick(sess.graph, ident, by)
        existing = get_certificate_user_ids(sess.graph, user.id)
        merged, added, present = merge_cert_ids(existing, new_entries)
        if present:
            console.print(t("Already present: " + ", ".join(present)))
        if not added:
            console.print("[yellow]Nothing to add.[/]")
            return
        try:
            plan = plan_set_certificate_user_ids(user, merged, existing)
        except PlanError as exc:
            fail(str(exc))
        _finish(run_action(sess, plan, yes=yes, dry_run=dry_run, elevate=elevate, reason=reason, minutes=minutes))


@id_app.command("cert-remove")
def id_cert_remove(
    ident: Annotated[str, typer.Argument(help="The user.")],
    value: Annotated[Optional[list[str]], typer.Option("--value", "-v", help="Full entry to remove (repeatable). Omit to choose from a list.")] = None,
    by: ByOpt = "auto",
    yes: YesOpt = False,
    dry_run: DryRunOpt = False,
    elevate: ElevateOpt = None,
    reason: ReasonOpt = None,
    minutes: MinutesOpt = 60,
    mode: ModeOpt = None,
) -> None:
    """Remove certificate user IDs."""
    with open_session(mode) as sess, graph_errors():
        user = resolve_user_or_pick(sess.graph, ident, by)
        existing = get_certificate_user_ids(sess.graph, user.id)
        if not existing:
            console.print("[yellow]This user has no certificate user IDs.[/]")
            return
        removals = list(value or [])
        if not removals:
            if not is_interactive():
                fail("Pass --value for each entry to remove when not running in a terminal.")
            for index, entry in enumerate(existing, 1):
                console.print(t(f"  {index}. [{describe_entry(entry)}] {entry}"))
            raw = str(typer.prompt("Remove which? (numbers, comma separated)"))
            try:
                removals = [existing[int(x) - 1] for x in raw.replace(" ", "").split(",") if x]
            except (ValueError, IndexError):
                fail("Enter valid numbers from the list.")
        merged, removed, missing = remove_cert_ids(existing, removals)
        if missing:
            console.print(t("Not found (ignored): " + ", ".join(missing)))
        if not removed:
            console.print("[yellow]Nothing to remove.[/]")
            return
        try:
            plan = plan_set_certificate_user_ids(user, merged, existing)
        except PlanError as exc:
            fail(str(exc))
        _finish(run_action(sess, plan, yes=yes, dry_run=dry_run, elevate=elevate, reason=reason, minutes=minutes))


def print_action_log(entries: list[dict[str, Any]]) -> None:
    if not entries:
        console.print("[yellow]No changes recorded yet.[/]")
        return
    table = Table(title="Recent changes made with this tool", box=box.SIMPLE_HEAD, header_style="bold")
    for column in ("When (UTC)", "Who", "Change", "Target", "Result"):
        table.add_column(column, overflow="fold")
    for e in entries:
        target = e.get("target") or {}
        status = str(e.get("status", ""))
        style = "green" if status == "ok" else "yellow" if status in ("dry_run", "skipped") else "bold red"
        table.add_row(t(str(e.get("ts", ""))[:19].replace("T", " ")), t(e.get("actor", "")), t(e.get("title", "")),
                      t(target.get("name", "")), Text(status, style=style))
    console.print(table)


@id_app.command("log")
def id_log(limit: Annotated[int, typer.Option(help="How many recent entries.")] = 20) -> None:
    """Show the local record of changes made with this tool (never contains passwords)."""
    print_action_log(audit_log.read_recent(limit))


# =========================================================================== #
# auditor group ...
# =========================================================================== #

@group_app.command("show")
def group_show(group: Annotated[str, typer.Argument(help="Group name, mail or object id.")], mode: ModeOpt = None) -> None:
    """Show a group: kind, owners and members."""
    with open_session(mode) as sess, graph_errors():
        g = resolve_group_or_pick(sess.graph, group)
        print_group_detail(g, group_detail(sess.graph, g))


def _group_members_command(
    group_ident: str, user_idents: list[str], plan_builder, by: str, yes: bool, dry_run: bool,
    elevate: Optional[bool], reason: Optional[str], minutes: int, mode: Optional[str], with_base: bool,
) -> None:
    with open_session(mode) as sess, graph_errors():
        g = resolve_group_or_pick(sess.graph, group_ident)
        users = [resolve_user_or_pick(sess.graph, u, by) for u in user_idents]
        try:
            plan = plan_builder(g, users, sess.graph.base_url) if with_base else plan_builder(g, users)
        except PlanError as exc:
            fail(str(exc))
        _finish(run_action(sess, plan, yes=yes, dry_run=dry_run, elevate=elevate, reason=reason, minutes=minutes))


_USERS_ARG = Annotated[list[str], typer.Argument(help="One or more users (UPN, email, name or object id).")]
_GROUP_ARG = Annotated[str, typer.Argument(help="Group name, mail or object id.")]


@group_app.command("add-member")
def group_add_member(group: _GROUP_ARG, users: _USERS_ARG, by: ByOpt = "auto", yes: YesOpt = False,
                     dry_run: DryRunOpt = False, elevate: ElevateOpt = None, reason: ReasonOpt = None,
                     minutes: MinutesOpt = 60, mode: ModeOpt = None) -> None:
    """Add users to a group."""
    _group_members_command(group, users, plan_add_group_members, by, yes, dry_run, elevate, reason, minutes, mode, True)


@group_app.command("remove-member")
def group_remove_member(group: _GROUP_ARG, users: _USERS_ARG, by: ByOpt = "auto", yes: YesOpt = False,
                        dry_run: DryRunOpt = False, elevate: ElevateOpt = None, reason: ReasonOpt = None,
                        minutes: MinutesOpt = 60, mode: ModeOpt = None) -> None:
    """Remove users from a group."""
    _group_members_command(group, users, plan_remove_group_members, by, yes, dry_run, elevate, reason, minutes, mode, False)


@group_app.command("add-owner")
def group_add_owner(group: _GROUP_ARG, users: _USERS_ARG, by: ByOpt = "auto", yes: YesOpt = False,
                    dry_run: DryRunOpt = False, elevate: ElevateOpt = None, reason: ReasonOpt = None,
                    minutes: MinutesOpt = 60, mode: ModeOpt = None) -> None:
    """Add owners to a group (the usual fix for an unowned group)."""
    _group_members_command(group, users, plan_add_group_owners, by, yes, dry_run, elevate, reason, minutes, mode, True)


@group_app.command("remove-owner")
def group_remove_owner(group: _GROUP_ARG, users: _USERS_ARG, by: ByOpt = "auto", yes: YesOpt = False,
                       dry_run: DryRunOpt = False, elevate: ElevateOpt = None, reason: ReasonOpt = None,
                       minutes: MinutesOpt = 60, mode: ModeOpt = None) -> None:
    """Remove owners from a group."""
    _group_members_command(group, users, plan_remove_group_owners, by, yes, dry_run, elevate, reason, minutes, mode, False)


def print_stale_groups(run: Any, only: Optional[str] = None, kind: Optional[str] = None) -> list[dict]:
    """Table of flagged groups from an audit run (one row per group). Returns the rows shown."""
    rows = groups_rows(run)
    if only:
        rows = [r for r in rows if only.lower() in str(r["issues"]).split(", ")]
    if kind:
        rows = [r for r in rows if kind.lower() in str(r["kind"]).lower().replace(" ", "_").replace("-", "_")
                or kind.lower() in str(r["kind"]).lower()]
    if not rows:
        console.print("[yellow]No flagged groups in this run. (Run `auditor run --checks groups` to scan.)[/]")
        return []
    table = Table(title=f"Unowned / empty / stale groups ({len(rows)})", box=box.SIMPLE_HEAD, header_style="bold")
    for column in ("Severity", "Group", "Kind", "Issues", "Owners", "Users", "Age (d)", "In use by"):
        table.add_column(column, overflow="fold", no_wrap=column in ("Severity",))
    for r in rows:
        table.add_row(sev(r["worst_severity"]), t(r["group"]), t(r["kind"]), t(r["issues"]),
                      t("?" if r["owners"] is None else r["owners"]), t("?" if r["user_members"] is None else r["user_members"]),
                      t("-" if r["age_days"] is None else r["age_days"]), t(r["in_use_by"] or "-"))
    console.print(table)
    return rows


@group_app.command("stale")
def group_stale(
    run_ref: RunRef = None,
    only: Annotated[Optional[str], typer.Option("--only", help="unowned | empty | stale")] = None,
    kind: Annotated[Optional[str], typer.Option("--kind", help="security | microsoft365 | ...")] = None,
    export: Annotated[Optional[Path], typer.Option("--export", help="Write the flagged groups to this CSV file.")] = None,
) -> None:
    """List unowned, empty and truly stale groups from a saved audit (mail-enabled security groups excluded)."""
    if only and only.lower() not in ("unowned", "empty", "stale"):
        fail("--only must be unowned, empty or stale")
    try:
        run = load_run(resolve_run(run_ref))
    except (FileNotFoundError, ValueError, OSError) as exc:
        fail(str(exc))
    rows = print_stale_groups(run, only, kind)
    if export and rows:
        console.print(f"[green]Wrote[/] {escape(str(write_groups_csv(run, export)))}")


# =========================================================================== #
# auditor pim ...
# =========================================================================== #

def _require_user(sess: Session) -> None:
    if not sess.user_mode:
        fail("PIM activates roles for a signed-in person. Use --mode device or --mode browser.")


@pim_app.command("list")
def pim_list(mode: ModeOpt = None) -> None:
    """Show the roles you are eligible for and the ones active right now."""
    with open_session(mode) as sess, graph_errors():
        _require_user(sess)
        pim = PimService(sess.graph)
        print_pim(pim.eligible(), pim.active())


@pim_app.command("activate")
def pim_activate(
    role: Annotated[str, typer.Argument(help="Role name (or part of it), e.g. 'User Administrator'.")],
    reason: Annotated[Optional[str], typer.Option("--reason", "-r", help="Justification (ticket or task).")] = None,
    minutes: MinutesOpt = 60,
    mode: ModeOpt = None,
) -> None:
    """Activate an eligible role."""
    with open_session(mode) as sess, graph_errors():
        _require_user(sess)
        pim = PimService(sess.graph)
        try:
            chosen = PimService.find(pim.eligible(), role)
        except PimError as exc:
            fail(f"{exc} {exc.hint}".strip())
        if any(r.role_id == chosen.role_id for r in pim.active()):
            console.print(t(f"{chosen.name} is already active."))
            return
        why = (reason or "").strip() or (str(typer.prompt("Justification (ticket or task)")).strip() if is_interactive() else "")
        if not why:
            fail("A justification is required: pass --reason.")
        if not activate_role(sess, pim, chosen, why, minutes):
            raise typer.Exit(1)


@pim_app.command("deactivate")
def pim_deactivate(
    role: Annotated[str, typer.Argument(help="Role name (or part of it).")],
    mode: ModeOpt = None,
) -> None:
    """Give up an activated role early."""
    with open_session(mode) as sess, graph_errors():
        _require_user(sess)
        pim = PimService(sess.graph)
        try:
            chosen = PimService.find([r for r in pim.active() if r.activated], role)
            result = pim.deactivate(chosen)
        except PimError as exc:
            fail(f"{exc} {exc.hint}".strip())
        console.print(t(f"{chosen.name}: {result.status}"))


# =========================================================================== #
# Interactive menu
# =========================================================================== #

CANCEL = object()   # Ctrl-C / escape
BACK = "__back__"


def _questionary():
    try:
        import questionary
    except ImportError:
        fail("The menu needs the 'questionary' package (pip install questionary).")
    return questionary


def ask(q: Any, message: str, options: list[tuple[str, Any]]) -> Any:
    """Arrow-key choice. Options map label -> value; returns the value, or CANCEL.

    Choices carry string indices, never the values themselves: questionary replaces a ``None``
    value with the title text, which once caused a real bug here."""
    choices = [q.Choice(title=label, value=str(i)) for i, (label, _) in enumerate(options)]
    answer = q.select(message, choices=choices).ask()
    return CANCEL if answer is None else options[int(answer)][1]


def _say_error(exc: Exception) -> None:
    console.print(Text(str(exc), style="bold red"))


def _pick_user(q: Any, sess: Session, prompt: str = "Search for a user (UPN, email, name, employee id, object id)") -> Optional[UserSummary]:
    text = q.text(prompt + ":").ask()
    if not text or not text.strip():
        return None
    try:
        users = find_users(sess.graph, text, limit=30)
    except (ValueError, GraphError) as exc:
        _say_error(exc)
        return None
    if not users:
        console.print("[yellow]No users found.[/]")
        return None
    if len(users) == 1:
        return users[0]
    picked = ask(q, f"{len(users)} matches. Which one?",
                 [(f"{u.label}  |  {u.display_name or ''}  |  {u.job_title or u.department or ''}", u) for u in users]
                 + [("<- Back", BACK)])
    return None if picked in (CANCEL, BACK) else picked


def _pick_group(q: Any, sess: Session, prompt: str = "Search for a group (name, mail or object id)") -> Optional[GroupSummary]:
    text = q.text(prompt + ":").ask()
    if not text or not text.strip():
        return None
    try:
        groups = find_groups(sess.graph, text, limit=30)
    except (ValueError, GraphError) as exc:
        _say_error(exc)
        return None
    if not groups:
        console.print("[yellow]No groups found.[/]")
        return None
    if len(groups) == 1:
        return groups[0]
    picked = ask(q, f"{len(groups)} matches. Which one?",
                 [(f"{g.label}  |  {g.kind_label}", g) for g in groups] + [("<- Back", BACK)])
    return None if picked in (CANCEL, BACK) else picked


def _apply(sess: Session, plan) -> None:
    """Preview, confirm, run (with PIM offer) - all prompts interactive."""
    run_action(sess, plan)
    console.input("[dim]Press Enter to continue[/]")


# ---- identity ---------------------------------------------------------------

def _menu_edit(q: Any, sess: Session, user: UserSummary) -> None:
    profile = load_user_profile(sess.graph, user.id)
    current = profile_current_values(profile)
    pending: dict[str, Optional[str]] = {}
    while True:
        options: list[tuple[str, Any]] = []
        for field in sorted(EDITABLE_USER_FIELDS):
            now = current.get(field) or "(empty)"
            new = f"  ->  {pending[field] or '(clear)'}" if field in pending else ""
            options.append((f"{field}: {now}{new}", field))
        options += [(f"Apply {len(pending)} change(s)", "apply"), ("<- Cancel", BACK)]
        picked = ask(q, "Which attribute?", options)
        if picked in (CANCEL, BACK):
            return
        if picked == "apply":
            break
        value = q.text(f"New value for {picked} (empty clears it):", default=str(pending.get(picked) or current.get(picked) or "")).ask()
        if value is not None:
            pending[picked] = value.strip() or None
    if not pending:
        return
    try:
        changes = parse_assignments([f"{k}={v or ''}" for k, v in pending.items()])
        plan = plan_update_user(user, changes, current)
    except PlanError as exc:
        _say_error(exc)
        return
    _apply(sess, plan)


def _menu_password(q: Any, sess: Session, user: UserSummary) -> None:
    how = ask(q, "How should the new password be set?", [
        ("Let Entra generate it (recommended; shown once)", "entra"),
        ("Generate it here (shown once)", "local"),
        ("Type one myself (hidden)", "typed"), ("<- Back", BACK)])
    if how in (CANCEL, BACK):
        return
    password, reveal = None, {}
    if how == "typed":
        first = q.password("New password:").ask()
        if not first or first != q.password("Repeat it:").ask():
            console.print("[red]Passwords didn't match.[/]")
            return
        password = first
    elif how == "local" or user.on_prem_synced:
        password = generate_password()
        reveal = {"password": password}
    profile = load_user_profile(sess.graph, user.id)
    try:
        plan = plan_reset_password(user, password, target_is_admin=holds_admin_roles(profile))
    except PlanError as exc:
        _say_error(exc)
        return
    run_action(sess, plan, extra_secrets=reveal)
    console.input("[dim]Press Enter to continue (the password is no longer shown after this)[/]")


def _menu_add_to_group(q: Any, sess: Session, user: UserSummary) -> None:
    group = _pick_group(q, sess, "Add to which group? Search (name, mail or object id)")
    if group:
        try:
            _apply(sess, plan_add_group_members(group, [user], sess.graph.base_url))
        except PlanError as exc:
            _say_error(exc)


def _menu_remove_from_group(q: Any, sess: Session, user: UserSummary) -> None:
    profile = load_user_profile(sess.graph, user.id)
    groups = [g for g in (profile.groups or []) if g.kind == "group"]
    if not groups:
        console.print("[yellow]This user isn't a member of any group.[/]")
        return
    picked = ask(q, "Remove from which group?", [(g.label, g) for g in groups] + [("<- Back", BACK)])
    if picked in (CANCEL, BACK):
        return
    try:
        _apply(sess, plan_remove_group_members(get_group(sess.graph, picked.id), [user]))
    except (PlanError, IdentityNotFound) as exc:
        _say_error(exc)


def _menu_certs(q: Any, sess: Session, user: UserSummary) -> None:
    while True:
        existing = get_certificate_user_ids(sess.graph, user.id)
        action = ask(q, f"Certificate user IDs ({len(existing)} on this account)", [
            ("List", "list"), ("Add (prefix pre-filled, paste the data)", "add"),
            ("Remove", "remove"), ("<- Back", BACK)])
        if action in (CANCEL, BACK):
            return
        if action == "list":
            for entry in existing or ["(none)"]:
                console.print(t(f"  [{describe_entry(entry) if existing else '-'}] {entry}"))
        elif action == "add":
            binding = ask(q, "Which kind of binding?", [(f"{b.label}   ({b.prefix}...)", b) for b in BINDINGS.values()]
                          + [("Paste a complete X509:<...> entry", "full"), ("<- Back", BACK)])
            if binding in (CANCEL, BACK):
                continue
            try:
                if binding == "full":
                    pasted = q.text("Paste the full entry:").ask()
                    if not pasted:
                        continue
                    new_entry = normalise_full_entry(pasted)
                else:
                    console.print(t(f"Stored as: {binding.template}" + (f"   ({binding.note})" if binding.note else "")))
                    values = {}
                    for name, label in binding.fields:
                        got = q.text(f"{binding.prefix}  <- paste the {label}:").ask()
                        if got is None:
                            raise CertIdError("Cancelled.")
                        values[name] = got
                    new_entry = build_cert_id(binding.key, values)
                merged, added, present = merge_cert_ids(existing, [new_entry])
                if not added:
                    console.print("[yellow]That entry is already on the account.[/]")
                    continue
                _apply(sess, plan_set_certificate_user_ids(user, merged, existing))
            except (CertIdError, PlanError) as exc:
                _say_error(exc)
        elif action == "remove":
            if not existing:
                console.print("[yellow]Nothing to remove.[/]")
                continue
            chosen = q.checkbox("Select entries to remove",
                                choices=[q.Choice(title=f"[{describe_entry(e)}] {e}", value=str(i)) for i, e in enumerate(existing)]).ask()
            if chosen:
                merged, removed, _ = remove_cert_ids(existing, [existing[int(i)] for i in chosen])
                try:
                    _apply(sess, plan_set_certificate_user_ids(user, merged, existing))
                except PlanError as exc:
                    _say_error(exc)


def identity_menu(q: Any, sess: Session, user: UserSummary) -> None:
    while True:
        console.rule(t(user.label))
        action = ask(q, f"{user.display_name or user.label}: what now?", [
            ("View full profile", "profile"), ("Edit attributes", "edit"), ("Reset password", "password"),
            ("Add to a group", "addgroup"), ("Remove from a group", "rmgroup"),
            ("Certificate user IDs", "certs"), ("Revoke sign-in sessions", "revoke"),
            (("Disable" if user.account_enabled is not False else "Enable") + " account", "toggle"),
            ("<- Back", BACK)])
        if action in (CANCEL, BACK):
            return
        try:
            if action == "profile":
                print_profile(load_user_profile(sess.graph, user.id))
                console.input("[dim]Press Enter to continue[/]")
            elif action == "edit":
                _menu_edit(q, sess, user)
            elif action == "password":
                _menu_password(q, sess, user)
            elif action == "addgroup":
                _menu_add_to_group(q, sess, user)
            elif action == "rmgroup":
                _menu_remove_from_group(q, sess, user)
            elif action == "certs":
                _menu_certs(q, sess, user)
            elif action == "revoke":
                _apply(sess, plan_revoke_sessions(user))
            elif action == "toggle":
                _apply(sess, plan_set_enabled(user, user.account_enabled is False))
            user = get_user(sess.graph, user.id)  # state may have changed (e.g. disabled)
        except (PlanError, IdentityNotFound) as exc:
            _say_error(exc)
        except GraphPermissionError as exc:
            _say_error(exc)
        except GraphError as exc:
            _say_error(exc)
        except typer.Exit:
            continue


# ---- groups -----------------------------------------------------------------

def _menu_group_people(q: Any, sess: Session, group: GroupSummary, edge: str, add: bool) -> None:
    noun = "member" if edge == "members" else "owner"
    if add:
        user = _pick_user(q, sess, f"Add which user as {noun}? Search")
        if user:
            builder = plan_add_group_members if edge == "members" else plan_add_group_owners
            _apply(sess, builder(group, [user], sess.graph.base_url))
        return
    people, _ = list_group_people(sess.graph, group.id, edge, 200)
    people = [p for p in people if p.kind == "user"]
    if not people:
        console.print(f"[yellow]No user {noun}s to remove.[/]")
        return
    chosen = q.checkbox(f"Select {noun}s to remove",
                        choices=[q.Choice(title=p.label, value=str(i)) for i, p in enumerate(people)]).ask()
    if chosen:
        users = [get_user(sess.graph, people[int(i)].id) for i in chosen]
        builder = plan_remove_group_members if edge == "members" else plan_remove_group_owners
        _apply(sess, builder(group, users))


def group_menu(q: Any, sess: Session, group: GroupSummary) -> None:
    while True:
        console.rule(t(group.label))
        action = ask(q, f"{group.label} ({group.kind_label}): what now?", [
            ("Show owners and members", "show"), ("Add a member", "addm"), ("Remove members", "rmm"),
            ("Add an owner", "addo"), ("Remove owners", "rmo"), ("<- Back", BACK)])
        if action in (CANCEL, BACK):
            return
        try:
            if action == "show":
                print_group_detail(group, group_detail(sess.graph, group))
                console.input("[dim]Press Enter to continue[/]")
            elif action == "addm":
                _menu_group_people(q, sess, group, "members", True)
            elif action == "rmm":
                _menu_group_people(q, sess, group, "members", False)
            elif action == "addo":
                _menu_group_people(q, sess, group, "owners", True)
            elif action == "rmo":
                _menu_group_people(q, sess, group, "owners", False)
        except (PlanError, IdentityNotFound, GraphError) as exc:
            _say_error(exc)
        except typer.Exit:
            continue


# ---- PIM --------------------------------------------------------------------

def pim_menu(q: Any, sess: Session) -> None:
    if not sess.user_mode:
        console.print("[yellow]PIM needs a user sign-in (--mode device or browser).[/]")
        return
    pim = PimService(sess.graph)
    while True:
        try:
            eligible, active = pim.eligible(), pim.active()
        except GraphError as exc:
            _say_error(exc)
            return
        print_pim(eligible, active)
        active_ids = {r.role_id for r in active}
        action = ask(q, "PIM", [("Activate a role", "on"), ("Deactivate a role", "off"), ("<- Back", BACK)])
        if action in (CANCEL, BACK):
            return
        if action == "on":
            choices = [r for r in eligible if r.role_id not in active_ids]
            if not choices:
                console.print("[yellow]Nothing left to activate.[/]")
                continue
            role = ask(q, "Activate which role?", [(r.label, r) for r in choices] + [("<- Back", BACK)])
            if role in (CANCEL, BACK):
                continue
            minutes = ask(q, "For how long?", [("30 minutes", 30), ("1 hour", 60), ("2 hours", 120),
                                               ("4 hours", 240), ("8 hours", 480)])
            reason = q.text("Justification (ticket or task):").ask()
            if minutes is not CANCEL and reason and reason.strip():
                activate_role(sess, pim, role, reason.strip(), minutes)
        else:
            mine = [r for r in active if r.activated]
            if not mine:
                console.print("[yellow]You have no PIM-activated roles to give up.[/]")
                continue
            role = ask(q, "Deactivate which role?", [(r.label, r) for r in mine] + [("<- Back", BACK)])
            if role not in (CANCEL, BACK):
                try:
                    console.print(t(f"{role.name}: {pim.deactivate(role).status}"))
                except PimError as exc:
                    _say_error(exc)


# ---- stale groups from the latest audit -------------------------------------

def stale_groups_menu(q: Any, sess: Session) -> None:
    try:
        run = load_run(resolve_run(None))
    except (FileNotFoundError, ValueError, OSError) as exc:
        console.print(t(str(exc) + " Run `auditor run --checks groups` first."))
        return
    rows = print_stale_groups(run)
    if not rows:
        return
    while True:
        picked = ask(q, "Open a group to fix it (add an owner, change members)?", [
            (f"[{r['worst_severity']:<8}] {r['group']}  ({r['issues']})", r) for r in rows[:200]] + [("<- Back", BACK)])
        if picked in (CANCEL, BACK):
            return
        try:
            group_menu(q, sess, get_group(sess.graph, picked["group_id"]))
        except IdentityNotFound as exc:
            _say_error(exc)


# ---- top level --------------------------------------------------------------

def _find_identity(q: Any, sess: Session) -> None:
    text = q.text("Search (UPN, email, name, employee id, alias or object id):").ask()
    if not text or not text.strip():
        return
    try:
        users = find_users(sess.graph, text, limit=30)
        if users:
            picked = ask(q, f"{len(users)} user(s). Open one:", [
                (f"{u.label}  |  {u.display_name or ''}  |  {'disabled' if u.account_enabled is False else 'enabled'}", u)
                for u in users] + [("<- Back", BACK)]) if len(users) > 1 else users[0]
            if picked not in (CANCEL, BACK):
                identity_menu(q, sess, picked)
            return
        groups = find_groups(sess.graph, text, limit=30)
        if groups:
            console.print("[yellow]No users matched, but these groups did.[/]")
            picked = ask(q, "Open a group:", [(f"{g.label}  |  {g.kind_label}", g) for g in groups] + [("<- Back", BACK)])
            if picked not in (CANCEL, BACK):
                group_menu(q, sess, picked)
            return
        apps = find_apps(sess.graph, text, limit=30)
        if apps:
            print_apps(apps)
            return
        console.print("[yellow]Nothing matched.[/]")
    except (ValueError, GraphError) as exc:
        _say_error(exc)


def toolkit_menu_loop(sess: Session) -> None:
    q = _questionary()
    while True:
        console.rule("[bold cyan]Identity toolkit")
        console.print(f"Signed in as {escape(sess.identity)}")
        choice = ask(q, "What would you like to do?", [
            ("Find an identity (user, group or app)", "find"),
            ("Find a group", "group"),
            ("My roles: activate / deactivate (PIM)", "pim"),
            ("Unowned / empty / stale groups (from the latest audit)", "stale"),
            ("Recent changes made with this tool", "log"),
            ("Back", BACK)])
        if choice in (CANCEL, BACK):
            return
        try:
            if choice == "find":
                _find_identity(q, sess)
            elif choice == "group":
                group = _pick_group(q, sess)
                if group:
                    group_menu(q, sess, group)
            elif choice == "pim":
                pim_menu(q, sess)
            elif choice == "stale":
                stale_groups_menu(q, sess)
            elif choice == "log":
                print_action_log(audit_log.read_recent(20))
        except typer.Exit:
            continue


def run_toolkit_menu(mode: Optional[str] = None) -> None:
    """Open a session and run the toolkit menu (also used by the main `auditor menu`)."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        fail("The interactive toolkit needs a terminal. Use `auditor id ...` / `auditor group ...` in scripts.")
    _questionary()
    with open_session(mode) as sess:
        toolkit_menu_loop(sess)


def toolkit_menu(mode: ModeOpt = None) -> None:
    """Interactive identity toolkit: find identities, edit them, manage groups, elevate with PIM."""
    run_toolkit_menu(mode)


def register(app: typer.Typer) -> None:
    app.add_typer(id_app, name="id")
    app.add_typer(group_app, name="group")
    app.add_typer(pim_app, name="pim")
    app.command("toolkit")(toolkit_menu)
