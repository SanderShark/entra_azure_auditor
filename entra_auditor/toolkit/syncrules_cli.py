"""`auditor sync ...`: understand and validate Entra Connect sync rules from an export. Offline: these
commands read files and never sign in or contact a tenant or the Connect server."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from ..cli_common import console, fail, t
from . import syncrules as S

sync_app = typer.Typer(help="Entra Connect sync rules (offline): describe, lint, explain, diff, impact.",
                       no_args_is_help=True, add_completion=False)

RulesArg = Annotated[Path, typer.Argument(help="The folder written by Get-ADSyncServerConfiguration -Path (or one rule file).")]
OuOpt = Annotated[Optional[list[str]], typer.Option("--excluded-ou", help="An extra distinguished name to treat as left out "
                                                    "(repeatable). Container/OU filtering is normally read from the "
                                                    "export's connector files.")]
TypeOpt = Annotated[str, typer.Option("--type", help="Object type to evaluate (user, group, contact, ...).")]
STYLE = {"error": "bold red", "warning": "yellow", "info": "dim"}


def _load(path: Path) -> S.RuleSet:
    try:
        return S.load_rules(path)
    except S.SyncRuleError as exc:
        fail(str(exc), 2)


def _print_issues(issues: list[S.Issue]) -> None:
    for issue in issues:
        line = t(f"{issue.level.upper():8} {issue.rule}: {issue.text}")
        line.stylize(STYLE.get(issue.level, ""))
        console.print(line)


@sync_app.command("describe")
def describe(rules: RulesArg,
             custom_only: Annotated[bool, typer.Option("--custom", help="Only rules that aren't Microsoft's built-in ones.")] = False,
             filters_only: Annotated[bool, typer.Option("--filters", help="Only rules that set cloudFiltered.")] = False) -> None:
    """Every rule in plain English, inbound first, by precedence."""
    loaded = _load(rules)
    shown = [r for r in loaded.ordered if (not custom_only or not r.standard) and (not filters_only or r.cloud_filter)]
    for rule in shown:
        console.print(t(rule.describe()))
        console.print()
    for containers in loaded.containers:
        console.print(t(f"Containers: {containers.text}"))
    if not loaded.containers:
        console.print(t("Containers: none found in this export (no connector files), so OU filtering isn't checked."))
    console.print(t(f"{len(shown)} of {len(loaded.rules)} rules shown ({sum(1 for r in loaded.rules if not r.standard)} custom, "
                    f"{sum(1 for r in loaded.rules if r.cloud_filter)} set cloudFiltered)."))


@sync_app.command("lint")
def lint(rules: RulesArg) -> None:
    """Problems inside one rule set. Exit code 1 when there is an error."""
    issues = S.lint(_load(rules))
    _print_issues(issues)
    errors = sum(1 for i in issues if i.level == "error")
    console.print(t(f"{errors} error(s), {sum(1 for i in issues if i.level == 'warning')} warning(s)."))
    raise typer.Exit(1 if errors else 0)


@sync_app.command("explain")
def explain(rules: RulesArg,
            attributes: Annotated[Optional[list[str]], typer.Option("--set", help="attribute=value for the object "
                                                                    "(repeatable), e.g. --set extensionAttribute14=no0365sync")] = None,
            population: Annotated[Optional[Path], typer.Option("--csv", help="Take the object from this CSV instead...")] = None,
            who: Annotated[Optional[str], typer.Option("--who", help="...the row whose userPrincipalName, sAMAccountName "
                                                       "or distinguishedName is this.")] = None,
            excluded_ou: OuOpt = None, object_type: TypeOpt = "user") -> None:
    """Why one object is, or isn't, synchronised to Entra ID."""
    loaded = _load(rules)
    obj: dict[str, str] = {}
    if population is not None:
        if not who:
            fail("--csv needs --who (which row).", 2)
        wanted = who.casefold()
        match = next((row for row in S.load_population(population)
                      if wanted in {str(row.get(k, "")).casefold() for k in ("userPrincipalName", "sAMAccountName", "distinguishedName")}), None)
        if match is None:
            fail(f"No row for '{who}' in {population}.", 2)
        obj.update(match)
    for item in attributes or []:
        if "=" not in item:
            fail(f"'{item}' is not in attribute=value form.", 2)
        key, _, value = item.partition("=")
        obj[key.strip()] = value
    if not obj:
        fail("Give the object's attributes with --set attribute=value, or --csv with --who.", 2)
    result = S.verdict(loaded, obj, object_type=object_type, excluded_ous=excluded_ou or [])
    headline = t(result.reason)
    headline.stylize("bold yellow" if result.filtered is None else "bold red" if result.filtered else "bold green")
    console.print(headline)
    if result.applying:
        console.print(t("Inbound rules that apply, strongest first:"))
        for rule in result.applying:
            console.print(t(f"  {rule.precedence}: {rule.name}" + (f"  [{rule.cloud_filter.text}]" if rule.cloud_filter else "")))
    for rule in result.uncertain:
        console.print(t(f"  ? {rule.precedence}: {rule.name}: scope couldn't be evaluated ({rule.scope_text})"))


@sync_app.command("diff")
def diff(old: Annotated[Path, typer.Argument(help="The export as it is now.")],
         new: Annotated[Path, typer.Argument(help="The export with your changes.")]) -> None:
    """What changed between two exports; changes that can alter who is synchronised come first."""
    changes = S.diff(_load(old), _load(new))
    if not changes:
        console.print(t("No differences in the rules."))
        return
    _print_issues(changes)
    console.print(t(f"{sum(1 for c in changes if c.level == 'error')} change(s) can alter who is synchronised; "
                    "run `auditor sync impact` with a population to see who."))


@sync_app.command("impact")
def impact(old: Annotated[Path, typer.Argument(help="The export as it is now.")],
           new: Annotated[Path, typer.Argument(help="The export with your changes.")],
           population: Annotated[Path, typer.Argument(help="CSV of objects to test (Get-ADUser -Properties * | Export-Csv).")],
           max_changes: Annotated[int, typer.Option("--max-changes", help="How many objects may start or stop synchronising.")] = 0,
           max_percent: Annotated[float, typer.Option("--max-percent", help="...or what percentage of the population.")] = 0.0,
           excluded_ou: OuOpt = None,
           new_excluded_ou: Annotated[Optional[list[str]], typer.Option("--new-excluded-ou", help="OU exclusions after the "
                                                                        "change, if they change too (repeatable).")] = None,
           object_type: TypeOpt = "user",
           show: Annotated[int, typer.Option("--show", help="How many names to list per group.")] = 20) -> None:
    """Validate a change: who would start or stop synchronising. Exit code 1 when it exceeds the limits."""
    try:
        people = S.load_population(population)
    except OSError as exc:
        fail(f"Cannot read {population}: {exc}", 2)
    if not people:
        fail(f"{population} has no rows.", 2)
    report = S.impact(_load(old), _load(new), people, object_type=object_type, excluded_ous=excluded_ou or [],
                      new_excluded_ous=new_excluded_ou)
    console.print(t(f"{report.total:,} objects tested: {len(report.stop):,} would STOP synchronising, "
                    f"{len(report.start):,} would START, {len(report.unknown):,} can't be judged, "
                    f"{report.unchanged:,} unchanged ({report.share:.1%} change)."))
    for title, names in (("Would stop synchronising (removed from Entra ID)", report.stop),
                         ("Would start synchronising", report.start), ("Can't be judged", report.unknown)):
        if names:
            console.print(t(f"{title}:"))
            for name in names[:show]:
                console.print(t(f"  {name}"))
            if len(names) > show:
                console.print(t(f"  ... and {len(names) - show:,} more"))
    ok = report.acceptable(max_changes, max_percent / 100)
    verdict_line = t("PASS: within the limits." if ok else "FAIL: more change than allowed"
                     + (" (objects that can't be judged always fail)." if report.unknown else "."))
    verdict_line.stylize("bold green" if ok else "bold red")
    console.print(verdict_line)
    raise typer.Exit(0 if ok else 1)
