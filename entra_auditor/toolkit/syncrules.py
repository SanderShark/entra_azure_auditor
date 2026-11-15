"""Entra Connect Sync rules, offline: read an export, explain it, and check a change before it is applied.

Entra Connect's rules live on the Connect server, not in Microsoft Graph, so this module works on FILES:

    Import-Module ADSync
    Get-ADSyncServerConfiguration -Path C:\\Temp\\connect-export        # a folder of JSON files
    Get-ADSyncRule | ConvertTo-Json -Depth 10 > rules.json             # or just the rules

and never touches a tenant or the Connect server. What it does:

    describe   each rule in plain English (what it applies to, what it sets)
    lint       problems inside one rule set (duplicate precedence, a rule that filters everything, ...)
    explain    for one object's attributes: which rules apply and whether it is filtered from the cloud
    diff       what changed between two exports, with the risky changes first
    impact     run both rule sets over a population (a CSV from Get-ADUser) and count who would start
               or stop synchronising: the "this must not change things wildly" check

How Connect decides (what is modelled here):
  * A rule applies to an object when its scope filter matches. The scope filter is a list of groups; an
    object matches when ANY group matches, and a group matches when ALL its conditions do. A rule with no
    scope filter applies to every object of its type.
  * An object is kept out of Entra ID when the metaverse attribute ``cloudFiltered`` ends up True. Among the
    inbound rules that apply and set it, the one with the LOWEST precedence number wins.
  * "Unknown is not no": an operator this module doesn't know, or a ``cloudFiltered`` value computed by an
    expression, gives "unknown", never a guess.

NOT modelled: organisational-unit filtering (it is part of the connector's configuration, not a rule: pass
``excluded_ous`` to account for it), expressions (IIF(...) etc. are shown, not evaluated), group-based
filtering, join rules, and outbound scoping other than cloudFiltered.

THE EXPORT FORMAT IS NOT CONFIRMED. The reader accepts the property names of the ADSync rule object
(Name, Identifier, Direction, Precedence, ScopeFilter -> ScopeConditionList -> Attribute /
ComparisonOperator / ComparisonValue, AttributeFlowMappings -> Destination / Source / Expression /
FlowType, Disabled, ImmutableTag ...) case-insensitively and in a few nestings, and reports rules it could
not understand instead of skipping them silently. Check it against a real export. See CLAUDE.md.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

CLOUD_FILTERED = "cloudfiltered"
CUSTOM_PRECEDENCE_LIMIT = 100       # Microsoft's convention: custom rules get a precedence below 100

# operator -> plain English. Value-less operators are in _NO_VALUE.
OPERATORS = {
    "EQUAL": "equals", "NOTEQUAL": "does not equal", "CONTAINS": "contains", "NOTCONTAINS": "does not contain",
    "STARTSWITH": "starts with", "NOTSTARTSWITH": "does not start with", "ENDSWITH": "ends with",
    "NOTENDSWITH": "does not end with", "ISNULL": "is empty", "ISNOTNULL": "has a value",
    "LESSTHAN": "is less than", "LESSTHAN_OR_EQUAL": "is at most", "GREATERTHAN": "is greater than",
    "GREATERTHAN_OR_EQUAL": "is at least", "ISIN": "is one of", "ISNOTIN": "is none of",
    "ISBITSET": "has bit set", "ISBITNOTSET": "does not have bit set",
}
_NO_VALUE = {"ISNULL", "ISNOTNULL"}


class SyncRuleError(ValueError):
    """The file isn't something this module can read; the message says what was expected."""


@dataclass(frozen=True)
class Condition:
    attribute: str
    operator: str
    value: str = ""

    @property
    def text(self) -> str:
        words = OPERATORS.get(self.operator.upper(), f"[{self.operator}]")
        return f"{self.attribute} {words}" + ("" if self.operator.upper() in _NO_VALUE else f" '{self.value}'")

    def matches(self, obj: Mapping[str, Any]) -> Optional[bool]:
        """True/False, or None when the operator isn't understood (never guessed)."""
        raw = _lookup(obj, self.attribute)
        values = [str(v) for v in raw] if isinstance(raw, (list, tuple, set)) else ([] if raw in (None, "") else [str(raw)])
        op, want = self.operator.upper(), self.value.casefold()
        folded = [v.casefold() for v in values]
        if op == "ISNULL":
            return not values
        if op == "ISNOTNULL":
            return bool(values)
        if op in ("EQUAL", "NOTEQUAL"):
            hit = want in folded
            return hit if op == "EQUAL" else not hit
        if op in ("CONTAINS", "NOTCONTAINS", "STARTSWITH", "NOTSTARTSWITH", "ENDSWITH", "NOTENDSWITH"):
            test = {"CONTAINS": lambda v: want in v, "STARTSWITH": lambda v: v.startswith(want),
                    "ENDSWITH": lambda v: v.endswith(want)}[op.removeprefix("NOT")]
            hit = any(test(v) for v in folded)
            return not hit if op.startswith("NOT") else hit
        if op in ("ISIN", "ISNOTIN"):
            options = {part.strip().casefold() for part in self.value.replace(";", ",").split(",") if part.strip()}
            hit = any(v in options for v in folded)
            return hit if op == "ISIN" else not hit
        if op in ("ISBITSET", "ISBITNOTSET", "LESSTHAN", "LESSTHAN_OR_EQUAL", "GREATERTHAN", "GREATERTHAN_OR_EQUAL"):
            try:
                number, have = int(self.value, 0), [int(v, 0) for v in values]
            except ValueError:
                return None
            if not have:
                return op == "ISBITNOTSET"
            test_number = {"ISBITSET": lambda h: h & number == number, "ISBITNOTSET": lambda h: h & number == 0,
                           "LESSTHAN": lambda h: h < number, "LESSTHAN_OR_EQUAL": lambda h: h <= number,
                           "GREATERTHAN": lambda h: h > number, "GREATERTHAN_OR_EQUAL": lambda h: h >= number}[op]
            return any(test_number(h) for h in have)
        return None


@dataclass(frozen=True)
class Flow:
    """One attribute the rule sets."""
    destination: str
    source: str = ""            # a source attribute, a constant, or an expression
    kind: str = ""              # Direct | Constant | Expression

    @property
    def text(self) -> str:
        return f"{self.destination} = {self.source}" + (f" ({self.kind.lower()})" if self.kind else "")

    @property
    def constant_bool(self) -> Optional[bool]:
        """True/False when the flow is a plain constant boolean; None for anything computed or copied."""
        if self.kind.lower() not in ("constant", ""):
            return None
        value = self.source.strip().strip('"').casefold()
        return True if value == "true" else False if value == "false" else None


@dataclass
class SyncRule:
    name: str
    identifier: str = ""
    direction: str = ""                 # Inbound | Outbound
    precedence: Optional[int] = None
    connector: str = ""
    source_type: str = ""
    target_type: str = ""
    link_type: str = ""
    disabled: bool = False
    immutable_tag: str = ""             # "Microsoft...." on the rules Connect ships
    scope: list[list[Condition]] = field(default_factory=list)      # groups (OR) of conditions (AND)
    flows: list[Flow] = field(default_factory=list)

    @property
    def key(self) -> str:
        return self.identifier or self.name

    @property
    def inbound(self) -> bool:
        return self.direction.lower().startswith("in")

    @property
    def standard(self) -> bool:
        return self.immutable_tag.lower().startswith("microsoft")

    @property
    def cloud_filter(self) -> Optional[Flow]:
        return next((f for f in self.flows if f.destination.casefold() == CLOUD_FILTERED), None)

    @property
    def scope_text(self) -> str:
        if not self.scope:
            return "every object"
        groups = [" and ".join(c.text for c in group) for group in self.scope]
        return groups[0] if len(groups) == 1 else " OR ".join(f"({g})" for g in groups)

    def in_scope(self, obj: Mapping[str, Any]) -> Optional[bool]:
        if not self.scope:
            return True
        unknown = False
        for group in self.scope:
            results = [c.matches(obj) for c in group]
            if all(r is True for r in results):
                return True
            if not any(r is False for r in results):
                unknown = True          # no condition failed, but one couldn't be evaluated
        return None if unknown else False

    def describe(self) -> str:
        state = " [DISABLED]" if self.disabled else ""
        kind = "built-in" if self.standard else "custom"
        what = f"{self.source_type or 'object'} -> {self.target_type or 'object'}"
        lines = [f"{self.name}{state}",
                 f"  {self.direction or '?'} rule, precedence {self.precedence if self.precedence is not None else '?'}, "
                 f"{kind}, {what}" + (f", connector {self.connector}" if self.connector else ""),
                 f"  Applies to: {self.scope_text}"]
        if self.cloud_filter is not None:
            lines.append(f"  FILTERS FROM THE CLOUD: {self.cloud_filter.text}")
        others = [f.text for f in self.flows if f.destination.casefold() != CLOUD_FILTERED]
        if others:
            shown = others[:6] + ([f"... and {len(others) - 6} more"] if len(others) > 6 else [])
            lines.append("  Sets: " + "; ".join(shown))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Reading an export
# --------------------------------------------------------------------------- #

def _lookup(obj: Mapping[str, Any], name: str) -> Any:
    if name in obj:
        return obj[name]
    wanted = name.casefold()
    return next((v for k, v in obj.items() if str(k).casefold() == wanted), None)


def _first(raw: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = _lookup(raw, name)
        if value not in (None, ""):
            return value
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, dict):         # PowerShell sometimes wraps collections: {"value": [...], "Count": n}
        inner = _first(value, "value", "Value")
        return _as_list(inner) if inner is not None else [value]
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _condition(raw: Mapping[str, Any]) -> Condition:
    return Condition(str(_first(raw, "Attribute", "attributeName") or "?"),
                     str(_first(raw, "ComparisonOperator", "Operator") or "?"),
                     str(_first(raw, "ComparisonValue", "Value") or ""))


def _scope(raw: Any) -> list[list[Condition]]:
    groups: list[list[Condition]] = []
    for item in _as_list(raw):
        if not isinstance(item, dict):
            continue
        conditions = _first(item, "ScopeConditionList", "ScopeConditions", "Conditions")
        if conditions is not None:
            groups.append([_condition(c) for c in _as_list(conditions) if isinstance(c, dict)])
        elif _first(item, "Attribute", "attributeName") is not None:      # a flat list of conditions: one group
            if not groups:
                groups.append([])
            groups[0].append(_condition(item))
    return [g for g in groups if g]


def _flow(raw: Mapping[str, Any]) -> Flow:
    source = _first(raw, "Expression", "Source", "Value")
    source = ", ".join(str(s) for s in source) if isinstance(source, (list, tuple)) else str(source if source is not None else "")
    return Flow(str(_first(raw, "Destination", "TargetAttribute") or "?"), source, str(_first(raw, "FlowType", "Type") or ""))


def looks_like_rule(raw: Any) -> bool:
    return isinstance(raw, dict) and _first(raw, "Name") is not None and (
        _lookup(raw, "Precedence") is not None or _lookup(raw, "Direction") is not None
        or _lookup(raw, "AttributeFlowMappings") is not None)


def parse_rule(raw: Mapping[str, Any]) -> SyncRule:
    precedence = _lookup(raw, "Precedence")
    try:
        precedence = int(precedence) if precedence is not None else None
    except (TypeError, ValueError):
        precedence = None
    disabled = _lookup(raw, "Disabled")
    return SyncRule(
        name=str(_first(raw, "Name")), identifier=str(_first(raw, "Identifier", "Id") or ""),
        direction=str(_first(raw, "Direction") or ""), precedence=precedence,
        connector=str(_first(raw, "ConnectorName", "Connector") or ""),
        source_type=str(_first(raw, "SourceObjectType") or ""), target_type=str(_first(raw, "TargetObjectType") or ""),
        link_type=str(_first(raw, "LinkType") or ""),
        disabled=disabled is True or str(disabled).casefold() == "true",
        immutable_tag=str(_first(raw, "ImmutableTag") or ""),
        scope=_scope(_first(raw, "ScopeFilter", "ScopingFilter")),
        flows=[_flow(f) for f in _as_list(_lookup(raw, "AttributeFlowMappings")) if isinstance(f, dict)])


@dataclass
class RuleSet:
    rules: list[SyncRule]
    source: str = ""
    unreadable: list[str] = field(default_factory=list)     # files/entries that weren't rules

    def by_key(self) -> dict[str, SyncRule]:
        return {r.key: r for r in self.rules}

    @property
    def ordered(self) -> list[SyncRule]:
        return sorted(self.rules, key=lambda r: (not r.inbound, r.precedence if r.precedence is not None else 10**9, r.name))


def _collect(data: Any, where: str, found: list[SyncRule], unreadable: list[str]) -> None:
    if looks_like_rule(data):
        found.append(parse_rule(data))
        return
    items = _as_list(data) if isinstance(data, (list, dict)) else []
    nested = [i for i in items if looks_like_rule(i)]
    if nested:
        found.extend(parse_rule(i) for i in nested)
    elif isinstance(data, dict):
        for key in ("SynchronizationRules", "Rules", "rules"):
            inner = _lookup(data, key)
            if inner is not None:
                _collect(inner, where, found, unreadable)
                return
        unreadable.append(where)
    else:
        unreadable.append(where)


def load_rules(path: str | Path) -> RuleSet:
    """Rules from one JSON file, or from every JSON file under a folder (a full Connect export)."""
    path = Path(path).expanduser()
    if not path.exists():
        raise SyncRuleError(f"{path} does not exist.")
    files = [path] if path.is_file() else sorted(path.rglob("*.json"))
    in_rule_folder = [f for f in files if "synchronizationrule" in str(f.parent).lower().replace(" ", "")]
    files = in_rule_folder or files        # a full export has connectors and settings too: prefer the rules folder
    if not files:
        raise SyncRuleError(f"No JSON files under {path}. Export with: Get-ADSyncServerConfiguration -Path <folder>")
    found: list[SyncRule] = []
    unreadable: list[str] = []
    for file in files:
        try:
            data = json.loads(file.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            unreadable.append(f"{file.name}: {exc}")
            continue
        _collect(data, file.name, found, unreadable)
    if not found:
        raise SyncRuleError(f"No synchronisation rules were recognised in {path}. Expected JSON objects with Name, "
                            "Direction, Precedence, ScopeFilter and AttributeFlowMappings.")
    return RuleSet(found, str(path), unreadable)


def load_population(path: str | Path) -> list[dict[str, Any]]:
    """Objects to test rules against: a CSV whose headers are AD attribute names (from Get-ADUser | Export-Csv).
    Empty cells are missing attributes."""
    with Path(path).expanduser().open(newline="", encoding="utf-8-sig") as handle:
        return [{k: v for k, v in row.items() if k and v not in (None, "")} for row in csv.DictReader(handle)]


# --------------------------------------------------------------------------- #
# Explaining one object
# --------------------------------------------------------------------------- #

@dataclass
class Verdict:
    """Is the object kept out of Entra ID? ``filtered`` None = can't tell; ``reason`` always says why."""
    filtered: Optional[bool]
    reason: str
    decided_by: Optional[SyncRule] = None
    applying: list[SyncRule] = field(default_factory=list)       # inbound rules in scope, by precedence
    uncertain: list[SyncRule] = field(default_factory=list)      # rules whose scope couldn't be evaluated


def _dn_in(dn: str, ous: Iterable[str]) -> Optional[str]:
    folded = dn.casefold().replace(", ", ",")
    for ou in ous:
        suffix = ou.casefold().replace(", ", ",")
        if folded == suffix or folded.endswith("," + suffix):
            return ou
    return None


def verdict(rules: RuleSet | Sequence[SyncRule], obj: Mapping[str, Any], *, object_type: str = "user",
            excluded_ous: Sequence[str] = ()) -> Verdict:
    rule_list = rules.rules if isinstance(rules, RuleSet) else list(rules)
    dn = str(_lookup(obj, "distinguishedName") or _lookup(obj, "dn") or "")
    ou = _dn_in(dn, excluded_ous) if dn else None
    if ou:
        return Verdict(True, f"Not synchronised: it is in the excluded organisational unit {ou}.")
    candidates = sorted((r for r in rule_list if r.inbound and not r.disabled
                         and (not r.source_type or r.source_type.casefold() == object_type.casefold())),
                        key=lambda r: (r.precedence if r.precedence is not None else 10**9, r.name))
    applying, uncertain = [], []
    for rule in candidates:
        scoped = rule.in_scope(obj)
        (applying if scoped else uncertain if scoped is None else []).append(rule)
    deciders = [r for r in sorted(applying + uncertain, key=lambda r: (r.precedence if r.precedence is not None else 10**9))
                if r.cloud_filter is not None]
    for rule in deciders:
        flow = rule.cloud_filter
        assert flow is not None
        if rule in uncertain:
            return Verdict(None, f"Can't tell: '{rule.name}' (precedence {rule.precedence}) would decide, but its scope "
                                 f"uses something that couldn't be evaluated ({rule.scope_text}).", rule, applying, uncertain)
        value = flow.constant_bool
        if value is None:
            return Verdict(None, f"Can't tell: '{rule.name}' (precedence {rule.precedence}) sets cloudFiltered with an "
                                 f"expression that isn't evaluated here: {flow.source}", rule, applying, uncertain)
        if value:
            return Verdict(True, f"Not synchronised: '{rule.name}' (precedence {rule.precedence}) sets cloudFiltered "
                                 f"to True because {rule.scope_text}.", rule, applying, uncertain)
        return Verdict(False, f"Synchronised: '{rule.name}' (precedence {rule.precedence}) sets cloudFiltered to False "
                              "and outranks any rule that would filter it.", rule, applying, uncertain)
    return Verdict(False, "Synchronised as far as these rules say: no rule that applies sets cloudFiltered."
                   + ("" if excluded_ous else " (Organisational-unit filtering is separate and wasn't given.)"),
                   None, applying, uncertain)


# --------------------------------------------------------------------------- #
# Checking a rule set, and a change
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Issue:
    level: str          # error | warning | info
    rule: str
    text: str


_LEVELS = {"error": 0, "warning": 1, "info": 2}


def _sorted(issues: list[Issue]) -> list[Issue]:
    return sorted(issues, key=lambda i: (_LEVELS.get(i.level, 9), i.rule.casefold(), i.text))


def lint(rules: RuleSet) -> list[Issue]:
    issues: list[Issue] = [Issue("warning", name, "This file or entry wasn't recognised as a rule and was ignored.")
                           for name in rules.unreadable]
    by_precedence: dict[tuple[bool, int], list[SyncRule]] = {}
    for rule in rules.rules:
        if rule.precedence is None:
            issues.append(Issue("error", rule.name, "No precedence could be read."))
        else:
            by_precedence.setdefault((rule.inbound, rule.precedence), []).append(rule)
        for group in rule.scope:
            for condition in group:
                if condition.operator.upper() not in OPERATORS:
                    issues.append(Issue("warning", rule.name, f"Unknown comparison '{condition.operator}' on "
                                                              f"{condition.attribute}: it can't be evaluated here."))
        flow = rule.cloud_filter
        if flow is not None and not rule.disabled:
            if flow.constant_bool is True and not rule.scope:
                issues.append(Issue("error", rule.name, "Sets cloudFiltered to True with no scope filter: it would "
                                                        "remove EVERY object of its type from Entra ID."))
            elif flow.constant_bool is None:
                issues.append(Issue("info", rule.name, f"cloudFiltered is computed by an expression ({flow.source}); "
                                                       "explain and impact report 'can't tell' for the objects it decides."))
        if not rule.standard and rule.precedence is not None and rule.precedence >= CUSTOM_PRECEDENCE_LIMIT:
            issues.append(Issue("warning", rule.name, f"Custom rule with precedence {rule.precedence}: custom rules "
                                                      f"normally sit below {CUSTOM_PRECEDENCE_LIMIT} so they outrank the "
                                                      "built-in ones and survive upgrades."))
        if rule.disabled:
            issues.append(Issue("info", rule.name, "Disabled: it has no effect."
                                + (" (A disabled built-in rule usually means it was cloned and customised.)" if rule.standard else "")))
        if not rule.flows and not rule.disabled:
            issues.append(Issue("info", rule.name, "Sets no attributes."))
    for (inbound, precedence), same in by_precedence.items():
        if len(same) > 1:
            names = ", ".join(sorted(r.name for r in same))
            issues.append(Issue("error", same[0].name, f"Precedence {precedence} is used by several "
                                                       f"{'inbound' if inbound else 'outbound'} rules ({names}); it must be unique."))
    return _sorted(issues)


def _flow_map(rule: SyncRule) -> dict[str, str]:
    return {f.destination.casefold(): f.text for f in rule.flows}


def diff(old: RuleSet, new: RuleSet) -> list[Issue]:
    """What changed from ``old`` to ``new``. error = can change who is synchronised; warning = changes what is
    written or which rule wins; info = cosmetic."""
    changes: list[Issue] = []
    before, after = old.by_key(), new.by_key()
    for key, rule in after.items():
        if key not in before:
            level = "error" if rule.cloud_filter is not None and not rule.disabled else "warning"
            changes.append(Issue(level, rule.name, f"New rule (precedence {rule.precedence}). Applies to: {rule.scope_text}."
                                 + (f" {rule.cloud_filter.text}." if rule.cloud_filter else "")))
    for key, rule in before.items():
        if key not in after:
            level = "error" if rule.cloud_filter is not None and not rule.disabled else "warning"
            changes.append(Issue(level, rule.name, "Rule removed."
                                 + (" It filtered objects from the cloud: they would start synchronising." if level == "error" else "")))
            continue
        now = after[key]
        filters = rule.cloud_filter is not None or now.cloud_filter is not None
        if rule.name != now.name:
            changes.append(Issue("info", now.name, f"Renamed from '{rule.name}'."))
        if rule.disabled != now.disabled:
            changes.append(Issue("error" if filters else "warning", now.name,
                                 "Now disabled." if now.disabled else "Now enabled."))
        if rule.scope_text != now.scope_text:
            changes.append(Issue("error" if filters else "warning", now.name,
                                 f"Scope changed: was {rule.scope_text}; now {now.scope_text}."))
        if rule.precedence != now.precedence:
            changes.append(Issue("warning", now.name, f"Precedence changed from {rule.precedence} to {now.precedence}: "
                                                      "a different rule may now win where they overlap."))
        was, is_now = _flow_map(rule), _flow_map(now)
        for destination in sorted(set(was) | set(is_now)):
            if was.get(destination) != is_now.get(destination):
                level = "error" if destination == CLOUD_FILTERED else "warning"
                changes.append(Issue(level, now.name, f"Attribute flow changed: was {was.get(destination, '(not set)')}; "
                                                      f"now {is_now.get(destination, '(not set)')}."))
        for attribute, a, b in (("direction", rule.direction, now.direction), ("connector", rule.connector, now.connector),
                                ("source object type", rule.source_type, now.source_type),
                                ("link type", rule.link_type, now.link_type)):
            if a != b:
                changes.append(Issue("warning", now.name, f"{attribute.capitalize()} changed from '{a}' to '{b}'."))
    return _sorted(changes)


@dataclass
class Impact:
    total: int = 0
    start: list[str] = field(default_factory=list)       # would START synchronising
    stop: list[str] = field(default_factory=list)        # would STOP synchronising (be removed from Entra ID)
    unknown: list[str] = field(default_factory=list)     # can't tell before, after, or both
    unchanged: int = 0

    @property
    def changed(self) -> int:
        return len(self.start) + len(self.stop)

    @property
    def share(self) -> float:
        return self.changed / self.total if self.total else 0.0

    def acceptable(self, max_changes: int = 0, max_share: float = 0.0) -> bool:
        """The validator's verdict: no more than ``max_changes`` objects and ``max_share`` of the population
        change, and nothing is unknown. The defaults mean "nothing may change"."""
        return not self.unknown and self.changed <= max_changes + int(max_share * self.total)


def impact(old: RuleSet, new: RuleSet, population: Sequence[Mapping[str, Any]], *, object_type: str = "user",
           excluded_ous: Sequence[str] = (), new_excluded_ous: Optional[Sequence[str]] = None) -> Impact:
    """Run both rule sets over ``population`` and report who would start or stop synchronising."""
    after_ous = excluded_ous if new_excluded_ous is None else new_excluded_ous
    report = Impact(total=len(population))
    for obj in population:
        label = str(_first(obj, "userPrincipalName", "sAMAccountName", "distinguishedName", "name") or "?")
        before = verdict(old, obj, object_type=object_type, excluded_ous=excluded_ous).filtered
        after = verdict(new, obj, object_type=object_type, excluded_ous=after_ous).filtered
        if before is None or after is None:
            report.unknown.append(label)
        elif before and not after:
            report.start.append(label)
        elif after and not before:
            report.stop.append(label)
        else:
            report.unchanged += 1
    return report
