"""Entra Connect Sync rules, offline: read an export, explain it, and check a change before it is applied.

Entra Connect's rules live on the Connect server, not in Microsoft Graph, so this module works on FILES and
never touches a tenant or the Connect server:

    Import-Module ADSync
    Get-ADSyncServerConfiguration -Path C:\\Temp\\connect-export

That writes a folder of XML: ``SynchronizationRules/SynchronizationRule_{guid}.xml`` (one rule each),
``Connectors/Connector_{guid}.xml`` (each connector, including which containers/OUs it reads) and
``GlobalSettings``. The format here was taken from the sample export Microsoft publishes with its
AADConnectConfigDocumenter tool (MIT licence); a trimmed copy is the test data in
``tests/data/connect_sample``. Nothing in this module is specific to one organisation's conventions.

    describe   each rule in plain English (what it applies to, what it sets)
    lint       problems inside one rule set (duplicate precedence, a rule that filters everything, ...)
    explain    for one object's attributes: which rules apply and whether it is filtered from the cloud
    diff       what changed between two exports, with the risky changes first
    impact     run both rule sets over a population (a CSV from Get-ADUser) and count who would start
               or stop synchronising: the "this must not change things wildly" check

How Connect decides (what is modelled here):
  * **Containers.** Each AD connector partition lists included and excluded containers; an object is read
    only if the most specific container that holds it is an included one. (This is "OU filtering".)
  * **Scope.** A rule applies to an object when its scope filter matches: a list of groups; ANY group
    must match, and within a group ALL conditions.
  * **cloudFiltered.** An object is kept out of Entra ID when the metaverse attribute ``cloudFiltered``
    ends up True. Inbound rules that apply contribute in precedence order (lowest number first); a rule
    whose flow yields NULL contributes nothing and the next one is asked. Microsoft's built-in rules
    compute it with an expression, which ``syncexpr`` evaluates.
  * "Unknown is not no": an operator, function or expression that isn't understood gives "can't tell",
    never a guess, and the impact validator fails on anything it can't judge.

NOT modelled: the outbound rules' other scoping conditions (for example, groups and contacts need more
than "not cloudFiltered" to be exported), join rules, group-based filtering, attribute-based "domain"
filtering beyond containers, and attribute values other than cloudFiltered.

Also accepted, format NOT confirmed: JSON (``Get-ADSyncRule | ConvertTo-Json``), matched loosely on the
ADSync object's property names. NOT VERIFIED AGAINST A LIVE CONNECT SERVER. See CLAUDE.md.
"""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from .syncexpr import UNKNOWN, ExpressionError, as_filter, evaluate
from .syncexpr import parse as parse_expression

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

    def filter_value(self, obj: Mapping[str, Any]) -> Any:
        """What this flow contributes to cloudFiltered for ``obj``: True, False, None (nothing: the next
        rule is asked) or UNKNOWN (it can't be worked out here)."""
        kind = self.kind.lower()
        if kind == "expression":
            return as_filter(evaluate(self.source, obj))
        if kind == "direct":
            return as_filter(_lookup(obj, self.source))
        constant = self.constant_bool
        return UNKNOWN if constant is None else constant

    @property
    def understood(self) -> bool:
        """False when the flow is an expression this module can't even parse."""
        if self.kind.lower() != "expression":
            return True
        try:
            parse_expression(self.source)
        except ExpressionError:
            return False
        return True


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


def _dn(text: str) -> str:
    return text.casefold().replace(", ", ",").strip()


def _dn_within(dn: str, container: str) -> bool:
    child, parent = _dn(dn), _dn(container)
    return bool(parent) and (child == parent or child.endswith("," + parent))


@dataclass(frozen=True)
class ContainerFilter:
    """Which containers one connector partition reads ("OU filtering")."""
    connector: str
    partition: str
    inclusions: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()

    def decides(self, dn: str) -> Optional[tuple[bool, str]]:
        """(read?, the container that decided) for a DN in this partition; None when it isn't in it."""
        if not _dn_within(dn, self.partition):
            return None
        best: Optional[tuple[bool, str]] = None
        for included, containers in ((True, self.inclusions), (False, self.exclusions)):
            for container in containers:
                if _dn_within(dn, container) and (best is None or len(_dn(container)) > len(_dn(best[1]))):
                    best = (included, container)
        return best if best is not None else (True, self.partition)

    @property
    def text(self) -> str:
        return (f"{self.connector} / {self.partition}: reads " + (", ".join(self.inclusions) or "everything")
                + (f"; except {', '.join(self.exclusions)}" if self.exclusions else ""))


def _xml_rule(root: ET.Element, connector_names: Mapping[str, str]) -> SyncRule:
    def text(tag: str) -> str:
        return (root.findtext(tag) or "").strip()

    try:
        precedence: Optional[int] = int(text("precedence"))
    except ValueError:
        precedence = None
    scope = [[Condition((c.findtext("csAttribute") or "?").strip(), (c.findtext("csOperator") or "?").strip(),
                        (c.findtext("csValue") or "").strip()) for c in group.findall("scope")]
             for group in root.findall("synchronizationCriteria/conditions")]
    flows = []
    for mapping in root.findall("attribute-mappings/mapping"):
        destination = (mapping.findtext("dest") or "?").strip()
        expression, src = mapping.findtext("expression"), mapping.find("src")
        attributes = [(a.text or "").strip() for a in src.findall("attr")] if src is not None else []
        if expression is not None:
            flows.append(Flow(destination, expression.strip(), "Expression"))
        elif attributes:
            flows.append(Flow(destination, ", ".join(attributes), "Direct"))
        else:
            flows.append(Flow(destination, (src.text or "").strip() if src is not None else "", "Constant"))
    connector_id = text("connector").strip("{}").lower()
    return SyncRule(name=text("name"), identifier=text("id").strip("{}").lower(), direction=text("direction"),
                    precedence=precedence, connector=connector_names.get(connector_id, text("connector")),
                    source_type=text("sourceObjectType"), target_type=text("targetObjectType"),
                    link_type=text("linkType"), disabled=text("disabled").casefold() == "true",
                    immutable_tag=text("immutable-tag"), scope=[g for g in scope if g], flows=flows)


def _xml_connector(root: ET.Element) -> tuple[str, str, list[ContainerFilter]]:
    """(id, name, container filters of the selected partitions) of one connector file."""
    connector_id = (root.findtext("id") or "").strip().strip("{}").lower()
    name = (root.findtext("name") or connector_id).strip()
    filters: list[ContainerFilter] = []
    if (root.findtext("category") or "").strip().upper().startswith("AD"):       # only AD has containers to filter
        for partition in root.iter("partition"):
            partition_name = (partition.findtext("name") or "").strip()
            if not partition_name or (partition.findtext("selected") or "1").strip() != "1":
                continue
            inclusions = tuple(t.strip() for t in (e.text or "" for e in partition.iter("inclusion")) if t.strip())
            exclusions = tuple(t.strip() for t in (e.text or "" for e in partition.iter("exclusion")) if t.strip())
            filters.append(ContainerFilter(name, partition_name, inclusions, exclusions))
    return connector_id, name, filters


@dataclass
class RuleSet:
    rules: list[SyncRule]
    source: str = ""
    unreadable: list[str] = field(default_factory=list)     # files/entries that weren't rules
    containers: list[ContainerFilter] = field(default_factory=list)     # OU filtering, when the export has it

    def container_verdict(self, dn: str) -> Optional[tuple[bool, str]]:
        """(read?, why) for a distinguished name; None when the export has no container filters or the DN
        is in none of the connectors' partitions."""
        for item in self.containers:
            decided = item.decides(dn)
            if decided is not None:
                return decided[0], f"{decided[1]} ({'included' if decided[0] else 'excluded'} on connector {item.connector})"
        return None

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
    """Rules (and, from a full export, the connectors' container filters) from an export folder or one file.
    XML is the format ``Get-ADSyncServerConfiguration`` writes; JSON is accepted too."""
    path = Path(path).expanduser()
    if not path.exists():
        raise SyncRuleError(f"{path} does not exist.")
    files = [path] if path.is_file() else sorted(f for f in path.rglob("*") if f.suffix.lower() in (".xml", ".json"))
    if not files:
        raise SyncRuleError(f"No XML or JSON files under {path}. Export with: Get-ADSyncServerConfiguration -Path <folder>")
    found: list[SyncRule] = []
    unreadable: list[str] = []
    containers: list[ContainerFilter] = []
    connector_names: dict[str, str] = {}
    rule_roots: list[ET.Element] = []
    for file in files:
        if file.suffix.lower() == ".json":
            try:
                data = json.loads(file.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as exc:
                unreadable.append(f"{file.name}: {exc}")
                continue
            before = len(unreadable)
            _collect(data, file.name, found, unreadable)
            if path.is_dir() and len(unreadable) > before:      # other JSON in a folder isn't an error
                del unreadable[before:]
            continue
        try:
            root = ET.parse(file).getroot()
        except (OSError, ET.ParseError) as exc:
            unreadable.append(f"{file.name}: {exc}")
            continue
        if root.tag == "synchronizationRule":
            rule_roots.append(root)
        elif root.tag == "ma-data":
            connector_id, name, filters = _xml_connector(root)
            connector_names[connector_id] = name
            containers += filters
        elif path.is_file():
            unreadable.append(f"{file.name}: not a synchronisation rule (root element <{root.tag}>)")
    found += [_xml_rule(root, connector_names) for root in rule_roots]      # after the connectors, for their names
    if not found:
        raise SyncRuleError(f"No synchronisation rules were recognised in {path}. Expected the folder written by "
                            "Get-ADSyncServerConfiguration -Path (SynchronizationRules/*.xml), or one such file.")
    return RuleSet(found, str(path), unreadable, containers)


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


def _precedence(rule: SyncRule) -> tuple[int, str]:
    return (rule.precedence if rule.precedence is not None else 10**9, rule.name)


def verdict(rules: RuleSet | Sequence[SyncRule], obj: Mapping[str, Any], *, object_type: str = "user",
            excluded_ous: Iterable[str] = ()) -> Verdict:
    """Is ``obj`` (AD attribute name -> value) kept out of Entra ID, and why. ``excluded_ous`` adds exclusions
    by hand, for exports without connector files."""
    ruleset = rules if isinstance(rules, RuleSet) else RuleSet(list(rules))
    dn = str(_lookup(obj, "distinguishedName") or _lookup(obj, "dn") or "")
    containers_checked = bool(list(excluded_ous)) or bool(ruleset.containers)
    if dn:
        manual = next((ou for ou in excluded_ous if _dn_within(dn, ou)), None)
        if manual:
            return Verdict(True, f"Not synchronised: it is in the excluded organisational unit {manual}.")
        decided = ruleset.container_verdict(dn)
        if decided is not None and not decided[0]:
            return Verdict(True, f"Not synchronised: its container isn't read. Decided by {decided[1]}.")
        if decided is None and ruleset.containers:
            return Verdict(True, "Not synchronised: it is outside every partition the connectors read.")
    if dn and "dn" not in {str(k).casefold() for k in obj}:
        obj = {**obj, "dn": dn}                     # Microsoft's expressions call the DN [dn]
    candidates = sorted((r for r in ruleset.rules if r.inbound and not r.disabled
                         and (not r.source_type or r.source_type.casefold() == object_type.casefold())), key=_precedence)
    applying, uncertain = [], []
    for rule in candidates:
        scoped = rule.in_scope(obj)
        (applying if scoped else uncertain if scoped is None else []).append(rule)
    for rule in sorted((r for r in applying + uncertain if r.cloud_filter is not None), key=_precedence):
        flow = rule.cloud_filter
        assert flow is not None
        where = f"'{rule.name}' (precedence {rule.precedence})"
        if rule in uncertain:
            return Verdict(None, f"Can't tell: {where} could decide, but its scope uses something that couldn't be "
                                 f"evaluated ({rule.scope_text}).", rule, applying, uncertain)
        value = flow.filter_value(obj)
        if value is None:
            continue                                # NULL: this rule contributes nothing; ask the next one
        if value is UNKNOWN:
            return Verdict(None, f"Can't tell: {where} sets cloudFiltered with an expression that couldn't be "
                                 f"worked out for this object: {flow.source}", rule, applying, uncertain)
        how = "its expression is true for this object" if flow.kind.lower() == "expression" else rule.scope_text
        if value:
            return Verdict(True, f"Not synchronised: {where} sets cloudFiltered to True because {how}.",
                           rule, applying, uncertain)
        return Verdict(False, f"Synchronised: {where} sets cloudFiltered to False and outranks any rule that would "
                              "filter it.", rule, applying, uncertain)
    note = "" if containers_checked and dn else (" (No distinguishedName was given, so container/OU filtering wasn't "
                                                 "checked.)" if containers_checked else
                                                 " (Container/OU filtering wasn't checked: the export has no connector files.)")
    return Verdict(False, "Synchronised as far as these rules say: no rule that applies filters it out." + note,
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
            elif not flow.understood:
                issues.append(Issue("warning", rule.name, f"cloudFiltered is set by an expression that couldn't be read "
                                                          f"({flow.source}); explain and impact report 'can't tell' "
                                                          "for the objects it decides."))
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
    was_containers, now_containers = {c.text for c in old.containers}, {c.text for c in new.containers}
    for text in sorted(was_containers - now_containers):
        changes.append(Issue("error", "(containers)", f"Container filter removed or changed; was: {text}"))
    for text in sorted(now_containers - was_containers):
        changes.append(Issue("error", "(containers)", f"Container filter added or changed; now: {text}"))
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
    """Run both rule sets (and each export's own container filters) over ``population`` and report who would
    start or stop synchronising."""
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
