"""Entra Connect sync rules, offline: read, explain, lint, diff and measure the impact of a change.

Two kinds of fixtures: Microsoft's published sample export (tests/data/connect_sample, the real XML format) and
small hand-built rules in the JSON shape, which keep the rule logic tests short."""

from __future__ import annotations

import json

import pytest

from entra_auditor.toolkit import syncrules as S
from entra_auditor.toolkit.syncrules import Condition, Flow, RuleSet, SyncRule


def rule(name, precedence, scope=None, flows=(), **kw):
    return {"Name": name, "Identifier": kw.pop("identifier", f"id-{name}"), "Direction": kw.pop("direction", "Inbound"),
            "Precedence": precedence, "SourceObjectType": "user", "TargetObjectType": "person",
            "ScopeFilter": [{"ScopeConditionList": [{"Attribute": a, "ComparisonOperator": op, "ComparisonValue": v}
                                                    for a, op, v in group]} for group in (scope or [])],
            "AttributeFlowMappings": [{"Destination": d, "Source": [s], "FlowType": k} for d, s, k in flows], **kw}


NO_SYNC = rule("In from AD - Do not sync (ext14)", 50, [[("extensionAttribute14", "EQUAL", "no0365sync")]],
               [("cloudFiltered", "True", "Constant")])
STANDARD = rule("In from AD - User Common", 110, [], [("displayName", "displayName", "Direct")],
                ImmutableTag="Microsoft.InfromADUserCommon.006")
EXPORT = [NO_SYNC, STANDARD]


def ruleset(*raw):
    return RuleSet([S.parse_rule(r) for r in (raw or EXPORT)])


# ---- reading -----------------------------------------------------------------------------------

def test_rules_are_read_from_a_file_an_array_or_an_export_folder(tmp_path):
    (tmp_path / "rules.json").write_text(json.dumps(EXPORT))
    assert [r.name for r in S.load_rules(tmp_path / "rules.json").rules] == [NO_SYNC["Name"], STANDARD["Name"]]
    export = tmp_path / "export"
    (export / "SynchronizationRules").mkdir(parents=True)
    (export / "Connectors").mkdir()
    (export / "SynchronizationRules" / "a.json").write_text(json.dumps(NO_SYNC), encoding="utf-8-sig")   # PowerShell's BOM
    (export / "SynchronizationRules" / "b.json").write_text(json.dumps(STANDARD))
    (export / "Connectors" / "contoso.json").write_text(json.dumps({"Name": "contoso.com", "Type": "AD"}))
    loaded = S.load_rules(export)
    assert len(loaded.rules) == 2 and loaded.unreadable == []            # the connector file isn't mistaken for a rule
    assert S.load_rules(tmp_path / "rules.json").rules[0].scope == loaded.rules[0].scope


def test_property_names_are_matched_loosely_and_what_is_not_a_rule_is_reported(tmp_path):
    odd = {"name": "Custom", "precedence": "70", "direction": "inbound", "disabled": "True",
           "scopeFilter": {"value": [{"scopeConditionList": {"value": [
               {"attribute": "department", "comparisonOperator": "STARTSWITH", "comparisonValue": "Lab"}]}}]},
           "attributeFlowMappings": [{"destination": "cloudFiltered", "expression": 'IIF([x]="1",True,False)', "flowType": "Expression"}]}
    parsed = S.parse_rule(odd)
    assert parsed.precedence == 70 and parsed.disabled and parsed.inbound
    assert parsed.scope == [[Condition("department", "STARTSWITH", "Lab")]]
    assert parsed.cloud_filter.constant_bool is None and "IIF" in parsed.cloud_filter.source
    (tmp_path / "mixed.json").write_text(json.dumps({"SynchronizationRules": [NO_SYNC]}))
    assert len(S.load_rules(tmp_path / "mixed.json").rules) == 1
    (tmp_path / "junk.json").write_text('{"hello": "world"}')
    with pytest.raises(S.SyncRuleError, match="No synchronisation rules were recognised"):
        S.load_rules(tmp_path / "junk.json")
    with pytest.raises(S.SyncRuleError, match="does not exist"):
        S.load_rules(tmp_path / "nope")


# ---- conditions -----------------------------------------------------------------------------------

@pytest.mark.parametrize("op, value, obj, expected", [
    ("EQUAL", "no0365sync", {"x": "NO0365SYNC"}, True),                             # case-insensitive
    ("EQUAL", "no0365sync", {"x": "no0365sync2"}, False),                           # one character more
    ("EQUAL", "no0365sync", {}, False),
    ("NOTEQUAL", "no0365sync", {}, True),
    ("ISNULL", "", {}, True), ("ISNULL", "", {"x": ""}, True), ("ISNULL", "", {"x": "a"}, False),
    ("ISNOTNULL", "", {"x": "a"}, True),
    ("STARTSWITH", "svc-", {"x": "SVC-backup"}, True), ("NOTSTARTSWITH", "svc-", {"x": "SVC-backup"}, False),
    ("ENDSWITH", "$", {"x": "PC01$"}, True), ("CONTAINS", "admin", {"x": ["users", "Domain Admins"]}, True),
    ("NOTCONTAINS", "admin", {"x": ["users"]}, True),
    ("ISIN", "a, b;c", {"x": "C"}, True), ("ISNOTIN", "a,b", {"x": "c"}, True),
    ("ISBITSET", "2", {"x": "514"}, True), ("ISBITSET", "2", {"x": "512"}, False),   # userAccountControl: disabled
    ("ISBITNOTSET", "2", {"x": "512"}, True), ("ISBITNOTSET", "2", {}, True),
    ("GREATERTHAN", "5", {"x": "6"}, True), ("GREATERTHAN", "5", {"x": "5"}, False),
    ("LESSTHAN_OR_EQUAL", "5", {"x": "5"}, True), ("GREATERTHAN", "5", {"x": "six"}, None),
    ("SOUNDSLIKE", "x", {"x": "x"}, None),                                           # unknown: never guessed
])
def test_conditions(op, value, obj, expected):
    assert Condition("x", op, value).matches(obj) is expected


def test_a_cloud_filter_copied_from_an_attribute_is_not_a_constant():
    assert Flow("cloudFiltered", "True", "Constant").constant_bool is True
    assert Flow("cloudFiltered", '"false"', "").constant_bool is False
    assert Flow("cloudFiltered", "True", "Direct").constant_bool is None        # an attribute that happens to be named True
    assert Flow("cloudFiltered", "IIF(...)", "Expression").constant_bool is None


def test_scope_is_any_group_of_all_conditions():
    r = S.parse_rule(rule("r", 10, [[("a", "EQUAL", "1"), ("b", "EQUAL", "2")], [("c", "ISNOTNULL", "")]]))
    assert r.in_scope({"a": "1", "b": "2"}) is True and r.in_scope({"a": "1"}) is False and r.in_scope({"c": "x"}) is True
    assert r.scope_text == "(a equals '1' and b equals '2') OR (c has a value)"
    assert S.parse_rule(rule("all", 10)).in_scope({}) is True and S.parse_rule(rule("all", 10)).scope_text == "every object"
    odd = S.parse_rule(rule("odd", 10, [[("a", "EQUAL", "1"), ("b", "SOUNDSLIKE", "x")]]))
    assert odd.in_scope({"a": "1"}) is None and odd.in_scope({"a": "2"}) is False    # a failed condition is certain


# ---- explaining -----------------------------------------------------------------------------------

def test_the_owners_convention_is_explained():
    rules = ruleset()
    out = S.verdict(rules, {"extensionAttribute14": "no0365sync", "displayName": "Svc"})
    assert out.filtered is True and out.decided_by.name == NO_SYNC["Name"]
    assert out.reason == ("Not synchronised: 'In from AD - Do not sync (ext14)' (precedence 50) sets cloudFiltered to "
                          "True because extensionAttribute14 equals 'no0365sync'.")
    out = S.verdict(rules, {"displayName": "Alice"})
    assert out.filtered is False and "no rule that applies filters it out" in out.reason
    assert "Container/OU filtering wasn't checked" in out.reason and [r.name for r in out.applying] == [STANDARD["Name"]]


def test_an_excluded_ou_filters_before_any_rule_and_matches_whole_components():
    rules, ous = ruleset(), ["OU=NoSync,DC=contoso,DC=com"]
    out = S.verdict(rules, {"distinguishedName": "CN=Bob,OU=Temps,OU=NoSync,DC=contoso,DC=com"}, excluded_ous=ous)
    assert out.filtered is True and "excluded organisational unit OU=NoSync,DC=contoso,DC=com" in out.reason
    assert S.verdict(rules, {"distinguishedName": "CN=Bob,OU=VeryNoSync,DC=contoso,DC=com"}, excluded_ous=ous).filtered is False
    assert S.verdict(rules, {"distinguishedName": "CN=Bob, OU=nosync, DC=Contoso, DC=com"}, excluded_ous=ous).filtered is True


def test_the_lowest_precedence_number_wins_and_disabled_rules_do_not_count():
    keep = rule("Keep VIPs", 40, [[("title", "EQUAL", "VIP")]], [("cloudFiltered", "False", "Constant")])
    vip = {"extensionAttribute14": "no0365sync", "title": "VIP"}
    out = S.verdict(ruleset(NO_SYNC, STANDARD, keep), vip)
    assert out.filtered is False and out.decided_by.name == "Keep VIPs"
    assert S.verdict(ruleset(NO_SYNC, STANDARD, {**keep, "Precedence": 60}), vip).filtered is True     # now outranked
    assert S.verdict(ruleset({**NO_SYNC, "Disabled": True}, STANDARD), vip).filtered is False
    outbound = {**NO_SYNC, "Direction": "Outbound"}
    assert S.verdict(ruleset(outbound, STANDARD), vip).filtered is False       # only inbound rules set cloudFiltered here
    assert S.verdict(ruleset(), vip, object_type="group").filtered is False    # user rules don't apply to groups


def test_what_cannot_be_evaluated_is_cannot_tell():
    computed = rule("Computed", 30, [], [("cloudFiltered", 'IIF(Word([department],1," ")="Lab",True,False)', "Expression")])
    out = S.verdict(ruleset(computed, STANDARD), {"department": "Lab"})
    assert out.filtered is None and "couldn't be worked out for this object" in out.reason
    odd = rule("Odd", 30, [[("x", "SOUNDSLIKE", "y")]], [("cloudFiltered", "True", "Constant")])
    out = S.verdict(ruleset(odd, STANDARD), {"x": "y"})
    assert out.filtered is None and "couldn't be evaluated" in out.reason


def test_a_rule_is_described_in_plain_english():
    text = ruleset().rules[0].describe()
    assert "Inbound rule, precedence 50, custom, user -> person" in text
    assert "Applies to: extensionAttribute14 equals 'no0365sync'" in text
    assert "FILTERS FROM THE CLOUD: cloudFiltered = True (constant)" in text
    assert "built-in" in ruleset().rules[1].describe() and "Sets: displayName = displayName (direct)" in ruleset().rules[1].describe()


# ---- lint -------------------------------------------------------------------------------------------

def test_lint_finds_the_dangerous_and_the_merely_odd():
    everything = rule("Filter all", 60, [], [("cloudFiltered", "True", "Constant")])
    clash = rule("Clash", 50, [[("a", "EQUAL", "1")]], [("x", "y", "Direct")])
    high = rule("Custom high", 150, [[("a", "SOUNDSLIKE", "1")]], [("x", "y", "Direct")])
    off = {**STANDARD, "Disabled": True}
    found = S.lint(ruleset(NO_SYNC, everything, clash, high, off))
    texts = [(i.level, i.rule, i.text) for i in found]
    assert ("error", "Filter all") == texts[1][:2] or ("error", "Filter all") == texts[0][:2]
    said = " | ".join(f"{level}:{name}:{text}" for level, name, text in texts)
    assert "remove EVERY object of its type" in said
    assert "Precedence 50 is used by several inbound rules (Clash, In from AD - Do not sync (ext14))" in said
    assert "warning:Custom high:Custom rule with precedence 150" in said
    assert "Unknown comparison 'SOUNDSLIKE'" in said and "cloned and customised" in said
    assert [i.level for i in found] == sorted((i.level for i in found), key=["error", "warning", "info"].index)
    assert S.lint(ruleset()) == []                               # the owner's two rules are clean


def test_the_same_precedence_inbound_and_outbound_is_not_a_clash():
    out = rule("Out to AAD - Something", 50, direction="Outbound", flows=[("x", "y", "Direct")])
    assert not any("used by several" in i.text for i in S.lint(ruleset(NO_SYNC, out)))


# ---- diff and impact ------------------------------------------------------------------------------------

def changed(**kw):
    return {**NO_SYNC, **kw}


def test_diff_ranks_what_can_change_who_is_synchronised_first():
    wider = rule("In from AD - Do not sync (ext14)", 50, [[("extensionAttribute14", "STARTSWITH", "no")]],
                 [("cloudFiltered", "True", "Constant")])
    renamed_standard = {**STANDARD, "Name": "In from AD - User Common (old)", "Precedence": 111}
    extra = rule("New filter", 45, [[("department", "EQUAL", "Lab")]], [("cloudFiltered", "True", "Constant")])
    found = S.diff(ruleset(), ruleset(wider, renamed_standard, extra))
    assert [(i.level, i.rule) for i in found][:2] == [("error", "In from AD - Do not sync (ext14)"), ("error", "New filter")]
    said = " | ".join(i.text for i in found)
    assert "Scope changed: was extensionAttribute14 equals 'no0365sync'; now extensionAttribute14 starts with 'no'" in said
    assert "Precedence changed from 110 to 111" in said and "Renamed from 'In from AD - User Common'" in said
    assert S.diff(ruleset(), ruleset()) == []


def test_removing_disabling_or_rewiring_a_filter_is_an_error():
    assert [i.level for i in S.diff(ruleset(), ruleset(STANDARD))] == ["error"]              # the filter is gone
    assert S.diff(ruleset(), ruleset(changed(Disabled=True), STANDARD))[0] == S.Issue(
        "error", NO_SYNC["Name"], "Now disabled.")
    flipped = rule("In from AD - Do not sync (ext14)", 50, [[("extensionAttribute14", "EQUAL", "no0365sync")]],
                   [("cloudFiltered", "False", "Constant")])
    found = S.diff(ruleset(), ruleset(flipped, STANDARD))
    assert found[0].level == "error" and "was cloudFiltered = True (constant); now cloudFiltered = False (constant)" in found[0].text
    harmless = {**STANDARD, "AttributeFlowMappings": [{"Destination": "displayName", "Source": ["cn"], "FlowType": "Direct"}]}
    assert [i.level for i in S.diff(ruleset(), ruleset(NO_SYNC, harmless))] == ["warning"]


POPULATION = ([{"userPrincipalName": f"user{i}@contoso.com"} for i in range(8)]
              + [{"userPrincipalName": "svc1@contoso.com", "extensionAttribute14": "no0365sync"},
                 {"userPrincipalName": "svc2@contoso.com", "extensionAttribute14": "nosync-legacy"}])


def test_impact_counts_who_would_start_and_stop_synchronising():
    same = S.impact(ruleset(), ruleset(), POPULATION)
    assert (same.total, same.changed, same.unchanged) == (10, 0, 10) and same.acceptable()
    wider = rule("In from AD - Do not sync (ext14)", 50, [[("extensionAttribute14", "STARTSWITH", "no")]],
                 [("cloudFiltered", "True", "Constant")])
    report = S.impact(ruleset(), ruleset(wider, STANDARD), POPULATION)
    assert report.stop == ["svc2@contoso.com"] and report.start == [] and report.share == 0.1
    assert not report.acceptable() and report.acceptable(max_changes=1) and report.acceptable(max_share=0.1)
    assert not report.acceptable(max_share=0.09)
    gone = S.impact(ruleset(), ruleset(STANDARD), POPULATION)
    assert gone.start == ["svc1@contoso.com"] and gone.stop == []


def test_impact_refuses_to_pass_what_it_cannot_judge_and_handles_ou_changes():
    computed = rule("Computed", 30, [], [("cloudFiltered", "IIF(...)", "Expression")])
    report = S.impact(ruleset(), ruleset(computed, NO_SYNC, STANDARD), POPULATION)
    assert len(report.unknown) == 10 and not report.acceptable(max_changes=1000)
    people = [{"userPrincipalName": "a@x.com", "distinguishedName": "CN=a,OU=Leavers,DC=x,DC=com"},
              {"userPrincipalName": "b@x.com", "distinguishedName": "CN=b,OU=Staff,DC=x,DC=com"}]
    report = S.impact(ruleset(), ruleset(), people, excluded_ous=["OU=Leavers,DC=x,DC=com"], new_excluded_ous=[])
    assert report.start == ["a@x.com"] and report.unchanged == 1


def test_a_population_is_read_from_a_get_aduser_csv(tmp_path):
    path = tmp_path / "users.csv"
    path.write_text('"userPrincipalName","extensionAttribute14","distinguishedName"\n'
                    '"a@x.com","no0365sync","CN=a,DC=x"\n"b@x.com","","CN=b,DC=x"\n', encoding="utf-8-sig")
    people = S.load_population(path)
    assert people == [{"userPrincipalName": "a@x.com", "extensionAttribute14": "no0365sync", "distinguishedName": "CN=a,DC=x"},
                      {"userPrincipalName": "b@x.com", "distinguishedName": "CN=b,DC=x"}]
    assert [S.verdict(ruleset(), p).filtered for p in people] == [True, False]
    assert isinstance(ruleset().rules[0], SyncRule) and Flow("a", "b").text == "a = b"


# ---- expressions decide too ---------------------------------------------------------------------------

def test_an_expression_that_yields_null_passes_the_decision_to_the_next_rule():
    first = rule("Lab only", 30, [], [("cloudFiltered", 'IIF([department]="Lab",True,NULL)', "Expression")])
    assert S.verdict(ruleset(first, NO_SYNC, STANDARD), {"department": "Lab"}).decided_by.name == "Lab only"
    out = S.verdict(ruleset(first, NO_SYNC, STANDARD), {"department": "Sales", "extensionAttribute14": "no0365sync"})
    assert out.filtered is True and out.decided_by.name == NO_SYNC["Name"]          # NULL at 30, so 50 decides
    assert S.verdict(ruleset(first, NO_SYNC, STANDARD), {"department": "Sales"}).filtered is False
    keep = rule("Keep", 20, [], [("cloudFiltered", 'IIF([title]="VIP",False,NULL)', "Expression")])
    assert S.verdict(ruleset(keep, first, STANDARD), {"department": "Lab", "title": "VIP"}).filtered is False


def test_lint_only_complains_about_expressions_it_cannot_read():
    fine = rule("Fine", 30, [[("a", "EQUAL", "1")]], [("cloudFiltered", 'IIF([department]="Lab",True,NULL)', "Expression")])
    broken = rule("Broken", 31, [[("a", "EQUAL", "1")]], [("cloudFiltered", 'IIF([department]="Lab",True', "Expression")])
    found = S.lint(ruleset(fine, broken))
    assert [(i.level, i.rule) for i in found] == [("warning", "Broken")] and "couldn't be read" in found[0].text


# ---- Microsoft's published sample export (the real XML format) -------------------------------------------

SAMPLE = "tests/data/connect_sample"
CORP = "OU=CORP,DC=contoso,DC=com"


def person(name, ou=f"OU=Staff,{CORP}", **attributes):
    return {"sAMAccountName": name, "userPrincipalName": f"{name}@contoso.com",
            "distinguishedName": f"CN={name},{ou}", **attributes}


@pytest.fixture(scope="module")
def sample():
    return S.load_rules(SAMPLE)


def test_the_sample_export_is_read_completely(sample):
    assert len(sample.rules) == 62 and sample.unreadable == []
    assert sum(1 for r in sample.rules if r.inbound) == 28 and all(r.standard for r in sample.rules)
    join = next(r for r in sample.rules if r.name == "In from AD - User Join")
    assert (join.precedence, join.direction, join.source_type, join.target_type, join.link_type) == (
        100, "Inbound", "user", "person", "Provision")
    assert join.connector == "contoso.com"                       # the connector's GUID was resolved to its name
    assert join.scope_text == "isCriticalSystemObject does not equal 'TRUE' and adminDescription does not start with 'User_'"
    assert join.cloud_filter.kind == "Expression" and join.cloud_filter.understood
    kinds = {f.kind for r in sample.rules for f in r.flows}
    assert kinds == {"Expression", "Direct", "Constant"}
    assert Flow("accountEnabled", "True", "Constant") in next(r for r in sample.rules if r.name == "In from AD - User AccountEnabled").flows
    several = [r for r in sample.rules if len(r.scope) > 1]
    assert len(several) == 1 and " OR " in several[0].scope_text
    assert [(i.level) for i in S.lint(sample)] == ["info"] * 5   # Microsoft's defaults raise nothing worse


def test_container_filtering_is_read_from_the_connector(sample):
    (containers,) = sample.containers
    assert containers.inclusions == (CORP,) and containers.exclusions == ("DC=contoso,DC=com",)
    assert containers.text == "contoso.com / DC=contoso,DC=com: reads OU=CORP,DC=contoso,DC=com; except DC=contoso,DC=com"
    assert S.verdict(sample, person("alice")).filtered is False
    out = S.verdict(sample, person("bob", ou="OU=Other,DC=contoso,DC=com"))
    assert out.filtered is True and "DC=contoso,DC=com (excluded on connector contoso.com)" in out.reason
    assert S.verdict(sample, person("eve", ou="OU=CORPORATE,DC=contoso,DC=com")).filtered is True     # not OU=CORP
    out = S.verdict(sample, person("dan", ou="DC=fabrikam,DC=com"))
    assert out.filtered is True and "outside every partition" in out.reason
    out = S.verdict(sample, {"sAMAccountName": "carol"})
    assert out.filtered is False and "No distinguishedName was given" in out.reason


def test_the_most_specific_container_wins():
    nested = S.ContainerFilter("c", "DC=x", inclusions=("OU=A,DC=x", "OU=Keep,OU=Off,OU=A,DC=x"), exclusions=("OU=Off,OU=A,DC=x",))
    assert nested.decides("CN=u,OU=A,DC=x") == (True, "OU=A,DC=x")
    assert nested.decides("CN=u,OU=Off,OU=A,DC=x") == (False, "OU=Off,OU=A,DC=x")
    assert nested.decides("CN=u,OU=Keep,OU=Off,OU=A,DC=x") == (True, "OU=Keep,OU=Off,OU=A,DC=x")
    assert nested.decides("CN=u,DC=x") == (True, "DC=x")          # no container listed: the partition itself
    assert nested.decides("CN=u,DC=y") is None


def test_microsofts_built_in_rules_filter_what_they_should(sample):
    for name in ("MSOL_1a2b3c4d", "AAD_abcdef"):
        out = S.verdict(sample, person(name))
        assert out.filtered is True and out.decided_by.name == "In from AD - User Join", name
    assert S.verdict(sample, person("mbx", mailNickname="SystemMailbox{1f05a927}")).filtered is True
    assert S.verdict(sample, person("room", msExchRecipientTypeDetails=str(0x20000000))).filtered is True
    assert S.verdict(sample, person("alice", mailNickname="alice", msExchRecipientTypeDetails="1")).filtered is False
    # a critical system object is out of the join rule's scope altogether: nothing filters it, nothing joins it
    assert "In from AD - User Join" not in [r.name for r in S.verdict(sample, person("krbtgt", isCriticalSystemObject="TRUE")).applying]


def with_custom_rule(tmp_path, operator="EQUAL", value="no0365sync", precedence=50, inclusion=CORP):
    """A copy of the sample plus one custom rule and, optionally, a different included container."""
    import shutil
    target = tmp_path / f"export-{operator}-{precedence}-{len(inclusion)}"
    shutil.copytree(SAMPLE, target)
    (target / "SynchronizationRules" / "SynchronizationRule_{11111111-2222-3333-4444-555555555555}.xml").write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<synchronizationRule><id>{{11111111-2222-3333-4444-555555555555}}</id><name>In from AD - User DoNotSync</name>
<immutable-tag></immutable-tag><direction>Inbound</direction><disabled>False</disabled>
<connector>{{ae4db4cc-b16b-4eb2-acf5-837ca84e4d7d}}</connector><sourceObjectType>user</sourceObjectType>
<targetObjectType>person</targetObjectType><linkType>Join</linkType><precedence>{precedence}</precedence>
<attribute-mappings><mapping><dest>cloudFiltered</dest><src>True</src><valueMergeType>Update</valueMergeType></mapping></attribute-mappings>
<synchronizationCriteria><conditions><scope><csAttribute>extensionAttribute14</csAttribute><csOperator>{operator}</csOperator>
<csValue>{value}</csValue></scope></conditions></synchronizationCriteria></synchronizationRule>""")
    connector = next((target / "Connectors").glob("*ae4db4cc*"))
    connector.write_text(connector.read_text().replace(f"<inclusion>{CORP}</inclusion>", f"<inclusion>{inclusion}</inclusion>"))
    return S.load_rules(target)


STAFF = ([person(f"user{i}") for i in range(6)] + [person("svc-backup", extensionAttribute14="no0365sync"),
                                                   person("svc-old", extensionAttribute14="nosync-legacy"),
                                                   person("MSOL_1a2b3c4d"), person("temp", ou="OU=Temps,DC=contoso,DC=com")])


def test_a_custom_filter_rule_on_top_of_the_defaults(sample, tmp_path):
    custom = with_custom_rule(tmp_path)
    assert len(custom.rules) == 63 and [r.name for r in custom.rules if not r.standard] == ["In from AD - User DoNotSync"]
    out = S.verdict(custom, person("svc-backup", extensionAttribute14="no0365sync"))
    assert out.filtered is True and out.decided_by.name == "In from AD - User DoNotSync"
    assert out.reason.endswith("because extensionAttribute14 equals 'no0365sync'.")
    assert S.verdict(custom, person("alice")).filtered is False
    changes = S.diff(sample, custom)
    assert [(c.level, c.rule) for c in changes] == [("error", "In from AD - User DoNotSync")]
    report = S.impact(sample, custom, STAFF)
    assert report.stop == ["svc-backup@contoso.com"] and report.start == [] and report.unknown == []
    assert report.unchanged == 9 and not report.acceptable() and report.acceptable(max_changes=1)


def test_widening_a_filter_or_moving_the_container_shows_up_in_diff_and_impact(tmp_path):
    before = with_custom_rule(tmp_path)
    wider = with_custom_rule(tmp_path, operator="STARTSWITH", value="no")
    assert "Scope changed" in S.diff(before, wider)[0].text
    assert S.impact(before, wider, STAFF).stop == ["svc-old@contoso.com"]
    moved = with_custom_rule(tmp_path, inclusion="DC=contoso,DC=com")          # now the whole domain is read
    changes = S.diff(before, moved)
    assert [c.rule for c in changes] == ["(containers)", "(containers)"] and all(c.level == "error" for c in changes)
    report = S.impact(before, moved, STAFF)
    assert report.start == ["temp@contoso.com"] and report.stop == []
    assert S.impact(before, before, STAFF).acceptable()
    weak = with_custom_rule(tmp_path, precedence=150)                          # below the built-in join rule
    assert any("Custom rule with precedence 150" in i.text for i in S.lint(weak))
