"""Group audit: collection (bulk query confirmed per group) and the unowned/empty/stale rules."""

import pytest

from entra_auditor.checks._common import AuditConfig
from entra_auditor.checks.stale_groups import check_stale_groups
from entra_auditor.graph.client import GraphError, GraphPermissionError
from entra_auditor.graph.collectors import TenantCollector
from tests.builders import NOW, ago, cfg, group, ids, only, policy, snapshot

U, G, D = "#microsoft.graph.user", "#microsoft.graph.group", "#microsoft.graph.device"
OLD, NEW = "2025-01-01T00:00:00Z", "2026-09-20T00:00:00Z"


def raw(i, name, **kw):
    return {**{"id": i, "displayName": name, "mailEnabled": False, "securityEnabled": True, "groupTypes": [], "createdDateTime": OLD}, **kw}


RAW = [
    raw("g1", "Finance-Share"), raw("g2", "Old Project"), raw("g3", "Mail-Sec", mailEnabled=True),
    raw("g4", "DL", mailEnabled=True, securityEnabled=False), raw("g5", "AD-Sync", onPremisesSyncEnabled=True),
    raw("g6", "Licensed Empty", assignedLicenses=[{"skuId": "x"}]), raw("g7", "Expand Liar"),
    raw("g8", "CA Exclusion Group"), raw("g9", "Nested Child"), raw("g10", "Role Group", isAssignableToRole=True),
    raw("g11", "Dynamic Empty", groupTypes=["DynamicMembership"], membershipRule="user.department -eq 'X'"),
    raw("g12", "Team Site", groupTypes=["Unified"], mailEnabled=True, securityEnabled=False),
    raw("g13", "New Empty", createdDateTime=NEW), raw("g14", "Only Devices"),
]
OWNERS = {"g1": ["o"], "g7": ["o"], "g11": ["o"], "g13": ["o"], "g14": ["o"]}
MEMBERS = {"g1": [(U, "u1"), (U, "u2")], "g7": [(U, "u1"), (U, "u2")], "g12": [(U, "u1")], "g14": [(D, "d1"), (D, "d2")]}
LIARS = {"g7"}     # the bulk query wrongly says these have no owners and no members


class GroupGraph:
    """Serves /groups (bulk expand + direct lookups) the way Graph does, including its flaws."""

    def __init__(self, expand_fail=(), forbid_usage=False, forbid_probe=()):
        self.expand_fail, self.forbid_usage, self.forbid_probe = set(expand_fail), forbid_usage, set(forbid_probe)
        self.calls = []

    def get_all(self, path, **kw):
        return list(self.get_paged(path, **kw))

    def get_paged(self, path, **kw):
        self.calls.append(path)
        if path == "/groups" and kw.get("expand"):
            edge = kw["expand"].split("(")[0]
            if edge in self.expand_fail:
                raise GraphError("400 unsupported expand", status_code=400)
            for g in RAW:
                gid = g["id"]
                if edge == "owners":
                    items = [] if gid in LIARS else [{"id": o, "@odata.type": U} for o in OWNERS.get(gid, [])]
                else:
                    items = [] if gid in LIARS else [{"id": i, "@odata.type": t} for t, i in MEMBERS.get(gid, [])]
                yield {"id": gid, edge: items}
            return
        if path == "/groups":
            yield from RAW
            return
        _, gid, edge = path.strip("/").split("/")[:3]
        if gid in self.forbid_probe:
            raise GraphError("500 boom", status_code=500)
        if edge == "owners":
            yield from [{"id": o} for o in OWNERS.get(gid, [])][: kw.get("top", 99)]
        elif edge == "transitiveMembers":
            users = [] if gid == "g9" else [{"id": i} for t, i in MEMBERS.get(gid, []) if t == U]
            yield from users[: kw.get("top", 99)]
        elif edge == "appRoleAssignments":
            if self.forbid_usage:
                raise GraphPermissionError("403 need Directory.Read.All", status_code=403)
            yield from ([{"id": "a"}] if gid == "g8" else [])
        elif edge == "memberOf":
            if gid == "g9":
                yield {"id": "g1", "displayName": "Finance-Share", "@odata.type": G}
            if gid == "g10":
                yield {"id": "r1", "displayName": "Helpdesk Administrator", "@odata.type": "#microsoft.graph.directoryRole"}


def scan(graph, config=None, probes=None):
    collector = TenantCollector(graph)
    if probes is not None:
        collector.MAX_GROUP_PROBES = probes
    groups = collector.groups()
    collector.group_usage(groups)
    snap = snapshot(groups=groups, group_usage_available=collector.group_usage_available,
                    ca_policies=[policy(exclude_groups=["g8"])], warnings=collector.warnings)
    findings = check_stale_groups(snap, NOW, config or AuditConfig())
    by_group = {}
    for f in findings:
        by_group.setdefault(f.resource_name, {})[f.check_id.removeprefix("GROUP_")] = f.severity
    return collector, groups, findings, by_group


@pytest.fixture(scope="module")
def bulk():
    return scan(GroupGraph())


@pytest.mark.parametrize("name,expected", [
    ("Old Project", {"UNOWNED": "low", "EMPTY": "low", "STALE": "low"}),
    ("AD-Sync", {"EMPTY": "low", "STALE": "low"}),                   # synced: never "unowned"
    ("Licensed Empty", {"UNOWNED": "medium", "EMPTY": "medium"}),    # in use: more severe, never stale
    ("CA Exclusion Group", {"UNOWNED": "medium", "EMPTY": "medium"}),
    ("Role Group", {"UNOWNED": "high", "EMPTY": "medium"}),          # directory role: high
    ("Dynamic Empty", {"EMPTY": "low"}),                             # dynamic: never stale
    ("Team Site", {"UNOWNED": "low"}),
    ("Only Devices", {"EMPTY": "low", "STALE": "low"}),              # devices are not users
    ("Nested Child", {"UNOWNED": "medium", "EMPTY": "medium"}),      # nested in another group = in use
])
def test_each_group_gets_the_right_findings(bulk, name, expected):
    assert bulk[3][name] == expected


@pytest.mark.parametrize("name", ["Finance-Share", "Expand Liar", "Mail-Sec", "DL", "New Empty"])
def test_these_groups_are_not_reported(bulk, name):
    # healthy / unreliable bulk result corrected / mail-enabled skipped / too new to call stale
    assert "STALE" not in bulk[3].get(name, {}) and (name == "New Empty" or name not in bulk[3])


def test_the_unreliable_bulk_query_is_corrected_by_a_direct_check(bulk):
    liar = next(g for g in bulk[1] if g.id == "g7")
    assert liar.owner_count == 1 and liar.user_member_count == 1


def test_healthy_groups_are_never_probed_individually(bulk):
    assert [p for p in bulk[0]._graph.calls if p.startswith("/groups/g1/")] == []


def test_mail_enabled_groups_can_be_included():
    _, _, _, by_group = scan(GroupGraph(), AuditConfig(include_mail_enabled_groups=True))
    assert "Mail-Sec" in by_group and "DL" in by_group


def test_unsupported_bulk_queries_fall_back_to_per_group_checks_with_the_same_result(bulk):
    collector, _, _, by_group = scan(GroupGraph(expand_fail={"owners", "members"}))
    assert by_group == bulk[3]
    assert any("bulk query" in w for w in collector.warnings)


def test_counts_that_cannot_be_confirmed_stay_unknown_and_are_never_flagged():
    collector, groups, findings, _ = scan(GroupGraph(expand_fail={"owners", "members"}), probes=3)
    unknown = {g.id for g in groups if g.owner_count is None and g.user_member_count is None}
    assert unknown and any("not confirmed" in w for w in collector.warnings)
    assert not any(f.resource_id in unknown for f in findings)


def test_a_group_whose_check_fails_is_unknown_not_flagged():
    _, groups, _, by_group = scan(GroupGraph(forbid_probe={"g2"}))
    assert next(g for g in groups if g.id == "g2").owner_count is None and "Old Project" not in by_group


def test_without_usage_data_nothing_is_called_stale():
    _, _, findings, _ = scan(GroupGraph(forbid_usage=True))
    assert "GROUP_STALE" not in ids(findings) and "GROUP_USAGE_UNAVAILABLE" in ids(findings)


# ---- the check on its own (builders, no collection) ---------------------------------------

def test_data_unavailable():
    assert ids(check_stale_groups(snapshot(groups=None), NOW, cfg())) == ["GROUPS_DATA_UNAVAILABLE"]


def test_a_healthy_group_has_no_findings():
    assert check_stale_groups(snapshot(groups=[group()], group_usage_available=True), NOW, cfg()) == []


def test_unknown_counts_are_never_flagged():
    assert check_stale_groups(snapshot(groups=[group(owner_count=None, user_member_count=None)]), NOW, cfg()) == []


def test_stale_needs_age_usage_data_and_no_usage_signal():
    base = dict(owner_count=0, user_member_count=0, usage_checked=True)
    stale = check_stale_groups(snapshot(groups=[group(**base)], group_usage_available=True), NOW, cfg())
    assert "GROUP_STALE" in ids(stale)
    for kwargs in (dict(created_at=ago(10)), dict(renewed_at=ago(10)), dict(usage_checked=False), dict(is_team=True),
                   dict(app_role_assignments=1), dict(has_licenses=True), dict(directory_roles=["Helpdesk Administrator"])):
        findings = check_stale_groups(snapshot(groups=[group(**{**base, **kwargs})], group_usage_available=True), NOW, cfg())
        assert "GROUP_STALE" not in ids(findings), kwargs


def test_stale_threshold_is_configurable():
    g = group(owner_count=0, user_member_count=0, usage_checked=True, created_at=ago(100))
    snap = snapshot(groups=[g], group_usage_available=True)
    assert "GROUP_STALE" not in ids(check_stale_groups(snap, NOW, cfg()))
    assert "GROUP_STALE" in ids(check_stale_groups(snap, NOW, cfg(group_stale_days=90)))


def test_a_group_referenced_by_conditional_access_is_in_use():
    snap = snapshot(groups=[group(owner_count=0)], ca_policies=[policy(name="Block legacy", exclude_groups=["g1"])])
    finding = only(check_stale_groups(snap, NOW, cfg()), "GROUP_UNOWNED")
    assert finding.severity == "medium" and "Block legacy" in str(finding.evidence["usage"])


def test_evidence_describes_the_group():
    finding = only(check_stale_groups(snapshot(groups=[group(owner_count=0, mail="x@y.com")]), NOW, cfg()), "GROUP_UNOWNED")
    assert finding.resource_type == "group" and finding.evidence["kind_label"] == "Security"
    assert finding.evidence["owners"] == 0 and finding.evidence["age_days"] == 900 and finding.remediation
