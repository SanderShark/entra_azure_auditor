"""The Conditional Access HTML report and Mermaid diagram: correct, escaped, and self-contained."""

import re
from html.parser import HTMLParser

import pytest

from entra_auditor import ca_report
from entra_auditor.checks.ca_analysis import analyze_policies
from entra_auditor.models import GroupInfo
from tests.builders import NOW, cfg, finding, make_run, policy, snapshot

HOSTILE = '<script>alert(1)</script> "]-->X["pwn"] #{} `x`'
VOID = {"meta", "input", "br", "hr", "img", "link"}


def build_run(**kw):
    policies = analyze_policies(snapshot(
        ca_groups=[GroupInfo(id="g1", display_name="<img src=x onerror=alert(2)>", member_count=250)],
        ca_policies=[
            policy("p1", "MFA all users", include_users=["All"], include_applications=["All"], grant_controls=["mfa"],
                   exclude_groups=["g1"], exclude_users=["bg"]),
            policy("p2", HOSTILE, include_users=["All"], include_applications=["All"], client_app_types=["other"], grant_controls=["block"]),
            policy("p3", "Guests", include_users=["GuestsOrExternalUsers"], include_applications=["All"],
                   grant_controls=["mfa", "compliantDevice"], grant_operator="OR"),
            policy("p4", "Pilot", state="enabledForReportingButNotEnforced", include_users=["All"], include_applications=["All"], grant_controls=["mfa"]),
            policy("p5", "Retired", state="disabled", include_users=["All"], grant_controls=["block"])]), cfg(), NOW)
    gaps = [finding("CA_NO_MFA_ALL_USERS", "high", "tenant", resource_type="tenant", resource_name=None, title="No policy requires MFA",
                    evidence={"closest_policies": [{"name": "MFA all users", "state": "enabled"}]})]
    return make_run(findings=gaps, policies=policies, **kw)


class Inspector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack, self.errors, self.tags, self.attrs, self.ids, self.hrefs = [], [], set(), set(), set(), []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        for key, value in attrs:
            self.attrs.add(key)
            if key == "id":
                self.ids.add(value)
            if key == "href":
                self.hrefs.append(value)
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(tag)
        else:
            self.stack.pop()


def inspect(page):
    inspector = Inspector()
    inspector.feed(page)
    return inspector


@pytest.fixture(scope="module")
def page():
    return ca_report.render_html(build_run())


def test_the_page_is_well_formed(page):
    inspector = inspect(page)
    assert inspector.errors == [] and inspector.stack == []


def test_hostile_names_appear_only_as_escaped_text(page):
    body = re.sub(r"<script>.*?</script>", "", page, flags=re.S)       # drop the page's own script block
    assert "<script" not in body and "<img" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body and "&lt;img src=x onerror=alert(2)&gt;" in body


def test_the_page_loads_nothing_from_the_network(page):
    inspector = inspect(page)
    assert not {"link", "img", "iframe", "object", "embed", "video", "audio", "source", "form"} & inspector.tags
    assert not {"src", "srcset", "action", "onclick", "onerror", "onload"} & inspector.attrs
    assert "Content-Security-Policy" in page and "default-src 'none'" in page


def test_every_flow_link_points_at_a_policy_card(page):
    inspector = inspect(page)
    local = [h for h in inspector.hrefs if h.startswith("#")]
    assert local and all(h[1:] in inspector.ids for h in local)


def test_the_page_summarises_gaps_policies_and_states(page):
    assert "No policy requires MFA" in page and "MFA all users (enabled)" in page            # baseline gap with its closest policy
    assert "Report-only" in page and "Retired" in page and "250 members" in page
    assert page.count('<article class="card policy"') == 5


def test_disabled_policies_can_be_left_out_of_the_cards():
    page = ca_report.render_html(build_run(), include_disabled=False)
    assert page.count('<article class="card policy"') == 4 and "Retired" not in page


def test_an_empty_run_still_renders():
    page = ca_report.render_html(make_run())
    assert "No Conditional Access policies were collected" in page and inspect(page).errors == []


# ---- Mermaid -----------------------------------------------------------------------------

def test_mermaid_structure_is_safe_even_with_hostile_names():
    source = ca_report.render_mermaid(build_run().policies, include_disabled=True)
    quotes = {"U": 4, "C": 2, "X": 2, "P": 4, "E": 2}      # raw quotes allowed per statement type
    for line in source.splitlines():
        stripped = line.strip()
        if stripped and stripped[0] in quotes and not stripped.startswith(("%%", "classDef", "class ")):
            assert stripped.count('"') == quotes[stripped[0]], stripped
    assert "<script" not in source.replace("<br/>", "") and "#lt;script#gt;" in source
    assert source.startswith("flowchart LR")


def test_mermaid_leaves_disabled_policies_out_by_default():
    run = build_run()
    assert "Retired" not in ca_report.render_mermaid(run.policies)
    assert "Retired" in ca_report.render_mermaid(run.policies, include_disabled=True)


def test_mermaid_colours_follow_state_and_action():
    lines = [line.strip() for line in ca_report.render_mermaid(build_run().policies).splitlines()]
    assert any(line.startswith("class P") and line.endswith("enabled;") for line in lines)
    assert any(line.startswith("class P") and line.endswith("reportOnly;") for line in lines)
    assert any(line.startswith("class A") and line.endswith("grant;") for line in lines)
    assert any(line.startswith("class A") and line.endswith("block;") for line in lines)


def test_mermaid_with_nothing_to_show():
    assert 'EMPTY["No enabled or report-only policies"]' in ca_report.render_mermaid([])


def test_the_markdown_export_wraps_the_diagram_for_github():
    text = ca_report.render_mermaid_markdown(build_run())
    assert "```mermaid\nflowchart LR" in text and text.rstrip().endswith("```") and "tenant" in text and "Legend" in text


@pytest.mark.parametrize("raw,expected", [('a"b', "a#quot;b"), ("<b>", "#lt;b#gt;"), ("a&b", "a#amp;b"), ("#1", "#35;1"), ("`x`", "'x'"), ("a\nb", "a b")])
def test_mermaid_labels_are_entity_encoded(raw, expected):
    assert ca_report._mm(raw) == expected


def test_long_labels_are_shortened():
    assert len(ca_report._mm("x" * 500, 70)) == 70
