"""Conditional Access report: a self-contained HTML page and a Mermaid diagram.

Pure functions (no I/O): they turn the ``PolicyProfile`` objects already stored on an
``AuditRun`` into text. ``reports.py`` writes the files.

``render_html(run)``                one offline HTML page: overview, baseline gaps, a flow
                                    diagram of every policy, searchable policy cards, and
                                    the Mermaid source.
``render_mermaid(policies)``        Mermaid flowchart source (Who -> Policy -> Outcome).
``render_mermaid_markdown(run)``    that diagram in a Markdown file (GitHub renders it).

Design notes
    * The HTML loads NOTHING from the network: no CDN scripts, no fonts, no images. A
      Content-Security-Policy meta tag enforces it. The report describes your tenant's
      weaknesses, so it must not phone home or run third-party code. The diagram is drawn
      with plain HTML/CSS; the Mermaid source is included for pasting into docs.
    * Every piece of tenant data (policy names, group names, ...) is HTML-escaped, and
      Mermaid labels are entity-encoded, so a hostile policy name can't inject markup or
      change the diagram's structure.
"""

from __future__ import annotations

import html
import re
from datetime import datetime
from typing import Iterable

from . import __version__
from .checks._common import SEVERITY_ORDER
from .checks.ca_analysis import PolicyProfile
from .engine import AuditRun
from .models import Finding

STATE_INFO = {
    "enabled": ("On", "on", "enabled"),
    "enabledForReportingButNotEnforced": ("Report-only", "report", "reportOnly"),
    "disabled": ("Off", "off", "disabled"),
}
ACTION_INFO = {
    "block": ("Block", "block"),
    "grant": ("Grant", "grant"),
    "session_only": ("Session controls", "session"),
    "no_effect": ("No effect", "none"),
}
_STATE_RANK = {"enabled": 0, "enabledForReportingButNotEnforced": 1, "disabled": 2}


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _ordered(policies: Iterable[PolicyProfile]) -> list[PolicyProfile]:
    """Enforced first, then report-only, then disabled; alphabetical within each."""
    return sorted(policies, key=lambda p: (_STATE_RANK.get(p.state, 3), p.name.lower()))


def _state(p: PolicyProfile) -> tuple[str, str, str]:
    return STATE_INFO.get(p.state, (p.state, "off", "disabled"))


def requirement_text(p: PolicyProfile) -> str:
    if p.action == "block":
        return "Block access"
    # "Require A OR B" reads better than "Require A OR Require B".
    reqs = p.requirements[:1] + [r.removeprefix("Require ") for r in p.requirements[1:]]
    if p.requirement_logic == "all":
        return " AND ".join(reqs) + " (all must be satisfied)"
    if p.requirement_logic == "any":
        return " OR ".join(reqs) + " (any one is enough)"
    return "; ".join(p.requirements) or "-"


def _exclusion_bits(p: PolicyProfile) -> list[str]:
    ex, bits = p.exclusions, []
    if ex.users:
        bits.append(f"{len(ex.users)} user(s)")
    if ex.groups:
        bits.append(f"{len(ex.groups)} group(s)")
    if ex.roles:
        bits.append(f"{len(ex.roles)} role(s)")
    if ex.guests_or_external:
        bits.append("guests")
    if ex.applications:
        bits.append(f"{len(ex.applications)} app(s)")
    return bits


def _exclusion_lines(p: PolicyProfile) -> list[str]:
    ex, lines = p.exclusions, []
    if ex.users:
        lines.append("Users: " + ", ".join(u.label for u in ex.users))
    if ex.groups:
        lines.append("Groups: " + ", ".join(g.label for g in ex.groups))
    if ex.roles:
        lines.append("Directory roles: " + ", ".join(r.label for r in ex.roles))
    if ex.guests_or_external:
        lines.append("Guest and external users")
    if ex.applications:
        lines.append("Apps: " + ", ".join(a.label for a in ex.applications))
    return lines


def _worst(p: PolicyProfile) -> str | None:
    return max((c.severity for c in p.concerns), key=SEVERITY_ORDER.index) if p.concerns else None


# --------------------------------------------------------------------------- #
# Mermaid
# --------------------------------------------------------------------------- #

_MERMAID_CLASSES = (
    "classDef enabled fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724;",
    "classDef reportOnly fill:#fff3cd,stroke:#ffc107,stroke-width:2px,color:#856404;",
    "classDef disabled fill:#e9ecef,stroke:#6c757d,stroke-width:2px,color:#495057;",
    "classDef block fill:#f8d7da,stroke:#dc3545,stroke-width:2px,color:#721c24;",
    "classDef grant fill:#d1ecf1,stroke:#17a2b8,stroke-width:2px,color:#0c5460;",
    "classDef session fill:#e2d9f3,stroke:#6f42c1,stroke-width:2px,color:#432874;",
    "classDef note fill:#ffffff,stroke:#adb5bd,color:#495057;",
)


def _mm(text: object, limit: int = 70) -> str:
    """Make arbitrary text safe inside a quoted Mermaid label."""
    value = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()
    if len(value) > limit:
        value = value[: limit - 1] + "\u2026"
    return (
        value.replace("#", "#35;")  # first: '#' starts an entity
        .replace("&", "#amp;")
        .replace('"', "#quot;")
        .replace("<", "#lt;")
        .replace(">", "#gt;")
        .replace("`", "'")  # a leading backtick would switch Mermaid to markdown-string mode
    )


def render_mermaid(policies: Iterable[PolicyProfile], include_disabled: bool = False) -> str:
    """Flowchart source: [Who] -> {Policy} -> [Outcome], with 'applies to' and 'except' notes."""
    lines = ["flowchart LR", *(f"    {c}" for c in _MERMAID_CLASSES), ""]
    shown = 0
    for p in _ordered(policies):
        if p.state == "disabled" and not include_disabled:
            continue
        i = shown
        shown += 1
        state_label, _, state_class = _state(p)

        who = _mm("; ".join(p.users), 80)
        bits = _exclusion_bits(p)
        if bits:
            who += f"<br/>except {_mm(', '.join(bits), 60)}"
        scope = f"apps: {_mm('; '.join(p.applications), 70)}"
        if p.conditions:
            scope += f"<br/>when: {_mm('; '.join(p.conditions), 90)}"
        policy = f"{_mm(p.name, 60)}<br/>[{state_label}]"

        lines.append(f"    %% Policy {i + 1}")
        lines.append(f'    U{i}(["{who}"]) --> P{i}{{"{policy}"}}')
        lines.append(f'    C{i}>"{scope}"] -.-> P{i}')
        if bits:
            lines.append(f'    X{i}>"except: {_mm("; ".join(_exclusion_lines(p)), 100)}"] -.-> P{i}')

        outcome = _mm(requirement_text(p) if p.action != "session_only"
                      else "; ".join(p.session_controls), 100)
        if p.action == "block":
            lines.append(f'    P{i} -->|"BLOCK"| A{i}[/"{outcome}"/]')
            action_class = "block"
        elif p.action == "grant":
            lines.append(f'    P{i} -->|"REQUIRE"| A{i}["{outcome}"]')
            action_class = "grant"
        elif p.action == "session_only":
            lines.append(f'    P{i} -->|"APPLY"| A{i}["{outcome}"]')
            action_class = "session"
        else:
            lines.append(f'    P{i} -->|"NONE"| A{i}["No grant or session controls"]')
            action_class = "disabled"

        lines.append(f"    class P{i} {state_class};")
        lines.append(f"    class A{i} {'disabled' if p.state == 'disabled' else action_class};")
        lines.append(f"    class C{i}{f',X{i}' if bits else ''} note;")
        lines.append("")

    if shown == 0:
        lines.append('    EMPTY["No enabled or report-only policies"]')
    return "\n".join(lines).rstrip() + "\n"


def render_mermaid_markdown(run: AuditRun, include_disabled: bool = False) -> str:
    policies = [p for p in run.policies if include_disabled or p.state != "disabled"]
    return (
        "# Conditional Access Policy Architecture\n\n"
        f"> Generated {run.started_at:%Y-%m-%d %H:%M} UTC by entra-auditor {__version__}  \n"
        f"> Tenant `{run.tenant_id}` | **Policies shown:** {len(policies)}\n\n"
        "## Legend\n"
        "- **Green:** policy enabled\n"
        "- **Yellow:** report-only (logged, not enforced)\n"
        "- **Grey:** disabled\n"
        "- **Red:** explicit block\n"
        "- **Blue:** grant requirements (MFA, compliant device, ...)\n"
        "- **Purple:** session controls\n\n"
        "## Diagram\n\n"
        f"```mermaid\n{render_mermaid(run.policies, include_disabled)}```\n"
    )


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1f2430;--muted:#667085;--line:#e3e6ec;--accent:#2563eb;
--on:#166534;--on-bg:#dcfce7;--report:#92400e;--report-bg:#fef3c7;--off:#4b5563;--off-bg:#eceef2;
--block:#b91c1c;--block-bg:#fee2e2;--grant:#075985;--grant-bg:#e0f2fe;--session:#5b21b6;--session-bg:#ede9fe;
--critical:#fff;--critical-bg:#b91c1c;--high:#b91c1c;--high-bg:#fee2e2;--medium:#92400e;--medium-bg:#fef3c7;
--low:#155e75;--low-bg:#cffafe;--info:#4b5563;--info-bg:#eceef2}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b24;--fg:#e6e9ef;--muted:#9aa3b2;--line:#262c38;
--accent:#6ea8fe;--on:#86efac;--on-bg:#12301f;--report:#fcd34d;--report-bg:#3a2e0b;--off:#b6bdca;--off-bg:#232833;
--block:#fca5a5;--block-bg:#3b1618;--grant:#7dd3fc;--grant-bg:#0c2a3a;--session:#c4b5fd;--session-bg:#27204a;
--high:#fca5a5;--high-bg:#3b1618;--medium:#fcd34d;--medium-bg:#3a2e0b;--low:#67e8f9;--low-bg:#0b2f36;
--info:#b6bdca;--info-bg:#232833}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--accent)}
.wrap{max-width:1100px;margin:0 auto;padding:24px 20px 64px}
header.top{margin-bottom:20px}
h1{margin:0 0 4px;font-size:26px}h2{margin:32px 0 12px;font-size:19px}h3{margin:0;font-size:17px}
.muted{color:var(--muted)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat b{display:block;font-size:24px;line-height:1.2}.stat span{color:var(--muted);font-size:13px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.b-on{background:var(--on-bg);color:var(--on)}.b-report{background:var(--report-bg);color:var(--report)}
.b-off,.b-none{background:var(--off-bg);color:var(--off)}.b-block{background:var(--block-bg);color:var(--block)}
.b-grant{background:var(--grant-bg);color:var(--grant)}.b-session{background:var(--session-bg);color:var(--session)}
.sev-critical{background:var(--critical-bg);color:var(--critical)}.sev-high{background:var(--high-bg);color:var(--high)}
.sev-medium{background:var(--medium-bg);color:var(--medium)}.sev-low{background:var(--low-bg);color:var(--low)}
.sev-info{background:var(--info-bg);color:var(--info)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:10px}
.gap{display:flex;gap:12px;align-items:flex-start}.gap p{margin:4px 0 0}
.gap>.badge{flex:0 0 74px;text-align:center}
.chip{display:inline-block;background:var(--off-bg);color:var(--off);border-radius:6px;padding:1px 7px;margin:2px 4px 2px 0;font-size:12px}
.flow-row{display:grid;grid-template-columns:1fr auto 1.2fr auto 1fr;gap:8px;align-items:center;margin-bottom:10px}
.node{border:2px solid var(--line);border-radius:10px;padding:8px 10px;font-size:13px;background:var(--card);overflow-wrap:anywhere}
.node small{display:block;color:var(--muted);margin-top:2px}
.node.who{border-radius:999px;text-align:center}.node.pnode a{color:inherit;text-decoration:none;font-weight:600}
.node.pnode.on{background:var(--on-bg);border-color:var(--on)}.node.pnode.report{background:var(--report-bg);border-color:var(--report)}
.node.pnode.off{background:var(--off-bg);border-color:var(--off);border-style:dashed}
.node.out.block{background:var(--block-bg);border-color:var(--block)}.node.out.grant{background:var(--grant-bg);border-color:var(--grant)}
.node.out.session{background:var(--session-bg);border-color:var(--session)}.node.out.none{background:var(--off-bg);border-color:var(--off)}
.arrow{color:var(--muted);font-size:18px;text-align:center}
.flow-hint{font-size:12px;color:var(--muted);text-align:center;margin:-4px 0 6px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.toolbar input[type=search],.toolbar select{padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:inherit}
.toolbar input[type=search]{flex:1;min-width:200px}
button{padding:7px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:inherit;cursor:pointer}
.policy header{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:6px}.policy header h3{flex:1;min-width:200px}
.policy .short{margin:0 0 8px}
details>summary{cursor:pointer;color:var(--accent);font-size:14px}
dl{display:grid;grid-template-columns:110px 1fr;gap:6px 14px;margin:10px 0 0}
dt{font-weight:600;color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}dd div+div{margin-top:2px}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:14px}
th,td{text-align:left;padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
pre{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;font-size:12.5px}
footer{margin-top:40px;color:var(--muted);font-size:13px}
@media (max-width:760px){.flow-row{grid-template-columns:1fr}.arrow{transform:rotate(90deg)}dl{grid-template-columns:1fr}}
@media print{body{background:#fff}.toolbar,button{display:none}.card,.stat,.node{break-inside:avoid}}
"""

_JS = """
(function () {
  var cards = [].slice.call(document.querySelectorAll('article.policy'));
  var q = document.getElementById('q'), st = document.getElementById('f-state'),
      ac = document.getElementById('f-action'), cn = document.getElementById('f-concerns'),
      count = document.getElementById('count');
  function apply() {
    var t = q.value.toLowerCase(), n = 0;
    cards.forEach(function (c) {
      var ok = (!t || c.dataset.search.indexOf(t) > -1) && (!st.value || c.dataset.state === st.value) &&
               (!ac.value || c.dataset.action === ac.value) && (!cn.checked || c.dataset.concerns !== '0');
      c.hidden = !ok; if (ok) n++;
    });
    count.textContent = n + ' of ' + cards.length + ' policies';
  }
  [q, st, ac, cn].forEach(function (el) { el.addEventListener('input', apply); });
  function setOpen(v) { cards.forEach(function (c) { var d = c.querySelector('details'); if (d) d.open = v; }); }
  document.getElementById('expand').addEventListener('click', function () { setOpen(true); });
  document.getElementById('collapse').addEventListener('click', function () { setOpen(false); });
  window.addEventListener('beforeprint', function () { setOpen(true); });
  var copy = document.getElementById('copy');
  if (copy && navigator.clipboard) {
    copy.addEventListener('click', function () {
      navigator.clipboard.writeText(document.getElementById('mermaid-src').textContent);
      copy.textContent = 'Copied';
    });
  } else if (copy) { copy.hidden = true; }
  apply();
})();
"""


def _badge(css: str, text: str) -> str:
    return f'<span class="badge {css}">{_e(text)}</span>'


def _sev_badge(severity: str, text: str | None = None) -> str:
    return _badge(f"sev-{severity}", text or severity.upper())


def _ca_gaps(run: AuditRun) -> list[Finding]:
    """Tenant-level Conditional Access / MFA findings (baseline gaps), worst first."""
    gaps = [f for f in run.findings
            if f.resource_type == "tenant" and f.check_id.startswith(("CA_", "MFA_"))]
    return sorted(gaps, key=lambda f: -SEVERITY_ORDER.index(f.severity))


def _stats(run: AuditRun, gaps: list[Finding]) -> str:
    ps = run.policies
    boxes = [
        ("Policies", len(ps)),
        ("Enforced", sum(p.state == "enabled" for p in ps)),
        ("Report-only", sum(p.is_report_only for p in ps)),
        ("Disabled", sum(p.state == "disabled" for p in ps)),
        ("Block rules", sum(p.action == "block" and p.state != "disabled" for p in ps)),
        ("Baseline gaps", sum(g.severity != "info" for g in gaps)),
        ("Policy concerns", sum(len(p.concerns) for p in ps if p.state != "disabled")),
    ]
    return '<div class="stats">' + "".join(
        f'<div class="stat"><b>{n}</b><span>{_e(label)}</span></div>' for label, n in boxes
    ) + "</div>"


def _gaps_html(gaps: list[Finding]) -> str:
    if not gaps:
        return '<div class="card">No tenant-level gaps found against the recommended baseline.</div>'
    out = []
    for g in gaps:
        closest = g.evidence.get("closest_policies") or []
        chips = "".join(f'<span class="chip">{_e(c.get("name", ""))} ({_e(c.get("state", ""))})</span>'
                        for c in closest if isinstance(c, dict))
        out.append(
            '<div class="card gap">' + _sev_badge(g.severity)
            + f'<div><strong>{_e(g.title)}</strong>'
            + (f'<p class="muted">{_e(g.remediation)}</p>' if g.remediation else "")
            + (f'<p>Closest: {chips}</p>' if chips else "")
            + "</div></div>"
        )
    return "".join(out)


def _flow_html(policies: list[PolicyProfile], include_disabled: bool) -> str:
    rows = []
    for i, p in enumerate(_ordered(policies)):
        if p.state == "disabled" and not include_disabled:
            continue
        _, state_css, _ = _state(p)
        _, action_css = ACTION_INFO[p.action]
        bits = _exclusion_bits(p)
        who = _e("; ".join(p.users)) + (f"<small>except {_e(', '.join(bits))}</small>" if bits else "")
        outcome = requirement_text(p) if p.action != "session_only" else "; ".join(p.session_controls)
        when = f"<small>when {_e('; '.join(p.conditions))}</small>" if p.conditions else ""
        rows.append(
            '<div class="flow-row">'
            f'<div class="node who">{who}</div><div class="arrow">&rarr;</div>'
            f'<div class="node pnode {state_css}"><a href="#policy-{i}">{_e(p.name)}</a>'
            f'<small>{_e(_state(p)[0])} &middot; {_e("; ".join(p.applications))}</small>{when}</div>'
            f'<div class="arrow">&rarr;</div>'
            f'<div class="node out {action_css}">{_e(ACTION_INFO[p.action][0].upper())}'
            f'<small>{_e(outcome)}</small></div></div>'
        )
    return "".join(rows) or '<div class="card">No enabled or report-only policies.</div>'


def _policy_html(i: int, p: PolicyProfile) -> str:
    state_label, state_css, _ = _state(p)
    action_label, action_css = ACTION_INFO[p.action]
    worst = _worst(p)
    badges = _badge(f"b-{state_css}", state_label) + _badge(f"b-{action_css}", action_label)
    if worst:
        badges += _sev_badge(worst, f"{len(p.concerns)} concern(s)" if worst != "info" else "note")

    ex_lines = _exclusion_lines(p)
    dates = " &middot; ".join(
        f"{label} {d:%Y-%m-%d}" for label, d in (("created", p.created_at), ("modified", p.modified_at)) if d
    )
    rows = [
        ("Who", "".join(f"<div>{_e(u)}</div>" for u in p.users)),
        ("Except", "".join(f"<div>{_e(x)}</div>" for x in ex_lines) or '<span class="muted">nobody is excluded</span>'),
        ("Apps", "".join(f"<div>{_e(a)}</div>" for a in p.applications)),
        ("When", "".join(f"<div>{_e(c)}</div>" for c in p.conditions)
                 or '<span class="muted">always (no extra conditions)</span>'),
        ("Then", f"<div>{_e(requirement_text(p))}</div>"),
    ]
    if p.session_controls:
        rows.append(("Session", "".join(f"<div>{_e(s)}</div>" for s in p.session_controls)))
    if p.tags:
        rows.append(("Purpose", "".join(f'<span class="chip">{_e(t.value)}</span>' for t in p.tags)))
    if dates:
        rows.append(("History", f'<span class="muted">{dates}</span>'))
    breakdown = "<dl>" + "".join(f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>"

    concerns = ""
    if p.concerns:
        ordered = sorted(p.concerns, key=lambda c: -SEVERITY_ORDER.index(c.severity))
        concerns = (
            "<table><thead><tr><th>Severity</th><th>Issue</th><th>How to fix</th></tr></thead><tbody>"
            + "".join(
                f"<tr><td>{_sev_badge(c.severity)}</td><td>{_e(c.text)}</td><td>{_e(c.remediation or '-')}</td></tr>"
                for c in ordered
            )
            + "</tbody></table>"
        )

    search = " ".join([p.name, p.summary, *p.users, *p.applications, *p.conditions,
                       *(t.value for t in p.tags), *ex_lines]).lower()
    return (
        f'<article class="card policy" id="policy-{i}" data-state="{_e(p.state)}" data-action="{_e(p.action)}" '
        f'data-concerns="{len(p.concerns)}" data-search="{_e(search)}">'
        f"<header><h3>{_e(p.name)}</h3>{badges}</header>"
        f'<p class="short">{_e(p.summary)}</p>'
        f"<details><summary>Full breakdown</summary>{breakdown}{concerns}</details></article>"
    )


def render_html(run: AuditRun, include_disabled: bool = True) -> str:
    gaps = _ca_gaps(run)
    ordered = _ordered(run.policies)
    mermaid = render_mermaid(run.policies, include_disabled=False)

    body = [
        '<header class="top"><h1>Conditional Access report</h1>'
        f'<div class="muted">Tenant {_e(run.tenant_id)} &middot; audit run {run.started_at:%Y-%m-%d %H:%M} UTC'
        f'{(" &middot; " + _e(run.identity)) if run.identity else ""}</div></header>',
        _stats(run, gaps),
        "<h2>Baseline gaps</h2>",
        '<p class="muted">Recommended protections that are missing, partial, or not yet enforced.</p>',
        _gaps_html(gaps),
        "<h2>Policy map</h2>",
        '<p class="flow-hint">Who it applies to &rarr; the policy &rarr; what happens. '
        "Click a policy name to jump to its breakdown.</p>",
        _flow_html(ordered, include_disabled=False),
        "<h2>Policies in plain English</h2>",
        '<div class="toolbar">'
        '<input type="search" id="q" placeholder="Search policies, users, apps, conditions..." aria-label="Search">'
        '<select id="f-state" aria-label="State"><option value="">Any state</option>'
        '<option value="enabled">On</option><option value="enabledForReportingButNotEnforced">Report-only</option>'
        '<option value="disabled">Off</option></select>'
        '<select id="f-action" aria-label="Action"><option value="">Any action</option>'
        '<option value="block">Block</option><option value="grant">Grant</option>'
        '<option value="session_only">Session controls</option><option value="no_effect">No effect</option></select>'
        '<label><input type="checkbox" id="f-concerns"> with concerns</label>'
        '<button type="button" id="expand">Expand all</button><button type="button" id="collapse">Collapse all</button>'
        '<span class="muted" id="count"></span></div>',
        "".join(_policy_html(i, p) for i, p in enumerate(ordered)
                if include_disabled or p.state != "disabled") or
        '<div class="card">No Conditional Access policies were collected in this run '
        "(none exist, or the mfa_ca check was not run).</div>",
        "<h2>Mermaid source</h2>",
        '<p class="muted">Paste into GitHub, GitLab, Notion or <a href="https://mermaid.live">mermaid.live</a> '
        "to get an editable diagram.</p>",
        '<details><summary>Show diagram source</summary><p><button type="button" id="copy">Copy</button></p>'
        f'<pre id="mermaid-src">{_e(mermaid)}</pre></details>',
        f"<footer>Generated by entra-auditor {_e(__version__)}. Contains sensitive tenant details: "
        "share carefully. This page loads no external resources.</footer>",
    ]

    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        '<meta name="color-scheme" content="light dark">'
        f"<title>Conditional Access report - {_e(run.tenant_id)}</title><style>{_CSS}</style></head>"
        f'<body><div class="wrap">{"".join(body)}</div><script>{_JS}</script></body></html>\n'
    )
