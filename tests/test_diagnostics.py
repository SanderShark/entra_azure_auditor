"""The tenant check: what a sign-in can do, as a report that is safe to share."""

from __future__ import annotations

import base64
import json

import pytest

from entra_auditor.graph.client import GraphAuthError
from entra_auditor.toolkit import diagnostics as D
from tests.fakes import FakeTenant


def token(**claims):
    def part(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return f"{part({'alg': 'none'})}.{part(claims)}.signature"


TOKEN = token(scp="User.ReadWrite.All Directory.Read.All BitlockerKey.Read.All", exp=1_900_000_000,
              wids=["r-global-reader", "b79fbf4d-3ef9-4689-8143-76b194e85509"], upn="alice@contoso.com",
              tid="11111111-2222-3333-4444-555555555555", name="Alice Ng")


def ticking():
    now = [0.0]

    def clock():
        now[0] += 0.0125
        return now[0]
    return clock


def test_the_token_is_read_locally():
    facts = D.token_facts(TOKEN)
    assert facts.scopes == ["BitlockerKey.Read.All", "Directory.Read.All", "User.ReadWrite.All"]
    assert facts.role_ids == ["b79fbf4d-3ef9-4689-8143-76b194e85509", "r-global-reader"]
    assert facts.expires.year == 2030 and not facts.error
    assert D.token_facts(None).error == "no token available"
    assert D.token_facts("not.a-token").error.startswith("not a readable token")
    assert D.token_facts(token()).scopes == [] and D.token_facts(token()).role_ids == []


def test_every_feature_is_tried_once_and_nothing_is_written():
    t = FakeTenant()
    report = D.run_checks(t, TOKEN, clock=ticking())
    assert [r.outcome for r in report.results] == ["OK"] * len(D.PROBES)
    assert t.writes == [] and all(r.milliseconds == 12 for r in report.results)
    assert report.roles == ["Global Reader", "role b79fbf4d-3ef9-4689-8143-76b194e85509"]    # names resolved
    assert report.optional_present == ["BitlockerKey.Read.All"]
    assert "Member.Read.Hidden" in report.optional_missing


def test_refusals_and_unsupported_queries_are_told_apart_and_explained():
    from entra_auditor.graph.client import GraphError
    t = FakeTenant()
    t.refuse_reads = [r"^/devices$", r"privilegedAccess"]
    real = t.get_paged

    def get_paged(path, **kw):
        if path == "/subscribedSkus":
            raise GraphError("Bad request", status_code=400, code="Request_UnsupportedQuery")
        return real(path, **kw)

    t.get_paged = get_paged
    report = D.run_checks(t, TOKEN)
    by = {r.probe.feature: r for r in report.results}
    assert (by["Devices"].outcome, by["Devices"].detail) == ("DENIED", "HTTP 403 Authorization_RequestDenied")
    assert by["Your eligible PIM groups"].outcome == "DENIED"
    assert by["Licences (subscriptions)"].outcome == "UNSUPPORTED" and by["Users list"].ok
    text = report.text()
    assert "What the failed checks need:" in text and "Devices: Device.Read.All or Directory.Read.All" in text


def test_the_report_names_nobody():
    t = FakeTenant()
    t.refuse_reads = [r"^/groups$"]
    text = D.run_checks(t, TOKEN, read_only=True).text()
    for secret in ("alice", "Alice", "contoso", "11111111-2222", "u-me", "me@"):
        assert secret not in text, secret
    assert "(read-only session)" in text and "Global Reader" in text and "User.ReadWrite.All" in text
    assert "Contains no user names" in text


def test_without_a_readable_token_the_reads_are_still_checked():
    report = D.run_checks(FakeTenant(), None)
    assert report.roles is None and report.optional_present is None
    assert "Token: couldn't be read (no token available)" in report.text()
    assert all(r.ok for r in report.results)


def test_a_failed_sign_in_stops_the_check():
    t = FakeTenant()
    t.get_paged = lambda *a, **k: (_ for _ in ()).throw(GraphAuthError("401", status_code=401))
    with pytest.raises(GraphAuthError):
        D.run_checks(t, TOKEN)


def test_the_session_token_is_taken_only_if_the_provider_offers_one():
    class Provider:
        def get_token(self):
            return TOKEN

    class Broken:
        def get_token(self):
            raise RuntimeError("expired")

    assert D.session_token(type("S", (), {"provider": Provider()})()) == TOKEN
    assert D.session_token(type("S", (), {"provider": Broken()})()) is None
    assert D.session_token(type("S", (), {"provider": object()})()) is None
