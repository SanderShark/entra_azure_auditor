"""Loading the whole user directory once (toolkit/directory.py)."""

import pytest

from entra_auditor.graph.client import GraphError
from entra_auditor.toolkit.directory import PAGE_SIZE, LoadCancelled, load_users
from entra_auditor.toolkit.search import USER_SELECT
from tests.fakes import FakeGraph, FakeTenant


def many(n):
    return [{"id": f"u{i}", "displayName": f"User {i:05d}", "userPrincipalName": f"u{i}@contoso.com"} for i in range(n)]


def test_it_asks_for_few_properties_and_the_largest_page():
    graph = FakeGraph({"/users": many(3)})
    load_users(graph)
    [(path, kw)] = graph.calls
    assert path == "/users" and kw["select"] == USER_SELECT and kw["top"] == PAGE_SIZE == 999


def test_every_user_is_returned_sorted_by_name():
    users = load_users(FakeTenant())
    names = [u.display_name for u in users]
    assert len(users) == 8 and names == sorted(names, key=str.casefold)
    alice = next(u for u in users if u.upn == "alice@contoso.com")
    assert alice.department == "IT" and alice.account_enabled is True


def test_progress_is_reported_once_per_page_and_at_the_end():
    seen = []
    load_users(FakeGraph({"/users": many(2 * PAGE_SIZE + 5)}), on_progress=seen.append)
    assert seen == [PAGE_SIZE, 2 * PAGE_SIZE, 2 * PAGE_SIZE + 5]


def test_an_exact_multiple_of_the_page_size_still_reports_the_final_count():
    seen = []
    load_users(FakeGraph({"/users": many(PAGE_SIZE)}), on_progress=seen.append)
    assert seen[-1] == PAGE_SIZE


def test_an_empty_tenant_is_an_empty_list():
    assert load_users(FakeGraph({"/users": []})) == []


def test_a_failed_load_raises_instead_of_returning_a_partial_list():
    def broken(kw):
        def pages():
            yield from many(3)
            raise GraphError("throttled for too long", status_code=429)
        return pages()

    with pytest.raises(GraphError):
        load_users(FakeGraph({"/users": broken}))


def test_a_load_can_be_cancelled_between_pages():
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return True

    with pytest.raises(LoadCancelled):
        load_users(FakeGraph({"/users": many(PAGE_SIZE + 1)}), should_cancel=cancel)
    assert calls["n"] == 1                      # stopped at the first page boundary


def test_fifty_thousand_users_load_quickly():
    import time
    start = time.perf_counter()
    users = load_users(FakeGraph({"/users": many(50_000)}))
    assert len(users) == 50_000 and time.perf_counter() - start < 5


def test_a_scope_becomes_a_server_side_filter_and_an_unknown_one_is_refused():
    import pytest

    from entra_auditor.toolkit.directory import USER_SCOPES, load_users
    from tests.fakes import FakeTenant
    t = FakeTenant()
    assert len(load_users(t)) == 8 and t.filters == []                       # "all" sends no filter
    assert [u.id for u in load_users(t, scope="guests")] == ["u-guest"] and t.filters[-1] == "userType eq 'Guest'"
    assert [u.id for u in load_users(t, scope="synced")] == ["u-sync"]
    assert len(load_users(t, scope="members")) == 7
    assert set(USER_SCOPES) == {"all", "members", "guests", "synced"}
    with pytest.raises(ValueError, match="Unknown user scope"):
        load_users(t, scope="everyone")


def test_external_users_can_be_left_out_while_loading_and_progress_still_counts_every_page():
    from entra_auditor.toolkit.directory import LoadCancelled, is_external, load_users
    from tests.fakes import FakeTenant, U
    assert is_external("partner_x.com#EXT#@contoso.onmicrosoft.com") and is_external("a_b.com#ext#@c.onmicrosoft.com")
    assert not is_external("ext@contoso.com") and not is_external(None)
    t = FakeTenant()
    for i in range(20):                                         # cross-tenant-synced users are Members with #EXT#
        t.users[f"x{i}"] = U(f"x{i}", f"Synced {i}", f"s{i}_fabrikam.com#EXT#@contoso.onmicrosoft.com")
    assert len(load_users(t)) == 28
    kept = load_users(t, exclude_external=True)
    assert len(kept) == 7 and not any(is_external(u.upn) for u in kept)      # the guest goes as well
    assert len(load_users(t, scope="members", exclude_external=True)) == 7
    seen, checks = [], []
    load_users(t, exclude_external=True, page_size=5, on_progress=seen.append,
               should_cancel=lambda: checks.append(1) and False)
    assert len(checks) >= 5 and seen[-1] == 7                   # checked once per page scanned, not per page kept
    import pytest
    with pytest.raises(LoadCancelled):
        load_users(t, exclude_external=True, page_size=5, should_cancel=lambda: True)
