import pytest

from entra_auditor.toolkit import search
from entra_auditor.toolkit.search import AmbiguousIdentity, IdentityNotFound

GUID = "11111111-2222-3333-4444-555555555555"


def labels(results):
    return sorted(r.label for r in results)


@pytest.mark.parametrize("query,by", [
    ("alice@contoso.com", "auto"),
    ("ALICE@Contoso.com", "auto"),           # case-insensitive
    ("alice@contoso.com", "upn"),
])
def test_find_by_upn(tenant, query, by):
    assert labels(search.find_users(tenant, query, by=by)) == ["alice@contoso.com"]


def test_find_by_alias_address(tenant):
    found = search.find_users(tenant, "a.ng@contoso.com")
    assert labels(found) == ["alice@contoso.com"] and found[0].matched_by == "proxy address"


def test_find_by_other_mail(tenant):
    assert labels(search.find_users(tenant, "alice@home.example")) == ["alice@contoso.com"]


def test_find_by_employee_id_and_alias(tenant):
    assert labels(search.find_users(tenant, "E100")) == ["alice@contoso.com"]
    assert labels(search.find_users(tenant, "alice", by="alias")) == ["alice@contoso.com"]
    assert labels(search.find_users(tenant, "E100", by="employee")) == ["alice@contoso.com"]


def test_find_by_object_id(tenant):
    found = search.find_users(tenant, GUID)
    assert labels(found) == ["gina@contoso.com"] and found[0].matched_by == "id"


def test_unknown_object_id_is_simply_no_result(tenant):
    assert search.find_users(tenant, "99999999-2222-3333-4444-555555555555") == []


def test_plain_text_combines_alias_match_and_name_matches(tenant):
    # "bob" is an exact alias AND the first name of two people: an exact hit must not hide the other
    assert labels(search.find_users(tenant, "Bob")) == ["bob.smith@contoso.com", "bob@contoso.com"]


def test_partial_email_falls_back_to_prefix(tenant):
    assert "bob@contoso.com" in labels(search.find_users(tenant, "bob@"))


def test_guest_found_by_its_ext_upn(tenant):
    upn = "partner_x.com#EXT#@contoso.onmicrosoft.com"
    assert labels(search.find_users(tenant, upn)) == [upn]


def test_a_quote_in_the_query_is_escaped_not_interpreted(tenant):
    assert search.find_users(tenant, "x' or userType eq 'Guest", by="upn") == []
    assert "'x'' or userType eq ''Guest'" in tenant.filters[-1]


def test_apostrophes_in_names_are_searchable(tenant):
    assert labels(search.find_users(tenant, "O'Brien", by="name")) == ["pat@contoso.com"]


def test_unknown_search_type_is_rejected(tenant):
    with pytest.raises(ValueError, match="Unknown search type"):
        search.find_users(tenant, "x", by="bogus")


def test_resolve_unique(tenant):
    assert search.resolve_user(tenant, "alice@contoso.com").id == "u-alice"
    assert search.resolve_user(tenant, "alice").id == "u-alice"
    assert search.resolve_user(tenant, GUID).label == "gina@contoso.com"


def test_resolve_ambiguous_raises_with_candidates(tenant):
    with pytest.raises(AmbiguousIdentity) as info:
        search.resolve_user(tenant, "Bob")
    assert len(info.value.candidates) == 2


def test_resolve_nothing_raises(tenant):
    with pytest.raises(IdentityNotFound):
        search.resolve_user(tenant, "nobody@nowhere.com")


def test_get_user_and_group_by_id(tenant):
    assert search.get_user(tenant, "u-alice").label == "alice@contoso.com"
    assert search.get_group(tenant, "g-fin").label == "Finance Share"
    with pytest.raises(IdentityNotFound):
        search.get_user(tenant, "nope")
    with pytest.raises(IdentityNotFound):
        search.get_group(tenant, "nope")


def test_group_search_and_kinds(tenant):
    assert [g.label for g in search.find_groups(tenant, "Finance")] == ["Finance Share"]
    assert search.resolve_group(tenant, "Mail-Sec").kind == "mail_enabled_security"
    assert search.resolve_group(tenant, "Dynamic IT").is_dynamic
    assert search.resolve_group(tenant, "Project X").kind == "microsoft365"


def test_group_resolve_none_and_ambiguous(tenant):
    with pytest.raises(IdentityNotFound):
        search.resolve_group(tenant, "No Such Group")


def test_find_apps_returns_nothing_when_there_are_none(tenant):
    assert search.find_apps(tenant, "anything") == []
