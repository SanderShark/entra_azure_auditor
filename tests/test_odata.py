import pytest

from entra_auditor.toolkit import odata


def test_literal_doubles_single_quotes():
    assert odata.literal("O'Brien") == "'O''Brien'"


def test_injection_attempt_stays_a_single_literal():
    assert odata.literal("x' or 1 eq 1 or 'y") == "'x'' or 1 eq 1 or ''y'"


def test_guest_upn_hash_is_encoded_in_url_paths():
    # an unencoded '#' would cut the URL off at a fragment
    assert odata.segment("a_b.com#EXT#@t.onmicrosoft.com") == "a_b.com%23EXT%23%40t.onmicrosoft.com"


def test_search_term_escapes_quotes_and_backslashes():
    assert odata.search_term('a"b\\c') == 'a\\"b\\\\c'


def test_guid_detection():
    assert odata.is_guid("123e4567-e89b-12d3-a456-426614174000")
    assert not odata.is_guid("not-a-guid")
    assert not odata.is_guid("123e4567e89b12d3a456426614174000")


@pytest.mark.parametrize("bad", ["", "   ", "a\x00b", "x" * 300])
def test_clean_query_rejects_unusable_input(bad):
    with pytest.raises(ValueError):
        odata.clean_query(bad)


def test_clean_query_collapses_whitespace():
    assert odata.clean_query("  bob \t  stone ") == "bob stone"


def test_looks_like_email():
    assert odata.looks_like_email("a@b.com")
    assert not odata.looks_like_email("a b@c")
    assert not odata.looks_like_email("plain")
