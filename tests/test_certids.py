import pytest

from entra_auditor.toolkit import certids
from entra_auditor.toolkit.certids import CertIdError


def test_prefix_is_prefilled():
    assert certids.build_cert_id("pn", "bob@contoso.com") == "X509:<PN>bob@contoso.com"


@pytest.mark.parametrize("key,value,expected", [
    ("rfc822", "u@x.com", "X509:<RFC822>u@x.com"),
    ("ski", "ab cd ef 12", "X509:<SKI>abcdef12"),               # spaces in pure hex are removed
    ("thumbprint", "AB:CD:EF:01", "X509:<SHA1-PUKEY>ABCDEF01"),  # alias + colons removed
    ("subject", "CN=user", "X509:<S>CN=user"),
])
def test_single_value_bindings(key, value, expected):
    assert certids.build_cert_id(key, value) == expected


def test_two_part_bindings():
    assert certids.build_cert_id("issuer-serial", {"issuer": "DC=com,CN=CA", "serial": "11 22"}) == \
        "X509:<I>DC=com,CN=CA<SR>11 22"
    assert certids.build_cert_id("issuer-subject", {"issuer": "CN=CA", "subject": "CN=u"}) == \
        "X509:<I>CN=CA<S>CN=u"


def test_surrounding_quotes_and_whitespace_are_stripped():
    assert certids.build_cert_id("pn", '  "bob@x.com" ') == "X509:<PN>bob@x.com"


def test_non_hex_values_are_not_mangled():
    assert certids.build_cert_id("ski", "aB1c-D2e=") == "X509:<SKI>aB1c-D2e="


@pytest.mark.parametrize("bad", ["a<SR>b", "a>b", "a\nb", "  ", ""])
def test_values_that_could_corrupt_the_entry_are_rejected(bad):
    with pytest.raises(CertIdError):
        certids.build_cert_id("pn", bad)


def test_two_part_binding_needs_every_value():
    with pytest.raises(CertIdError):
        certids.build_cert_id("issuer-serial", "just one value")
    with pytest.raises(CertIdError):
        certids.build_cert_id("issuer-serial", {"issuer": "CN=CA"})


def test_unknown_binding():
    with pytest.raises(CertIdError, match="Unknown binding"):
        certids.get_binding("nope")


def test_full_entries_are_validated_and_prefix_is_case_sensitive():
    assert certids.normalise_full_entry("X509:<PN>a@b.com") == "X509:<PN>a@b.com"
    with pytest.raises(CertIdError):
        certids.normalise_full_entry("x509:<pn>a@b.com")
    with pytest.raises(CertIdError):
        certids.normalise_full_entry("hello")


@pytest.mark.parametrize("entry,label", [
    ("X509:<PN>a", "PrincipalName"),
    ("X509:<SHA1-PUKEY>abc", "SHA1 public key (thumbprint)"),
    ("X509:<I>a<SR>b", "Issuer + serial number"),
    ("X509:<I>a<S>b", "Issuer + subject"),
    ("X509:<S>a", "Subject"),
    ("something else", "Unrecognised"),
])
def test_describe_entry(entry, label):
    assert certids.describe_entry(entry) == label


def test_merge_does_not_duplicate():
    assert certids.merge_cert_ids(["a", "b"], ["b", "c"]) == (["a", "b", "c"], ["c"], ["b"])


def test_remove_reports_what_was_missing():
    assert certids.remove_cert_ids(["a", "b"], ["b", "z"]) == (["a"], ["b"], ["z"])
