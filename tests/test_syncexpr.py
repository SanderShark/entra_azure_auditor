"""The expression evaluator behind sync-rule filtering, including Microsoft's own built-in expression."""

from __future__ import annotations

import pytest

from entra_auditor.toolkit.syncexpr import UNKNOWN, ExpressionError, as_filter, evaluate, parse

# The cloudFiltered flow of "In from AD - User Join" from Microsoft's published sample export.
USER_JOIN = ('IIF(IsPresent([isCriticalSystemObject]) || IsPresent([sAMAccountName]) = False || '
             '[sAMAccountName] = "SUPPORT_388945a0" || Left([mailNickname], 14) = "SystemMailbox{" || '
             'Left([sAMAccountName], 4) = "AAD_" || (Left([mailNickname], 4) = "CAS_" && (InStr([mailNickname], "}") > 0)) || '
             '(Left([sAMAccountName], 4) = "CAS_" && (InStr([sAMAccountName], "}") > 0)) || Left([sAMAccountName], 5) = "MSOL_" || '
             'CBool(IIF(IsPresent([msExchRecipientTypeDetails]),BitAnd([msExchRecipientTypeDetails],&H21C07000) > 0,NULL)) || '
             'CBool(InStr(DNComponent(CRef([dn]),1),"\\\\0ACNF:")>0), True, NULL)')


@pytest.mark.parametrize("obj, expected", [
    ({"sAMAccountName": "alice", "dn": "CN=Alice,OU=Staff,DC=contoso,DC=com"}, None),       # an ordinary user
    ({"dn": "CN=NoSam,DC=contoso,DC=com"}, True),                                             # no sAMAccountName
    ({"sAMAccountName": "krbtgt", "isCriticalSystemObject": "TRUE"}, True),
    ({"sAMAccountName": "MSOL_1a2b3c"}, True), ({"sAMAccountName": "MSOLx"}, None),           # "MSOL_" exactly
    ({"sAMAccountName": "AAD_abc"}, True), ({"sAMAccountName": "AADabc"}, None),
    ({"sAMAccountName": "SUPPORT_388945a0"}, True),
    ({"sAMAccountName": "a", "mailNickname": "SystemMailbox{1f05a927}"}, True),
    ({"sAMAccountName": "a", "mailNickname": "CAS_{abc}"}, True), ({"sAMAccountName": "a", "mailNickname": "CAS_abc"}, None),
    ({"sAMAccountName": "a", "msExchRecipientTypeDetails": str(0x1)}, None),                  # a user mailbox: outside the mask
    ({"sAMAccountName": "a", "msExchRecipientTypeDetails": str(0x20000000)}, True),           # a bit inside it
    ({"sAMAccountName": "a", "dn": "CN=Bob\\\\0ACNF:1a2b,OU=Staff,DC=contoso,DC=com"}, True),  # a conflict object
])
def test_microsofts_built_in_user_filter(obj, expected):
    assert as_filter(evaluate(USER_JOIN, obj)) is expected


@pytest.mark.parametrize("expression, obj, expected", [
    ('IIF([extensionAttribute14] = "no0365sync", True, NULL)', {"extensionAttribute14": "NO0365SYNC"}, True),
    ('IIF([extensionAttribute14] = "no0365sync", True, NULL)', {}, None),
    ('IIF(IsNullOrEmpty([userCertificate]),True,NULL)', {}, True),
    ('IIF(IsNullOrEmpty([userCertificate]),True,NULL)', {"userCertificate": ["abc"]}, None),
    ('Left([a], 2) & "-" & Right([a], 2)', {"a": "abcdef"}, "ab-ef"),
    ('Mid([a], 2, 3)', {"a": "abcdef"}, "bcd"), ('Len(Trim([a]))', {"a": "  ab "}, 2),
    ('InStr([a], "CD")', {"a": "abcdef"}, 3), ('InStr([a], "zz")', {"a": "abcdef"}, 0),
    ('BitAnd([uac], 2) > 0', {"uac": "514"}, True), ('BitAnd([uac], 2) > 0', {"uac": "512"}, False),
    ('[a] <> "x"', {"a": "y"}, True), ('1 + 2 = 3', {}, True), ('[n] >= 10', {"n": "10"}, True),
    ('DNComponent(CRef([dn]), 2)', {"dn": "CN=Bob,OU=Staff,DC=x"}, "Staff"),
    ('Contains([memberOf], "g1") > 0', {"memberOf": ["g0", "G1"]}, True),
    ('"say ""hi"""', {}, 'say "hi"'), ('&HFF', {}, 255), ('True && False', {}, False),
])
def test_expressions(expression, obj, expected):
    assert evaluate(expression, obj) == expected


def test_what_is_not_understood_is_unknown_unless_it_cannot_matter():
    assert evaluate('Word([a], 1, " ") = "x"', {"a": "x y"}) is UNKNOWN                 # a function not covered
    assert evaluate('SomeNewFunction([a])', {}) is UNKNOWN
    assert evaluate('True || Word([a], 1, " ") = "x"', {}) is True                       # short-circuit: irrelevant
    assert evaluate('False && Word([a], 1, " ") = "x"', {}) is False
    assert evaluate('Word([a], 1, " ") = "x" || True', {}) is True                       # either side
    assert evaluate('False || Word([a], 1, " ") = "x"', {}) is UNKNOWN
    assert evaluate('IIF(True, 1, Error("no"))', {}) == 1                                # the untaken branch is not run
    assert evaluate('IIF(Word([a],1," ")="x", True, NULL)', {}) is UNKNOWN
    assert evaluate('this is not an expression', {}) is UNKNOWN and evaluate('IIF(', {}) is UNKNOWN
    assert evaluate('[n] > 5', {"n": "five"}) is UNKNOWN
    with pytest.raises(ExpressionError):
        parse('Left([a], 2')
    with pytest.raises(TypeError):
        bool(UNKNOWN)


def test_what_a_result_means_for_filtering():
    assert as_filter(True) is True and as_filter(False) is False and as_filter("True") is True
    assert as_filter(None) is None and as_filter("") is None and as_filter(UNKNOWN) is UNKNOWN
