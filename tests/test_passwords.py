import pytest

from entra_auditor.toolkit import passwords


def test_generated_passwords_are_valid_and_unique():
    generated = [passwords.generate_password() for _ in range(200)]
    assert all(not passwords.password_problems(p) for p in generated)
    assert len(set(generated)) == len(generated)
    assert all(len(p) == 20 for p in generated)


def test_generated_passwords_avoid_ambiguous_characters():
    generated = "".join(passwords.generate_password() for _ in range(100))
    assert not set(generated) & set("0O1lI")


def test_generator_refuses_short_lengths():
    with pytest.raises(ValueError):
        passwords.generate_password(8)


def test_weak_passwords_are_rejected():
    assert any("at least 3" in p for p in passwords.password_problems("alllowercase"))
    assert passwords.password_problems("Sh0rt!")


def test_spaces_are_rejected():
    assert any("spaces" in p for p in passwords.password_problems("Abc 1234 Xyz!"))


def test_password_containing_the_account_name_is_rejected():
    assert any("account name" in p for p in passwords.password_problems("Bobby-Pass123!", "bobby@x.com"))


def test_a_good_password_has_no_problems():
    assert passwords.password_problems("Str0ng!Passw0rd#9", "alice@x.com") == []
