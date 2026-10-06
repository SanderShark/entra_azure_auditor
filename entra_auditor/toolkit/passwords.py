"""Password generation and validation (Entra complexity rules)."""

from __future__ import annotations

import secrets
import string

# Visually unambiguous characters (no 0/O, 1/l/I) so a password read out over the phone survives,
# and no quotes/backslashes that break shells or copy-paste.
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_LOWER = "abcdefghijkmnopqrstuvwxyz"
_DIGITS = "23456789"
_SYMBOLS = "!@#$%&*-_+=?"
MIN_LENGTH, MAX_LENGTH = 8, 256


def generate_password(length: int = 20) -> str:
    """Cryptographically random, containing all four character classes."""
    if length < 12:
        raise ValueError("Generated passwords must be at least 12 characters.")
    rng = secrets.SystemRandom()
    chars = [secrets.choice(c) for c in (_UPPER, _LOWER, _DIGITS, _SYMBOLS)]
    pool = _UPPER + _LOWER + _DIGITS + _SYMBOLS
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    rng.shuffle(chars)
    return "".join(chars)


def password_problems(password: str, upn: str | None = None) -> list[str]:
    """Reasons Entra would reject this password (empty list = acceptable)."""
    problems: list[str] = []
    if not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        problems.append(f"must be {MIN_LENGTH}-{MAX_LENGTH} characters")
    classes = sum([
        any(c in string.ascii_uppercase for c in password),
        any(c in string.ascii_lowercase for c in password),
        any(c in string.digits for c in password),
        any(not c.isalnum() and not c.isspace() for c in password),
    ])
    if classes < 3:
        problems.append("must use at least 3 of: uppercase, lowercase, digits, symbols")
    if any(c.isspace() for c in password):
        problems.append("must not contain spaces")
    if upn:
        local = upn.split("@", 1)[0].lower()
        if len(local) >= 3 and local in password.lower():
            problems.append("must not contain the user's account name")
    return problems
