"""Safe construction of Graph query text from user input.

Anything typed by a person must go through these before it is placed in a $filter,
$search or URL path, otherwise a stray quote changes the meaning of the query.
"""

from __future__ import annotations

import re
from urllib.parse import quote as _urlquote

_GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
MAX_QUERY_LENGTH = 256


def clean_query(value: str) -> str:
    """Trim, collapse whitespace, and reject empty/oversized/control-character input."""
    text = " ".join(str(value).split())
    if not text:
        raise ValueError("The search text is empty.")
    if len(text) > MAX_QUERY_LENGTH:
        raise ValueError(f"The search text is too long (max {MAX_QUERY_LENGTH} characters).")
    if any(ord(c) < 32 for c in text):
        raise ValueError("The search text contains control characters.")
    return text


def literal(value: str) -> str:
    """OData string literal: ``O'Brien`` -> ``'O''Brien'`` (single quotes doubled)."""
    return "'" + str(value).replace("'", "''") + "'"


def search_term(value: str) -> str:
    """Escape text for use inside a ``$search="property:term"`` expression."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def segment(value: str) -> str:
    """Percent-encode one URL path segment. Guest UPNs contain ``#EXT#``; an unencoded ``#``
    would cut the URL off at a fragment."""
    return _urlquote(str(value), safe="")


def is_guid(value: str) -> bool:
    return bool(_GUID.match(str(value).strip()))


def looks_like_email(value: str) -> bool:
    return "@" in value and " " not in value
