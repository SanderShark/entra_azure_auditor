"""Certificate user IDs (``authorizationInfo.certificateUserIds``) for certificate-based auth.

Entra stores one string per username binding, always starting with a CASE-SENSITIVE prefix
such as ``X509:<SKI>``. The tool pre-fills the prefix so you only paste the certificate data.

    PrincipalName          X509:<PN>user@contoso.com
    RFC822Name             X509:<RFC822>user@contoso.com
    SubjectKeyIdentifier   X509:<SKI>...
    SHA1 public key        X509:<SHA1-PUKEY>...        (the certificate's thumbprint)
    Issuer + serial        X509:<I>IssuerDN<SR>SerialNumber
    Issuer + subject       X509:<I>IssuerDN<S>SubjectDN
    Subject                X509:<S>SubjectDN

Paste each value exactly as your tenant's username-binding policy expects it; the tool only
adds the prefix and tidies obvious paste artefacts (surrounding quotes/whitespace, and
colon/space separators in pure-hex values such as ``AB:CD:EF``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CertBinding:
    key: str
    label: str
    template: str                          # e.g. "X509:<I>{issuer}<SR>{serial}"
    fields: tuple[tuple[str, str], ...]    # (placeholder name, prompt text)
    example: str
    note: str = ""

    @property
    def prefix(self) -> str:
        """The fixed text before the first pasted value, e.g. ``X509:<SKI>``."""
        return self.template.split("{", 1)[0]


BINDINGS: dict[str, CertBinding] = {b.key: b for b in (
    CertBinding("pn", "PrincipalName", "X509:<PN>{value}",
                (("value", "PrincipalName"),), "X509:<PN>bob@woodgrove.com"),
    CertBinding("rfc822", "RFC822Name (email)", "X509:<RFC822>{value}",
                (("value", "Email (RFC822Name)"),), "X509:<RFC822>user@woodgrove.com"),
    CertBinding("ski", "Subject Key Identifier", "X509:<SKI>{value}",
                (("value", "Subject Key Identifier"),), "X509:<SKI>aB1cD2eF3gH4iJ5kL6mN7oP8qR",
                "High-affinity binding."),
    CertBinding("sha1", "SHA1 public key (thumbprint)", "X509:<SHA1-PUKEY>{value}",
                (("value", "Certificate thumbprint"),), "X509:<SHA1-PUKEY>cD2eF3gH4iJ5kL6mN7oP8qR9sT",
                "High-affinity binding. Use the certificate's Thumbprint value."),
    CertBinding("issuer-serial", "Issuer + serial number", "X509:<I>{issuer}<SR>{serial}",
                (("issuer", "Issuer DN (e.g. DC=com,DC=contoso,CN=CONTOSO-DC-CA)"),
                 ("serial", "Serial number")),
                "X509:<I>DC=com,DC=contoso,CN=CONTOSO-DC-CA<SR>eF3gH4iJ5kL6mN7oP8qR9sT0uV",
                "High-affinity binding."),
    CertBinding("issuer-subject", "Issuer + subject", "X509:<I>{issuer}<S>{subject}",
                (("issuer", "Issuer DN"), ("subject", "Subject DN")),
                "X509:<I>DC=com,DC=contoso,CN=CONTOSO-DC-CA<S>DC=com,DC=contoso,OU=UserAccounts,CN=user",
                "Low-affinity binding."),
    CertBinding("subject", "Subject", "X509:<S>{subject}",
                (("subject", "Subject DN"),), "X509:<S>DC=com,DC=contoso,OU=UserAccounts,CN=user",
                "Low-affinity binding."),
)}

ALIASES = {"upn": "pn", "principalname": "pn", "email": "rfc822", "mail": "rfc822",
           "thumbprint": "sha1", "serial": "issuer-serial", "issuer-and-serial": "issuer-serial",
           "issuer-and-subject": "issuer-subject"}

_HEX_WITH_SEPARATORS = re.compile(r"^[0-9A-Fa-f]{2}(?:[ :\-]?[0-9A-Fa-f]{2})+$")
_PREFIXES = sorted(
    ((b.prefix, b) for b in BINDINGS.values()), key=lambda pair: -len(pair[0]))  # longest first
_KNOWN_ENTRY_PREFIXES = ("X509:<PN>", "X509:<RFC822>", "X509:<SKI>", "X509:<SHA1-PUKEY>",
                         "X509:<I>", "X509:<S>")


class CertIdError(ValueError):
    pass


def get_binding(key: str) -> CertBinding:
    k = ALIASES.get(key.strip().lower(), key.strip().lower())
    if k not in BINDINGS:
        raise CertIdError(f"Unknown binding '{key}'. Choose one of: {', '.join(BINDINGS)}")
    return BINDINGS[k]


def clean_value(raw: str, *, binding: CertBinding, field: str) -> str:
    """Tidy one pasted value and reject anything that could corrupt the stored string."""
    value = str(raw).strip().strip("'\"").strip()
    if not value:
        raise CertIdError(f"{field} is empty.")
    if any(ord(c) < 32 for c in value):
        raise CertIdError(f"{field} contains a line break or control character.")
    if "<" in value or ">" in value:
        raise CertIdError(f"{field} must not contain '<' or '>' (the prefix is added for you).")
    if binding.key in ("ski", "sha1") and _HEX_WITH_SEPARATORS.match(value):
        value = re.sub(r"[ :\-]", "", value)  # AB:CD:EF -> ABCDEF
    return value


def build_cert_id(key: str, values: dict[str, str] | str) -> str:
    """Prefix + pasted data -> the string to store, e.g. ``X509:<SKI>aB1c...``."""
    binding = get_binding(key)
    if isinstance(values, str):
        if len(binding.fields) != 1:
            raise CertIdError(f"'{binding.key}' needs {len(binding.fields)} values: "
                              + ", ".join(n for n, _ in binding.fields))
        values = {binding.fields[0][0]: values}
    cleaned = {}
    for name, prompt in binding.fields:
        if name not in values:
            raise CertIdError(f"Missing value: {prompt}")
        cleaned[name] = clean_value(values[name], binding=binding, field=prompt)
    return binding.template.format(**cleaned)


def normalise_full_entry(entry: str) -> str:
    """Accept a complete, already-prefixed entry pasted by the user; validate its prefix."""
    text = str(entry).strip().strip("'\"").strip()
    if not text.startswith(_KNOWN_ENTRY_PREFIXES):
        raise CertIdError("Not a recognised certificate user ID (expected one of: "
                          + ", ".join(p + "..." for p in _KNOWN_ENTRY_PREFIXES) + "). "
                          "Prefixes are case-sensitive.")
    if any(ord(c) < 32 for c in text):
        raise CertIdError("The entry contains a line break or control character.")
    return text


def describe_entry(entry: str) -> str:
    """Human label for a stored entry, e.g. ``Subject Key Identifier``."""
    for prefix, binding in _PREFIXES:
        if entry.startswith(prefix):
            if binding.key in ("issuer-serial", "issuer-subject") and not (
                ("<SR>" in entry) == (binding.key == "issuer-serial")
                and ("<S>" in entry) == (binding.key == "issuer-subject")
            ):
                continue
            return binding.label
    return "Unrecognised"


def merge_cert_ids(existing: list[str], additions: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Append without duplicating. Returns (new list, actually added, already present)."""
    result, added, present = list(existing), [], []
    for item in additions:
        if item in result:
            present.append(item)
        else:
            result.append(item)
            added.append(item)
    return result, added, present


def remove_cert_ids(existing: list[str], removals: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Returns (new list, removed, not found)."""
    result, removed, missing = list(existing), [], []
    for item in removals:
        if item in result:
            result.remove(item)
            removed.append(item)
        else:
            missing.append(item)
    return result, removed, missing
