from __future__ import annotations

import re

from ldap3.utils.conv import escape_filter_chars

PHONE_CHARS = re.compile(r"[+\d\s().-]+")


def is_phone_like(username: str | None) -> bool:
    """True for values such as ``+44 7700 900123``.

    Stealer logs often contain consumer logins (phone numbers) next to
    corporate ones; those cannot be mapped to an employee and are skipped.
    """
    if not username or "@" in username:
        return False
    value = username.strip()
    if not PHONE_CHARS.fullmatch(value):
        return False
    return 10 <= len(re.sub(r"\D", "", value)) <= 15


def normalize_ldap_search_value(username: str) -> str:
    """Strip the admin-account suffixes (``-ca`` / ``_ca``) used for privileged accounts."""
    cleaned = username.strip()
    for suffix in ("-ca", "_ca"):
        cleaned = cleaned.replace(suffix, "")
    return cleaned


def user_filters(username: str) -> list[tuple[str, str]]:
    """LDAP filters tried in order to find the directory entry of a leaked login.

    All user input is escaped, including in the wildcard filters.
    """
    clean = username.strip()
    sam = escape_filter_chars(clean.split("@")[0].split("\\")[-1])
    exact = escape_filter_chars(clean)
    base_name = escape_filter_chars(normalize_ldap_search_value(clean.split("@")[0]))
    return [
        ("sAMAccountName", f"(sAMAccountName={sam})"),
        ("userPrincipalName", f"(userPrincipalName={exact})"),
        ("mail", f"(mail={exact})"),
        (
            "sAMAccountName/displayName contains",
            f"(|(sAMAccountName=*{sam}*)(displayName=*{sam}*))",
        ),
        ("cn contains (admin suffix removed)", f"(&(objectCategory=person)(cn=*{base_name}*))"),
    ]


def manager_filters(manager_name: str) -> list[tuple[str, str]]:
    name = escape_filter_chars(manager_name.strip())
    return [
        ("cn", f"(cn={name})"),
        ("displayName", f"(displayName={name})"),
        ("cn/displayName contains", f"(|(cn=*{name}*)(displayName=*{name}*))"),
    ]


def cn_from_dn(dn: str) -> str:
    first = dn.split(",", 1)[0]
    return first.split("=", 1)[1].strip() if "=" in first else first.strip()
