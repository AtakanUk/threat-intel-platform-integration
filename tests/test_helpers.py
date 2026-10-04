from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from threat_intel_platform_integration.client import LdapManagerResolver
from threat_intel_platform_integration.config import AppConfig
from threat_intel_platform_integration.helpers import (
    cn_from_dn,
    is_phone_like,
    normalize_ldap_search_value,
    user_filters,
)

BASE = "OU=Staff,DC=example,DC=com"


def test_is_phone_like():
    assert is_phone_like("+44 7700 900123")
    assert is_phone_like("(555) 010-0199")
    assert not is_phone_like("j.doe@example.com")
    assert not is_phone_like("jdoe")
    assert not is_phone_like("12345")


def test_filters_escape_user_input():
    filters = dict(user_filters("j*doe)(cn=*@example.com"))
    assert filters["sAMAccountName"] == r"(sAMAccountName=j\2adoe\29\28cn=\2a)"
    assert "*)" not in filters["mail"].replace(r"\2a", "")


def test_helpers():
    assert normalize_ldap_search_value("jdoe_ca") == "jdoe"
    assert cn_from_dn("CN=Jane Smith,OU=Managers,DC=example,DC=com") == "Jane Smith"


def make_directory():
    server = Server("mock-dc", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(server, user=f"CN=svc,{BASE}", password="pw", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry(f"CN=svc,{BASE}", {"userPassword": "pw", "objectClass": "person"})
    conn.strategy.add_entry(
        f"CN=Jane Smith,{BASE}",
        {
            "objectClass": ["person", "user"],
            "cn": "Jane Smith",
            "displayName": "Jane Smith",
            "mail": "jane.smith@example.com",
            "telephoneNumber": "+1 555 0100",
        },
    )
    conn.strategy.add_entry(
        f"CN=John Doe,{BASE}",
        {
            "objectClass": ["person", "user"],
            "sAMAccountName": "jdoe",
            "userPrincipalName": "jdoe@example.com",
            "manager": f"CN=Jane Smith,{BASE}",
        },
    )
    conn.strategy.add_entry(
        f"CN=No Manager,{BASE}", {"objectClass": ["person", "user"], "sAMAccountName": "nomgr"}
    )
    conn.bind()
    return conn


def test_manager_resolution_against_mock_directory():
    config = AppConfig(
        threat_intel_base_url="x", threat_intel_api_token="t", ldap_search_bases=[BASE]
    )
    with LdapManagerResolver(config, connection=make_directory()) as resolver:
        contact = resolver.resolve_manager("jdoe@example.com")
        assert (contact.manager_name, contact.manager_email, contact.manager_phone) == (
            "Jane Smith",
            "jane.smith@example.com",
            "+1 555 0100",
        )
        assert resolver.resolve_manager("nomgr") is None
        assert resolver.resolve_manager("unknown.user") is None
