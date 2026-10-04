from __future__ import annotations

import logging
import smtplib
import ssl
import time
from collections.abc import Iterator
from email.message import EmailMessage
from typing import Any

import requests

from .config import AppConfig
from .helpers import cn_from_dn, manager_filters, user_filters
from .models import CredentialTicket, ManagerContact

LOG = logging.getLogger(__name__)

TICKETS_PATH = "/security-intelligence/account-takeover-prevention/compromised-credentials-tickets"


class ThreatIntelClient:
    """Compromised-credential tickets of the threat-intelligence platform (paginated REST API)."""

    def __init__(self, config: AppConfig, session: requests.Session | None = None):
        self.config = config
        self.session = session or requests.Session()
        if config.proxies:
            self.session.proxies.update(config.proxies)
        self.session.verify = config.threat_intel_verify_ssl
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"{config.threat_intel_auth_scheme} {config.threat_intel_api_token}",
            }
        )

    def compromised_credentials(self, status: str) -> Iterator[CredentialTicket]:
        page = 1
        while True:
            response = self.session.get(
                self.config.threat_intel_base_url + TICKETS_PATH,
                params={
                    "status": status,
                    "is_corporate": str(self.config.corporate_only).lower(),
                    "page": page,
                    "size": self.config.page_size,
                },
                timeout=30,
            )
            if response.status_code == 401:
                raise PermissionError("Threat-intelligence API rejected the token (HTTP 401)")
            response.raise_for_status()
            body = response.json()
            for item in body.get("results") or []:
                if item.get("id") is None:
                    LOG.warning("Ticket without id skipped")
                    continue
                yield CredentialTicket.from_api(item)
            if not body.get("next"):
                return
            page += 1


class LdapManagerResolver:
    """Finds the manager of a leaked account in Active Directory (``manager`` attribute).

    One connection per run; use as a context manager. Returns None when the
    user, the manager or the manager's mail cannot be found, so the caller can
    fall back to the security team mailbox.
    """

    USER_ATTRIBUTES = (
        "cn",
        "displayName",
        "sAMAccountName",
        "userPrincipalName",
        "mail",
        "manager",
    )
    MANAGER_ATTRIBUTES = ("cn", "displayName", "mail", "telephoneNumber")

    def __init__(self, config: AppConfig, connection: Any = None):
        self.config = config
        self.conn = connection

    def __enter__(self) -> LdapManagerResolver:
        if self.conn is None and self.config.ldap_configured:
            from ldap3 import ALL, Connection, Server

            server = Server(
                self.config.ldap_server,
                port=self.config.ldap_port,
                use_ssl=self.config.ldap_use_ssl,
                connect_timeout=15,
                get_info=ALL,
            )
            self.conn = Connection(
                server,
                user=self.config.ldap_user_dn,
                password=self.config.ldap_password,
                auto_bind=True,
                receive_timeout=30,
            )
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.conn is not None:
            self.conn.unbind()

    def _search(self, filters: list[tuple[str, str]], attributes: list[str]) -> Any:
        for base in self.config.ldap_search_bases:
            for label, search_filter in filters:
                self.conn.search(base, search_filter, attributes=attributes)
                if self.conn.entries:
                    LOG.debug("LDAP match via %s in %s", label, base)
                    return self.conn.entries[0]
        return None

    @staticmethod
    def _value(entry: Any, attribute: str) -> str | None:
        if attribute in entry and entry[attribute].value:
            return str(entry[attribute].value)
        return None

    def _contact(self, entry: Any) -> ManagerContact | None:
        mail = self._value(entry, "mail")
        if not mail:
            return None
        name = self._value(entry, "displayName") or self._value(entry, "cn") or mail
        return ManagerContact(
            manager_name=name,
            manager_email=mail,
            manager_phone=self._value(entry, "telephoneNumber"),
        )

    def resolve_manager(self, username: str) -> ManagerContact | None:
        if self.conn is None or not username:
            return None
        try:
            user = self._search(user_filters(username), self.USER_ATTRIBUTES)
            manager_dn = self._value(user, "manager") if user is not None else None
            if not manager_dn:
                LOG.info("No directory user or manager for %s", username)
                return None

            from ldap3 import BASE

            self.conn.search(
                manager_dn, "(objectClass=*)", search_scope=BASE, attributes=self.MANAGER_ATTRIBUTES
            )
            if self.conn.entries:
                return self._contact(self.conn.entries[0])
            # Manager DN not readable (e.g. moved object): search by name instead.
            manager = self._search(manager_filters(cn_from_dn(manager_dn)), self.MANAGER_ATTRIBUTES)
            return self._contact(manager) if manager is not None else None
        except Exception as exc:
            LOG.warning("LDAP lookup for %s failed: %s", username, exc)
            return None


class EmailNotifier:
    def __init__(self, config: AppConfig):
        self.config = config

    def send(self, recipient: str, subject: str, html_body: str) -> None:
        if self.config.test_recipient:
            subject = f"[TEST for {recipient}] {subject}"
            recipient = self.config.test_recipient
        if self.config.dry_run:
            LOG.info("DRY_RUN: mail '%s' to %s not sent", subject, recipient)
            return
        if not self.config.smtp_host:
            raise RuntimeError("SMTP_HOST is required when DRY_RUN is false")

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.config.smtp_from_address
        message["To"] = recipient
        message.set_content("This notification requires an HTML-capable mail client.")
        message.add_alternative(html_body, subtype="html")
        with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=20) as smtp:
            if self.config.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self.config.smtp_username:
                smtp.login(self.config.smtp_username, self.config.smtp_password or "")
            smtp.send_message(message)
        LOG.info("Mail '%s' sent to %s", subject, recipient)


class SoarClient:
    """Opens an incident in IBM QRadar SOAR for critical leaks (playbooks there handle SMS/calls)."""

    def __init__(self, config: AppConfig, rest_client: Any = None):
        self.config = config
        self._client = rest_client

    def create_incident(self, ticket: CredentialTicket) -> dict[str, Any] | None:
        incident: dict[str, Any] = {
            "name": f"Compromised corporate credential - {ticket.username}",
            "description": {
                "format": "text",
                "content": (
                    f"Threat-intelligence ticket {ticket.ticket_id}: credentials of {ticket.username} were found in "
                    f"stealer logs from the corporate device {ticket.asset_name} (infection date {ticket.infection_date or 'unknown'}, "
                    f"source {ticket.source})."
                ),
            },
            "severity_code": "High",
            "discovered_date": int(time.time() * 1000),
        }
        if self.config.soar_incident_type:
            incident["incident_type_ids"] = [self.config.soar_incident_type]
        if not self.config.soar_enabled:
            LOG.info("SOAR disabled; incident for ticket %s not created", ticket.ticket_id)
            return None
        if self._client is None:
            import resilient

            self._client = resilient.get_client(self.config.soar_options())
        created = self._client.post("/incidents", incident)
        LOG.info("SOAR incident %s created for ticket %s", created.get("id"), ticket.ticket_id)
        return created
