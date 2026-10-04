from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Iterable

from .client import EmailNotifier, LdapManagerResolver, SoarClient, ThreatIntelClient
from .config import AppConfig
from .helpers import is_phone_like
from .models import CredentialTicket, ManagerContact, ProcessorSummary
from .state import ProcessedTicketStore
from .templates import render_batch_email, render_single_ticket_email

LOG = logging.getLogger(__name__)


class CredentialLeakProcessor:
    """Notifies line managers about leaked employee credentials.

    1. Fetch open compromised-credential tickets (corporate accounts only).
    2. Skip tickets that were already notified and consumer-style logins (phone numbers).
    3. Flag critical cases: the credential was stolen from a managed corporate
       device (matching ``CRITICAL_DEVICE_PATTERN``) and belongs to a corporate
       account (``CRITICAL_USERNAME_PATTERN``); these become SOAR incidents.
    4. Resolve each user's manager in Active Directory (fallback: security team).
    5. Send one mail per ticket, or one digest per manager when a manager has
       ``batch_threshold`` or more tickets.

    A ticket is only marked as processed after its mail was sent, so failed
    deliveries are retried on the next run.
    """

    def __init__(
        self,
        config: AppConfig,
        client: ThreatIntelClient | None = None,
        resolver: LdapManagerResolver | None = None,
        notifier: EmailNotifier | None = None,
        soar: SoarClient | None = None,
    ):
        self.config = config
        self.client = client or ThreatIntelClient(config)
        self.resolver = resolver or LdapManagerResolver(config)
        self.notifier = notifier or EmailNotifier(config)
        self.soar = soar or SoarClient(config)
        self.store = ProcessedTicketStore(config.state_file)

    def is_critical(self, ticket: CredentialTicket) -> bool:
        device_rule, user_rule = (
            self.config.critical_device_pattern,
            self.config.critical_username_pattern,
        )
        if not device_rule or not user_rule:
            return False
        return bool(
            re.search(device_rule, ticket.computer_name or "", re.IGNORECASE)
            and re.search(user_rule, ticket.username, re.IGNORECASE)
        )

    def group_by_manager(
        self, tickets: Iterable[CredentialTicket], summary: ProcessorSummary
    ) -> dict[ManagerContact, list[CredentialTicket]]:
        fallback = ManagerContact("Information Security Team", self.config.fallback_manager_email)
        groups: dict[ManagerContact, list[CredentialTicket]] = defaultdict(list)
        for ticket in tickets:
            contact = self.resolver.resolve_manager(ticket.username)
            if contact is None:
                contact = fallback
                summary.fallback_tickets += 1
            groups[contact].append(ticket)
        return groups

    def _deliver(
        self, manager: ManagerContact, tickets: list[CredentialTicket], summary: ProcessorSummary
    ) -> None:
        if len(tickets) >= self.config.batch_threshold:
            messages = [
                (
                    f"Credential exposure: {len(tickets)} accounts of your team",
                    render_batch_email(manager, tickets),
                    tickets,
                )
            ]
        else:
            messages = [
                (
                    f"Credential exposure alert #{t.ticket_id}",
                    render_single_ticket_email(manager, t),
                    [t],
                )
                for t in tickets
            ]

        for subject, body, covered in messages:
            try:
                self.notifier.send(manager.manager_email, subject, body)
            except Exception as exc:
                summary.notifications_failed += 1
                LOG.error(
                    "Mail to %s failed, %d ticket(s) will be retried: %s",
                    manager.manager_email,
                    len(covered),
                    exc,
                )
                continue
            summary.notifications_sent += 1
            summary.tickets_notified += len(covered)
            for ticket in covered:
                self.store.add(ticket.ticket_id)

    def run(self, status: str | None = None) -> ProcessorSummary:
        summary = ProcessorSummary()
        actionable: list[CredentialTicket] = []
        for ticket in self.client.compromised_credentials(status or self.config.ticket_status):
            summary.scanned += 1
            if self.store.contains(ticket.ticket_id):
                summary.skipped_processed += 1
            elif not ticket.username:
                summary.invalid += 1
            elif self.config.skip_phone_usernames and is_phone_like(ticket.username):
                summary.skipped_phone += 1
            else:
                actionable.append(ticket)

        for ticket in actionable:
            if self.is_critical(ticket):
                summary.critical += 1
                LOG.warning(
                    "Critical leak: %s from corporate device %s (ticket %s)",
                    ticket.username,
                    ticket.asset_name,
                    ticket.ticket_id,
                )
                try:
                    if self.soar.create_incident(ticket):
                        summary.soar_incidents += 1
                except Exception as exc:
                    LOG.error("SOAR incident for ticket %s failed: %s", ticket.ticket_id, exc)

        try:
            with self.resolver:
                groups = self.group_by_manager(actionable, summary)
            for manager, tickets in groups.items():
                self._deliver(manager, tickets, summary)
        finally:
            self.store.persist()
        LOG.info("Run summary: %s", summary)
        return summary
