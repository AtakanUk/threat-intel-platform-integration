from __future__ import annotations

from html import escape

from .models import CredentialTicket, ManagerContact

STYLE_CELL = "padding:6px 10px;border:1px solid #d8d8d8;text-align:left"

ACTIONS = """
<p><b>What needs to be done</b></p>
<ol>
  <li>Make sure the user changes the password of the account (and of any other account that used the same password).</li>
  <li>Have the listed device checked by IT: the credentials were collected by info-stealer malware running on it.</li>
  <li>Check that multi-factor authentication is enabled for the account.</li>
</ol>
<p>If you have questions, reply to this mail or contact the Information Security team.</p>
"""


def _row(label: str, value: object) -> str:
    return f"<tr><th style='{STYLE_CELL};background:#f3f5f7'>{escape(label)}</th><td style='{STYLE_CELL}'>{escape(str(value))}</td></tr>"


def render_single_ticket_email(manager: ManagerContact, ticket: CredentialTicket) -> str:
    rows = "".join(
        [
            _row("Ticket", ticket.ticket_id),
            _row("Account", ticket.username),
            _row("Device", ticket.asset_name),
            _row("Infection date", ticket.infection_date or "unknown"),
            _row("Source", ticket.source or "unknown"),
        ]
    )
    return (
        "<html><body style='font-family:Segoe UI,Arial,sans-serif;color:#222'>"
        f"<p>Dear {escape(manager.manager_name)},</p>"
        "<p>The credentials of a member of your team were found in data stolen by malware and offered on criminal "
        "marketplaces. Until the password is changed, anyone holding this data can sign in as the user.</p>"
        f"<table style='border-collapse:collapse'>{rows}</table>"
        f"{ACTIONS}</body></html>"
    )


def render_batch_email(manager: ManagerContact, tickets: list[CredentialTicket]) -> str:
    header = "".join(
        f"<th style='{STYLE_CELL};background:#f3f5f7'>{h}</th>"
        for h in ("Ticket", "Account", "Device", "Infection date", "Source")
    )
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td style='{STYLE_CELL}'>{escape(str(value))}</td>"
            for value in (
                t.ticket_id,
                t.username,
                t.asset_name,
                t.infection_date or "unknown",
                t.source or "unknown",
            )
        )
        + "</tr>"
        for t in tickets
    )
    return (
        "<html><body style='font-family:Segoe UI,Arial,sans-serif;color:#222'>"
        f"<p>Dear {escape(manager.manager_name)},</p>"
        f"<p>The credentials of <b>{len(tickets)}</b> accounts in your team were found in data stolen by malware. "
        "They are listed together to avoid sending one mail per account.</p>"
        f"<table style='border-collapse:collapse'><tr>{header}</tr>{rows}</table>"
        f"{ACTIONS}</body></html>"
    )
