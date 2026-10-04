from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CredentialTicket:
    ticket_id: int
    username: str
    source: str
    infection_date: str | None = None
    computer_name: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def asset_name(self) -> str:
        return self.computer_name or "unknown"

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> CredentialTicket:
        content = item.get("content") or {}
        victim = content.get("victim_detail") or {}
        return cls(
            ticket_id=int(item["id"]),
            username=str(content.get("username") or item.get("username") or "").strip(),
            source=str(content.get("source") or "unknown"),
            infection_date=victim.get("infection_date") or None,
            computer_name=victim.get("computer_name") or None,
            raw=item,
        )


@dataclass(frozen=True)
class ManagerContact:
    manager_name: str
    manager_email: str
    manager_phone: str | None = None


@dataclass
class ProcessorSummary:
    scanned: int = 0
    skipped_processed: int = 0
    skipped_phone: int = 0
    invalid: int = 0
    notifications_sent: int = 0
    notifications_failed: int = 0
    tickets_notified: int = 0
    fallback_tickets: int = 0
    critical: int = 0
    soar_incidents: int = 0
