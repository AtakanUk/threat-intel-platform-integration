from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path


class ProcessedTicketStore:
    """Ticket IDs that were already notified, with the time of notification."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, str] = self._load()

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        # older files were a plain list of IDs
        return (
            {str(item): "" for item in data}
            if isinstance(data, list)
            else {str(k): v for k, v in data.items()}
        )

    def contains(self, ticket_id: int) -> bool:
        return str(ticket_id) in self._data

    def add(self, ticket_id: int) -> None:
        self._data[str(ticket_id)] = datetime.now(UTC).isoformat(timespec="seconds")

    def persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)
