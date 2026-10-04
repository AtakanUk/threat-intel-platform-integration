from __future__ import annotations

import argparse
import logging

from .config import AppConfig
from .processor import CredentialLeakProcessor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Notify managers about leaked employee credentials"
    )
    parser.add_argument(
        "--status", default=None, help="ticket status to process (default: TICKET_STATUS or 'open')"
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    summary = CredentialLeakProcessor(AppConfig.from_env()).run(status=args.status)
    print(
        f"scanned={summary.scanned} already_notified={summary.skipped_processed} phone_like={summary.skipped_phone} "
        f"critical={summary.critical} soar_incidents={summary.soar_incidents} mails_sent={summary.notifications_sent} "
        f"mails_failed={summary.notifications_failed} tickets_notified={summary.tickets_notified} fallback={summary.fallback_tickets}"
    )
    return 1 if summary.notifications_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
