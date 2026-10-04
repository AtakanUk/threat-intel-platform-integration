import json
from unittest.mock import MagicMock

from threat_intel_platform_integration.client import ThreatIntelClient
from threat_intel_platform_integration.config import AppConfig
from threat_intel_platform_integration.models import CredentialTicket, ManagerContact
from threat_intel_platform_integration.processor import CredentialLeakProcessor

ALICE_MANAGER = ManagerContact("Manager A", "manager.a@example.com")


def ticket(ticket_id, username, device="LT-OPS-0042"):
    return CredentialTicket(
        ticket_id=ticket_id, username=username, source="stealer-log", computer_name=device
    )


class FakeClient:
    def __init__(self, tickets):
        self.tickets = tickets

    def compromised_credentials(self, status):
        return iter(self.tickets)


class FakeResolver:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def resolve_manager(self, username):
        return ALICE_MANAGER if username.startswith("team-a") else None


def make_processor(tmp_path, tickets, notifier=None, **config):
    cfg = AppConfig(
        threat_intel_base_url="https://ti.example.com",
        threat_intel_api_token="t",
        state_file=tmp_path / "state.json",
        **config,
    )
    notifier = notifier or MagicMock()
    soar = MagicMock()
    soar.create_incident.return_value = {"id": 1}
    return (
        CredentialLeakProcessor(
            cfg, client=FakeClient(tickets), resolver=FakeResolver(), notifier=notifier, soar=soar
        ),
        notifier,
        soar,
    )


def test_batching_fallback_and_filters(tmp_path):
    tickets = [
        ticket(1, "team-a.one"),
        ticket(2, "team-a.two"),
        ticket(3, "team-a.three"),
        ticket(4, "other.user"),
        ticket(5, "+44 7700 900123"),
    ]
    processor, notifier, _ = make_processor(tmp_path, tickets)

    summary = processor.run()

    recipients = [call.args[0] for call in notifier.send.call_args_list]
    assert recipients.count("manager.a@example.com") == 1  # one digest for 3 tickets
    assert recipients.count("security-team@example.com") == 1
    assert (summary.skipped_phone, summary.fallback_tickets, summary.tickets_notified) == (1, 1, 4)
    assert set(json.loads((tmp_path / "state.json").read_text())) == {"1", "2", "3", "4"}


def test_failed_mail_is_retried_next_run(tmp_path):
    notifier = MagicMock()
    notifier.send.side_effect = [RuntimeError("SMTP down")]
    processor, _, _ = make_processor(tmp_path, [ticket(7, "other.user")], notifier=notifier)
    assert processor.run().notifications_failed == 1

    notifier.send.side_effect = None
    processor, _, _ = make_processor(tmp_path, [ticket(7, "other.user")], notifier=notifier)
    summary = processor.run()
    assert (summary.skipped_processed, summary.tickets_notified) == (0, 1)


def test_critical_leaks_create_soar_incidents(tmp_path):
    tickets = [
        ticket(1, "jdoe@corp.example.com", device="CORP-LT-001"),
        ticket(2, "jdoe@gmail.example", device="CORP-LT-001"),
    ]
    processor, _, soar = make_processor(
        tmp_path,
        tickets,
        critical_device_pattern=r"^CORP-",
        critical_username_pattern=r"@corp\.example\.com$",
    )
    summary = processor.run()
    assert (summary.critical, summary.soar_incidents) == (1, 1)
    assert soar.create_incident.call_args.args[0].ticket_id == 1


def test_client_follows_pagination():
    config = AppConfig(threat_intel_base_url="https://ti.example.com", threat_intel_api_token="t")
    session = MagicMock()
    session.headers = {}
    pages = [
        {
            "results": [
                {"id": 1, "content": {"username": "a", "victim_detail": {"computer_name": "PC1"}}}
            ],
            "next": "page2",
        },
        {"results": [{"id": 2, "content": {"username": "b"}}, {"content": {}}], "next": None},
    ]
    responses = []
    for page in pages:
        response = MagicMock(status_code=200)
        response.json.return_value = page
        responses.append(response)
    session.get.side_effect = responses
    tickets = list(ThreatIntelClient(config, session=session).compromised_credentials("open"))
    assert [(t.ticket_id, t.username, t.asset_name) for t in tickets] == [
        (1, "a", "PC1"),
        (2, "b", "unknown"),
    ]
    assert session.get.call_args_list[1].kwargs["params"]["page"] == 2
