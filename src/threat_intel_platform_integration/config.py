from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on", "y"}


def _opt(name: str) -> str | None:
    return os.environ.get(name, "").strip() or None


@dataclass
class AppConfig:
    threat_intel_base_url: str
    threat_intel_api_token: str
    threat_intel_auth_scheme: str = "Token"
    threat_intel_verify_ssl: bool = True
    http_proxy_url: str | None = None
    https_proxy_url: str | None = None
    ticket_status: str = "open"
    corporate_only: bool = True
    page_size: int = 100

    batch_threshold: int = 3
    skip_phone_usernames: bool = True
    fallback_manager_email: str = "security-team@example.com"
    state_file: Path = Path("data/processed_tickets.json")

    smtp_host: str | None = None
    smtp_port: int = 25
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_starttls: bool = False
    smtp_from_address: str = "soc-notifications@example.com"
    dry_run: bool = True
    test_recipient: str | None = None

    ldap_server: str | None = None
    ldap_port: int = 636
    ldap_use_ssl: bool = True
    ldap_user_dn: str | None = None
    ldap_password: str | None = None
    ldap_search_bases: list[str] = field(default_factory=list)

    critical_device_pattern: str | None = None
    critical_username_pattern: str | None = None
    soar_enabled: bool = False
    soar_host: str | None = None
    soar_port: int = 443
    soar_org: str | None = None
    soar_api_key_id: str | None = None
    soar_api_key_secret: str | None = None
    soar_cafile: str | None = None
    soar_incident_type: str | None = None

    @property
    def proxies(self) -> dict[str, str] | None:
        if not self.http_proxy_url and not self.https_proxy_url:
            return None
        return {
            "http": self.http_proxy_url or self.https_proxy_url or "",
            "https": self.https_proxy_url or self.http_proxy_url or "",
        }

    @property
    def ldap_configured(self) -> bool:
        return bool(
            self.ldap_server and self.ldap_user_dn and self.ldap_password and self.ldap_search_bases
        )

    def soar_options(self) -> dict[str, object]:
        options: dict[str, object] = {
            "host": self.soar_host,
            "port": self.soar_port,
            "org": self.soar_org,
            "api_key_id": self.soar_api_key_id,
            "api_key_secret": self.soar_api_key_secret,
        }
        if self.soar_cafile:
            options["cafile"] = self.soar_cafile
        return options

    @classmethod
    def from_env(cls) -> AppConfig:
        token = _opt("THREAT_INTEL_API_TOKEN")
        if not token:
            raise SystemExit("THREAT_INTEL_API_TOKEN is required")
        bases = [
            base.strip()
            for base in os.environ.get("LDAP_SEARCH_BASES", "").split(";")
            if base.strip()
        ]
        return cls(
            threat_intel_base_url=os.environ.get(
                "THREAT_INTEL_BASE_URL", "https://api.example.com/threat-stream/v4"
            ).rstrip("/"),
            threat_intel_api_token=token,
            threat_intel_auth_scheme=os.environ.get("THREAT_INTEL_AUTH_SCHEME", "Token"),
            threat_intel_verify_ssl=_bool("THREAT_INTEL_VERIFY_SSL", True),
            http_proxy_url=_opt("HTTP_PROXY_URL"),
            https_proxy_url=_opt("HTTPS_PROXY_URL"),
            ticket_status=os.environ.get("TICKET_STATUS", "open"),
            corporate_only=_bool("CORPORATE_ONLY", True),
            batch_threshold=int(os.environ.get("BATCH_THRESHOLD", "3")),
            skip_phone_usernames=_bool("SKIP_PHONE_USERNAMES", True),
            fallback_manager_email=os.environ.get(
                "FALLBACK_MANAGER_EMAIL", cls.fallback_manager_email
            ),
            state_file=Path(os.environ.get("STATE_FILE", "data/processed_tickets.json")),
            smtp_host=_opt("SMTP_HOST"),
            smtp_port=int(os.environ.get("SMTP_PORT", "25")),
            smtp_username=_opt("SMTP_USERNAME"),
            smtp_password=_opt("SMTP_PASSWORD"),
            smtp_starttls=_bool("SMTP_STARTTLS", False),
            smtp_from_address=os.environ.get("SMTP_FROM_ADDRESS", cls.smtp_from_address),
            dry_run=_bool("DRY_RUN", True),
            test_recipient=_opt("TEST_RECIPIENT"),
            ldap_server=_opt("LDAP_SERVER"),
            ldap_port=int(os.environ.get("LDAP_PORT", "636")),
            ldap_use_ssl=_bool("LDAP_USE_SSL", True),
            ldap_user_dn=_opt("LDAP_USER_DN"),
            ldap_password=_opt("LDAP_PASSWORD"),
            ldap_search_bases=bases,
            critical_device_pattern=_opt("CRITICAL_DEVICE_PATTERN"),
            critical_username_pattern=_opt("CRITICAL_USERNAME_PATTERN"),
            soar_enabled=_bool("SOAR_ENABLED", False),
            soar_host=_opt("SOAR_HOST"),
            soar_port=int(os.environ.get("SOAR_PORT", "443")),
            soar_org=_opt("SOAR_ORG"),
            soar_api_key_id=_opt("SOAR_API_KEY_ID"),
            soar_api_key_secret=_opt("SOAR_API_KEY_SECRET"),
            soar_cafile=_opt("SOAR_CAFILE"),
            soar_incident_type=_opt("SOAR_INCIDENT_TYPE"),
        )
