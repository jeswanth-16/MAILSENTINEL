import email.utils
import logging
import re
from typing import Optional, Tuple

from app.services.intelligence.models import (
    EmailAddressIntelligenceResult,
    EmailRole,
    LookupStatus,
    ReputationStatus,
)

logger = logging.getLogger("mailsentinel.intelligence.email")

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "guerrillamail.com", "10minutemail.com",
    "yopmail.com", "throwawaymail.com", "sharklasers.com", "trashmail.com",
    "getairmail.com", "dispostable.com", "fakeinbox.com", "mohmal.com",
    "temp-mail.org", "nada.ltd", "burnermail.io", "mytemp.email"
}
DISPOSABLE_EMAIL_DOMAINS = DISPOSABLE_DOMAINS

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "aol.com", "protonmail.com", "proton.me", "zoho.com",
    "gmx.com", "mail.com", "yandex.com", "fastmail.com"
}


def parse_and_normalize_email(raw_email: str) -> Tuple[str, str, str, bool]:
    """
    Parses an RFC 5322 email string (e.g. 'Jane Doe <jane@example.com>' or 'jane@EXAMPLE.COM').
    Returns (normalized_full_email, local_part, domain, is_valid_syntax).
    """
    cleaned = raw_email.strip()
    # Extract address if enclosed in RFC display format
    _, addr = email.utils.parseaddr(cleaned)
    target = addr.strip() if addr else cleaned

    # Strip angle brackets, quotes, and whitespace
    target = target.strip("<>\"' ").strip()

    if "@" not in target:
        return target.lower(), target.lower(), "", False

    parts = target.split("@", 1)
    local_part = parts[0].strip().lower()
    domain = parts[1].strip().lower()

    normalized = f"{local_part}@{domain}"
    is_valid = bool(EMAIL_REGEX.match(normalized)) and "." in domain

    return normalized, local_part, domain, is_valid


class EmailAddressIntelligenceProvider:
    """
    Local email address intelligence analyzer.
    Extracts display names, local-part, and domain, analyzes syntax RFC-compliance,
    identifies disposable mail services and free providers without external dependencies.
    """

    @property
    def name(self) -> str:
        return "local_email_analyzer"

    async def lookup_email(
        self,
        raw_email: str,
        role: EmailRole = EmailRole.SENDER,
    ) -> EmailAddressIntelligenceResult:
        normalized, local_part, domain, is_valid = parse_and_normalize_email(raw_email)
        entity_id = f"email:{normalized}"

        if not is_valid or not domain:
            return EmailAddressIntelligenceResult(
                entity_id=entity_id,
                raw_email=raw_email,
                normalized_email=normalized,
                local_part=local_part,
                domain=domain,
                role=role,
                is_valid_syntax=False,
                is_disposable_domain=False,
                is_free_provider=False,
                reputation=ReputationStatus.SUSPICIOUS,
                source=self.name,
                status=LookupStatus.ERROR,
                attribution="LOCAL ANALYSIS",
                status_message="Malformed email address syntax or missing domain.",
            )

        is_disposable = domain in DISPOSABLE_DOMAINS
        is_free = domain in FREE_EMAIL_PROVIDERS
        is_lookalike = any(b in domain for b in ["paypa1", "m1crosoft", "micros0ft", "g00gle", "app1e", "d0cusign"]) or "xn--" in domain

        reputation = ReputationStatus.CLEAN
        if is_lookalike:
            reputation = ReputationStatus.KNOWN_MALICIOUS
            status_message = "High-risk brand lookalike/typosquatting domain identified in email address."
        elif is_disposable:
            reputation = ReputationStatus.SUSPICIOUS
            status_message = "Disposable/temporary email domain identified."
        elif is_free:
            reputation = ReputationStatus.CLEAN
            status_message = "Free/consumer email service provider identified."
        else:
            status_message = "Corporate or custom domain email address normalized."

        return EmailAddressIntelligenceResult(
            entity_id=entity_id,
            raw_email=raw_email,
            normalized_email=normalized,
            local_part=local_part,
            domain=domain,
            role=role,
            is_valid_syntax=True,
            is_disposable_domain=is_disposable,
            is_disposable=is_disposable,
            is_free_provider=is_free,
            is_lookalike_domain=is_lookalike,
            raw_address=raw_email,
            normalized_address=normalized,
            reputation=reputation,
            source=self.name,
            status=LookupStatus.SUCCESS,
            attribution="LOCAL ANALYSIS",
            cached=False,
            status_message=status_message,
        )


default_email_provider = EmailAddressIntelligenceProvider()
