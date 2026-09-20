import asyncio
import idna
import re
import socket
from typing import List, Optional
from urllib.parse import urlparse

from app.services.intelligence.models import (
    DomainIntelligenceResult,
    LookupStatus,
    ReputationStatus,
)
from app.services.intelligence.providers.base import BaseDomainIntelligenceProvider

HIGH_RISK_TLDS = {
    "xyz", "top", "work", "buzz", "club", "tk", "ml", "ga", "cf", "gq", 
    "icu", "monster", "rest", "cam", "fit", "surf", "cn", "ru"
}

SUSPICIOUS_KEYWORDS = [
    "security", "verify", "verification", "update", "login", "signin", 
    "auth", "authenticate", "support", "billing", "account", "secure", 
    "recover", "wallet", "banking", "service", "portal", "confirm", "alert"
]

KNOWN_DOMAIN_DATABASE = {
    "paypa1-security.com": {
        "reputation": ReputationStatus.KNOWN_MALICIOUS,
        "structural_indicators": [
            "Typosquatting / Character Substitution (paypa1 -> paypal)",
            "Suspicious Brand Keyword (security)",
        ],
        "a_records": ["185.220.101.5"],
        "mx_records": ["mail.paypa1-security.com"],
        "source": "threat_intel_feed",
    },
    "account-update-alert.com": {
        "reputation": ReputationStatus.SUSPICIOUS,
        "structural_indicators": [
            "Suspicious Keywords Sequence (account, update, alert)",
            "Recent Registration Pattern",
        ],
        "a_records": ["185.220.101.5"],
        "source": "threat_intel_feed",
    },
    "paypal.com": {
        "reputation": ReputationStatus.CLEAN,
        "structural_indicators": ["Legitimate Registered Enterprise Domain"],
        "a_records": ["151.101.65.140", "151.101.1.140"],
        "source": "whitelist_db",
    },
    "google.com": {
        "reputation": ReputationStatus.CLEAN,
        "structural_indicators": ["Legitimate Registered Enterprise Domain"],
        "a_records": ["142.250.190.46"],
        "source": "whitelist_db",
    },
    "github.com": {
        "reputation": ReputationStatus.CLEAN,
        "structural_indicators": ["Legitimate Registered Enterprise Domain"],
        "a_records": ["140.82.121.4"],
        "source": "whitelist_db",
    },
}


INTERNAL_TLDS = {
    "local", "internal", "lan", "corp", "home", "test", "example", 
    "invalid", "localhost", "onion", "intra"
}

TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "edu.au",
    "co.jp", "ne.jp", "co.in", "net.in", "org.in", "co.nz", "com.br", "co.za"
}


def normalize_domain_string(domain: str) -> str:
    """Normalizes domain by trimming, lowercasing, and stripping protocols or ports if present."""
    d = domain.strip().lower()
    if "://" in d:
        try:
            d = urlparse(d).hostname or d
        except Exception:
            pass
    if "/" in d:
        d = d.split("/")[0]
    if ":" in d:
        d = d.split(":")[0]
    return d.strip(".")


def extract_registrable_domain(normalized_domain: str) -> str:
    """Extracts the base registrable domain from a normalized domain string."""
    parts = normalized_domain.split(".")
    if len(parts) <= 2:
        return normalized_domain
    if len(parts) >= 3:
        potential_two_part = f"{parts[-2]}.{parts[-1]}"
        if potential_two_part in TWO_PART_SUFFIXES:
            return f"{parts[-3]}.{potential_two_part}"
    return f"{parts[-2]}.{parts[-1]}"


class OfflineDomainIntelligenceProvider(BaseDomainIntelligenceProvider):
    """
    Offline structural domain intelligence analyzer.
    Performs deterministic RFC/IDNA parsing, homograph checks, subdomain depth analysis,
    internal/localhost boundary detection, and reference threat matching without external dependencies.
    """

    @property
    def name(self) -> str:
        return "structural_domain_engine"

    async def lookup_domain(self, domain: str) -> DomainIntelligenceResult:
        normalized = normalize_domain_string(domain)
        entity_id = f"domain:{normalized}"

        if not normalized or (normalized != "localhost" and "." not in normalized):
            return DomainIntelligenceResult(
                entity_id=entity_id,
                domain=domain,
                normalized_domain=normalized,
                status=LookupStatus.ERROR,
                status_message="Invalid domain name format.",
                source=self.name,
                attribution="LOCAL ANALYSIS",
            )

        # 1. Localhost Detection
        is_localhost = normalized in ("localhost", "localhost.localdomain", "127.0.0.1", "::1") or normalized.endswith(".localhost")
        if is_localhost:
            return DomainIntelligenceResult(
                entity_id=entity_id,
                domain=domain,
                normalized_domain=normalized,
                registrable_domain="localhost",
                tld="localhost",
                subdomain_depth=0,
                is_internal=True,
                is_localhost=True,
                reputation=ReputationStatus.CLEAN,
                source="rfc_domain_classifier",
                status=LookupStatus.SUCCESS,
                attribution="LOCAL ANALYSIS",
                status_message="RFC 6761 Localhost domain — isolated from external lookups.",
            )

        # 2. Internal / Reserved TLD Detection
        parts = normalized.split(".")
        tld = parts[-1] if len(parts) > 1 else ""
        subdomain_depth = max(0, len(parts) - 2)
        registrable_domain = extract_registrable_domain(normalized)

        if tld in INTERNAL_TLDS:
            return DomainIntelligenceResult(
                entity_id=entity_id,
                domain=domain,
                normalized_domain=normalized,
                registrable_domain=registrable_domain,
                tld=tld,
                subdomain_depth=subdomain_depth,
                is_internal=True,
                is_localhost=False,
                reputation=ReputationStatus.UNKNOWN,
                source="rfc_domain_classifier",
                status=LookupStatus.SUCCESS,
                attribution="LOCAL ANALYSIS",
                status_message=f"RFC Reserved/Internal TLD (.{tld}) — external lookups bypassed.",
            )

        # 3. Punycode / IDNA Analysis
        is_punycode = False
        punycode_decoded = None
        structural_indicators: List[str] = []

        if normalized.startswith("xn--") or ".xn--" in normalized:
            is_punycode = True
            try:
                punycode_decoded = idna.decode(normalized)
                structural_indicators.append(f"Internationalized Domain / Punycode detected: {punycode_decoded}")
            except Exception:
                structural_indicators.append("Malformed Punycode Domain")

        if subdomain_depth >= 3:
            structural_indicators.append(f"Excessive Subdomain Depth ({subdomain_depth} levels)")

        if tld in HIGH_RISK_TLDS:
            structural_indicators.append(f"High-Risk / Low-Cost TLD (.{tld})")

        # 4. Suspicious Keyword Extraction
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in normalized]
        if len(found_keywords) >= 2:
            structural_indicators.append(f"Multiple Suspicious Keywords ({', '.join(found_keywords)})")
        elif len(found_keywords) == 1:
            structural_indicators.append(f"Suspicious Security/Auth Keyword ({found_keywords[0]})")

        # 5. Homoglyph / Digit Substitution check (e.g., '0' for 'o', '1' for 'l' or 'i')
        if re.search(r"[a-z]+[01][a-z]+", normalized):
            structural_indicators.append("Possible Digit-for-Letter Homoglyph Substitution")

        # 6. Check Curated Reference Database
        a_records: List[str] = []
        mx_records: List[str] = []
        ns_records: List[str] = []
        txt_records: List[str] = []
        dns_status = LookupStatus.NOT_AVAILABLE
        reputation = ReputationStatus.UNKNOWN
        attribution = "LOCAL ANALYSIS"

        if normalized in KNOWN_DOMAIN_DATABASE:
            ref = KNOWN_DOMAIN_DATABASE[normalized]
            reputation = ref.get("reputation", ReputationStatus.UNKNOWN)
            for ind in ref.get("structural_indicators", []):
                if ind not in structural_indicators:
                    structural_indicators.append(ind)
            a_records = ref.get("a_records", [])
            mx_records = ref.get("mx_records", [])
            dns_status = LookupStatus.SUCCESS
            source = ref.get("source", self.name)
            attribution = "OFFLINE FALLBACK"
        else:
            # Calculate default structural reputation
            if any("Homoglyph" in s or "Typosquatting" in s for s in structural_indicators):
                reputation = ReputationStatus.SUSPICIOUS
            elif len(structural_indicators) >= 2:
                reputation = ReputationStatus.SUSPICIOUS
            else:
                reputation = ReputationStatus.UNKNOWN
            source = self.name

        is_lookalike = any("Typosquatting" in s or "Homoglyph" in s for s in structural_indicators) or any(
            b in normalized for b in ["paypa1", "m1crosoft", "micros0ft", "g00gle", "app1e"]
        )

        return DomainIntelligenceResult(
            entity_id=entity_id,
            domain=domain,
            normalized_domain=normalized,
            registrable_domain=registrable_domain,
            tld=tld,
            subdomain_depth=subdomain_depth,
            is_punycode=is_punycode,
            punycode_decoded=punycode_decoded,
            is_internal=False,
            is_localhost=False,
            is_lookalike=is_lookalike,
            is_lookalike_brand=is_lookalike,
            dns_status=dns_status,
            a_records=a_records,
            mx_records=mx_records,
            ns_records=ns_records,
            txt_records=txt_records,
            structural_indicators=structural_indicators,
            reputation=reputation,
            source=source,
            status=LookupStatus.SUCCESS,
            attribution=attribution,
            status_message="Domain structural intelligence generated.",
        )
