import ipaddress
import re
from typing import List, Optional
from urllib.parse import urlparse

from app.services.intelligence.models import (
    LookupStatus,
    ReputationStatus,
    URLIntelligenceResult,
)
from app.services.intelligence.providers.base import BaseURLIntelligenceProvider

CREDENTIAL_PATHS = [
    "/login", "/signin", "/auth", "/authenticate", "/verify", "/verification",
    "/account/update", "/billing", "/recover", "/password/reset", "/portal"
]

OPEN_REDIRECT_PARAMS = [
    "redirect", "url", "next", "target", "dest", "destination", "r", "u", "link"
]

KNOWN_URL_DATABASE = {
    "http://185.220.101.5/auth/login.php": {
        "reputation": ReputationStatus.KNOWN_MALICIOUS,
        "structural_indicators": [
            "Raw IP Address in URL Host",
            "Insecure HTTP Protocol for Authentication Form",
            "Credential Harvesting Path Pattern",
        ],
        "source": "threat_intel_feed",
    },
    "http://paypa1-security.com/verification.html": {
        "reputation": ReputationStatus.KNOWN_MALICIOUS,
        "structural_indicators": [
            "Typosquatted Brand Domain",
            "Insecure HTTP Scheme for Security Form",
            "Credential Phishing Path",
        ],
        "source": "threat_intel_feed",
    },
    "https://github.com/login": {
        "reputation": ReputationStatus.CLEAN,
        "structural_indicators": ["Legitimate Secure Authentication Endpoint"],
        "source": "whitelist_db",
    },
}


class OfflineURLIntelligenceProvider(BaseURLIntelligenceProvider):
    """
    Offline URL structural and reputation analyzer.
    Performs RFC-compliant URI parsing, IP-in-hostname detection, non-standard port checks,
    credential harvesting path detection, and known threat matching without external dependencies.
    """

    @property
    def name(self) -> str:
        return "structural_url_engine"

    async def lookup_url(self, url: str) -> URLIntelligenceResult:
        clean_url = url.strip()
        entity_id = f"url:{clean_url}"

        # Ensure scheme is present for urlparse
        parse_target = clean_url
        if not parse_target.startswith(("http://", "https://", "ftp://")):
            parse_target = "http://" + parse_target

        try:
            parsed = urlparse(parse_target)
        except Exception:
            return URLIntelligenceResult(
                entity_id=entity_id,
                url=clean_url,
                normalized_url=clean_url,
                domain="",
                status=LookupStatus.ERROR,
                status_message="Failed to parse URL.",
                source=self.name,
            )

        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        scheme = parsed.scheme.lower()
        path = parsed.path or "/"
        query = parsed.query or ""

        structural_indicators: List[str] = []

        # 1. Check if Host is raw IP address
        is_ip_host = False
        try:
            ipaddress.ip_address(hostname)
            is_ip_host = True
            structural_indicators.append("Host is a Direct IP Address (Obfuscation Risk)")
        except ValueError:
            is_ip_host = False

        # 2. Check for Insecure Protocol on Credential Paths
        has_credential_path = any(cred_path in path.lower() for cred_path in CREDENTIAL_PATHS)
        if has_credential_path:
            structural_indicators.append("Credential or Authentication-Related URL Path")
            if scheme == "http":
                structural_indicators.append("Insecure HTTP Scheme for Authentication Route")

        # 3. Check for Non-Standard Ports
        if port and port not in (80, 443, 8080):
            structural_indicators.append(f"Non-Standard Web Port (:{port})")

        # 4. Check for Open Redirect Query Parameters
        if query:
            for param in OPEN_REDIRECT_PARAMS:
                if f"{param}=" in query.lower():
                    structural_indicators.append(f"Potential Open-Redirect Query Parameter ({param}=)")
                    break

        # 5. Check Punycode Host
        is_punycode = hostname.startswith("xn--") or ".xn--" in hostname
        if is_punycode:
            structural_indicators.append("Host contains Punycode/IDNA representation")

        # 6. Check Reference Database & Calculate Reputation
        reputation = ReputationStatus.UNKNOWN
        source = self.name
        attribution = "LOCAL ANALYSIS"
        has_query = bool(query)
        host_ip = hostname if is_ip_host else None

        if clean_url in KNOWN_URL_DATABASE:
            ref = KNOWN_URL_DATABASE[clean_url]
            reputation = ref.get("reputation", ReputationStatus.UNKNOWN)
            for ind in ref.get("structural_indicators", []):
                if ind not in structural_indicators:
                    structural_indicators.append(ind)
            source = ref.get("source", self.name)
            attribution = "OFFLINE FALLBACK"
        else:
            if is_ip_host and has_credential_path:
                reputation = ReputationStatus.KNOWN_MALICIOUS
            elif is_ip_host or (has_credential_path and scheme == "http"):
                reputation = ReputationStatus.SUSPICIOUS
            elif len(structural_indicators) >= 2:
                reputation = ReputationStatus.SUSPICIOUS

        return URLIntelligenceResult(
            entity_id=entity_id,
            url=clean_url,
            normalized_url=f"{scheme}://{hostname}{f':{port}' if port else ''}{path}{f'?{query}' if query else ''}",
            domain=hostname,
            hostname=hostname,
            host_ip=host_ip,
            scheme=scheme,
            port=port,
            path=path,
            query=query,
            has_query=has_query,
            is_ip_host=is_ip_host,
            has_credential_path=has_credential_path,
            has_credential_keywords=has_credential_path,
            is_punycode=is_punycode,
            structural_indicators=structural_indicators,
            reputation=reputation,
            source=source,
            status=LookupStatus.SUCCESS,
            attribution=attribution,
            status_message="URL structural intelligence generated.",
        )
