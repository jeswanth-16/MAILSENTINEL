import logging
from typing import Optional
import httpx

from app.services.intelligence.models import (
    IPCategory,
    IPIntelligenceResult,
    LookupStatus,
    ReputationStatus,
)
from app.services.intelligence.providers.base import BaseIPIntelligenceProvider
from app.services.intelligence.providers.ip_provider import classify_ip_address

logger = logging.getLogger("mailsentinel.intelligence.abuseipdb")


class AbuseIPDBProvider(BaseIPIntelligenceProvider):
    """
    Real-time threat intelligence provider using AbuseIPDB API v2.
    Provides verified IP reputation, abuse confidence scoring, report counts,
    ISP, domain, and usage type telemetry.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.abuseipdb.com/api/v2/check",
        timeout: float = 5.0,
        max_age_in_days: int = 90,
    ):
        self.api_key = api_key.strip() if api_key and api_key.strip() else None
        self.base_url = base_url
        self.timeout = timeout
        self.max_age_in_days = max_age_in_days

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    @property
    def current_api_key(self) -> Optional[str]:
        if self.api_key:
            return self.api_key
        try:
            from app.core.config import settings
            key = getattr(settings, "ABUSEIPDB_API_KEY", None)
            return key.strip() if key and key.strip() else None
        except Exception:
            return None

    @property
    def is_configured(self) -> bool:
        return bool(self.current_api_key)

    async def lookup_ip(self, ip: str) -> IPIntelligenceResult:
        clean_ip = ip.strip()
        entity_id = f"ip:{clean_ip}"
        category, is_routable, _ = classify_ip_address(clean_ip)

        # 1. Invalid IP check
        if category == IPCategory.INVALID:
            return IPIntelligenceResult(
                entity_id=entity_id,
                ip=clean_ip,
                category=category,
                is_routable=False,
                status=LookupStatus.ERROR,
                status_message="Invalid IPv4/IPv6 address syntax.",
                source=self.name,
                attribution="UNAVAILABLE",
            )

        # 2. RFC Boundary check - do NOT query external provider for private or reserved IPs
        if not is_routable:
            return IPIntelligenceResult(
                entity_id=entity_id,
                ip=clean_ip,
                category=category,
                is_routable=False,
                status=LookupStatus.PRIVATE_IP_SKIPPED,
                status_message=f"{category.value} address range — external geolocation skipped.",
                source="rfc_ip_classifier",
                attribution="RFC PRIVATE / SKIPPED",
            )

        # 3. Missing API key check
        active_key = self.current_api_key
        if not active_key:
            logger.debug("AbuseIPDB query skipped: no API key configured.")
            return IPIntelligenceResult(
                entity_id=entity_id,
                ip=clean_ip,
                category=category,
                is_routable=True,
                status=LookupStatus.PROVIDER_UNAVAILABLE,
                status_message="AbuseIPDB API key not configured.",
                source=self.name,
                attribution="UNAVAILABLE",
            )

        # 4. Perform external API call
        headers = {
            "Key": active_key,
            "Accept": "application/json",
            "User-Agent": "MAILSENTINEL-ThreatIntel/1.0",
        }
        params = {
            "ipAddress": clean_ip,
            "maxAgeInDays": str(self.max_age_in_days),
            "verbose": "true",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.base_url, headers=headers, params=params)

            if response.status_code == 200:
                try:
                    payload = response.json()
                except Exception as exc:
                    logger.warning(f"AbuseIPDB returned non-JSON payload for IP {clean_ip}: {exc}")
                    return IPIntelligenceResult(
                        entity_id=entity_id,
                        ip=clean_ip,
                        category=category,
                        is_routable=True,
                        status=LookupStatus.ERROR,
                        status_message="Malformed JSON response from AbuseIPDB.",
                        source=self.name,
                        attribution="UNAVAILABLE",
                    )

                data = payload.get("data")
                if not isinstance(data, dict):
                    logger.warning(f"AbuseIPDB payload missing 'data' object for IP {clean_ip}")
                    return IPIntelligenceResult(
                        entity_id=entity_id,
                        ip=clean_ip,
                        category=category,
                        is_routable=True,
                        status=LookupStatus.ERROR,
                        status_message="Invalid data structure from AbuseIPDB.",
                        source=self.name,
                        attribution="UNAVAILABLE",
                    )

                score = data.get("abuseConfidenceScore")
                country_code = data.get("countryCode")
                country_name = data.get("countryName")
                usage_type = data.get("usageType")
                isp = data.get("isp")
                domain = data.get("domain")
                total_reports = data.get("totalReports")
                last_reported_at = data.get("lastReportedAt")

                # Reputation normalization
                if score is not None:
                    if score >= 50:
                        reputation = ReputationStatus.KNOWN_MALICIOUS
                    elif score > 0:
                        reputation = ReputationStatus.SUSPICIOUS
                    else:
                        reputation = ReputationStatus.CLEAN
                else:
                    reputation = ReputationStatus.UNKNOWN

                return IPIntelligenceResult(
                    entity_id=entity_id,
                    ip=clean_ip,
                    category=category,
                    is_routable=True,
                    country=country_name or country_code,
                    country_code=country_code,
                    city=None,
                    region=None,
                    latitude=None,
                    longitude=None,
                    asn=None,
                    organization=isp,
                    isp=isp,
                    domain=domain,
                    usage_type=usage_type,
                    reputation=reputation,
                    source=self.name,
                    status=LookupStatus.SUCCESS,
                    status_message="Real-time verified via AbuseIPDB API.",
                    attribution="REAL-TIME",
                    cached=False,
                    abuse_confidence_score=score,
                    total_reports=total_reports,
                    last_reported_at=last_reported_at,
                )

            elif response.status_code == 429:
                logger.warning(f"AbuseIPDB rate limit exceeded for query IP: {clean_ip}")
                return IPIntelligenceResult(
                    entity_id=entity_id,
                    ip=clean_ip,
                    category=category,
                    is_routable=True,
                    status=LookupStatus.PROVIDER_UNAVAILABLE,
                    status_message="AbuseIPDB rate limit exceeded (HTTP 429).",
                    source=self.name,
                    attribution="UNAVAILABLE",
                )

            elif response.status_code in (401, 403):
                logger.warning(f"AbuseIPDB authentication error (HTTP {response.status_code})")
                return IPIntelligenceResult(
                    entity_id=entity_id,
                    ip=clean_ip,
                    category=category,
                    is_routable=True,
                    status=LookupStatus.PROVIDER_UNAVAILABLE,
                    status_message="AbuseIPDB authentication failed: invalid or unauthorized API key.",
                    source=self.name,
                    attribution="UNAVAILABLE",
                )

            else:
                logger.warning(f"AbuseIPDB returned unexpected status HTTP {response.status_code} for IP {clean_ip}")
                return IPIntelligenceResult(
                    entity_id=entity_id,
                    ip=clean_ip,
                    category=category,
                    is_routable=True,
                    status=LookupStatus.PROVIDER_UNAVAILABLE,
                    status_message=f"AbuseIPDB service error: HTTP {response.status_code}.",
                    source=self.name,
                    attribution="UNAVAILABLE",
                )

        except httpx.TimeoutException:
            logger.warning(f"Timeout querying AbuseIPDB for IP {clean_ip}")
            return IPIntelligenceResult(
                entity_id=entity_id,
                ip=clean_ip,
                category=category,
                is_routable=True,
                status=LookupStatus.TIMEOUT,
                status_message="AbuseIPDB connection timed out.",
                source=self.name,
                attribution="UNAVAILABLE",
            )

        except httpx.RequestError as exc:
            # Never include request headers in logs to protect the API key
            logger.warning(f"Network error querying AbuseIPDB for IP {clean_ip}: {exc.__class__.__name__}")
            return IPIntelligenceResult(
                entity_id=entity_id,
                ip=clean_ip,
                category=category,
                is_routable=True,
                status=LookupStatus.PROVIDER_UNAVAILABLE,
                status_message="Network connectivity error reaching AbuseIPDB.",
                source=self.name,
                attribution="UNAVAILABLE",
            )

        except Exception as exc:
            logger.error(f"Unexpected error in AbuseIPDB provider for IP {clean_ip}: {exc}", exc_info=True)
            return IPIntelligenceResult(
                entity_id=entity_id,
                ip=clean_ip,
                category=category,
                is_routable=True,
                status=LookupStatus.ERROR,
                status_message=f"Internal error processing AbuseIPDB lookup: {str(exc)}",
                source=self.name,
                attribution="UNAVAILABLE",
            )
