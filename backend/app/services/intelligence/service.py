import asyncio
import logging
from typing import Any, List, Optional

from app.core.config import settings
from app.services.intelligence.cache import IntelligenceCache, default_intel_cache
from app.services.intelligence.models import (
    DomainIntelligenceResult,
    EmailAddressIntelligenceResult,
    EmailRole,
    IPCategory,
    IPIntelligenceResult,
    InvestigationIntelligenceResult,
    InvestigationIntelligenceSummary,
    LookupStatus,
    ReputationStatus,
    URLIntelligenceResult,
)
from app.services.intelligence.providers.abuseipdb_provider import (
    AbuseIPDBProvider,
)
from app.services.intelligence.providers.base import (
    BaseDomainIntelligenceProvider,
    BaseIPIntelligenceProvider,
    BaseURLIntelligenceProvider,
)
from app.services.intelligence.providers.email_provider import (
    EmailAddressIntelligenceProvider,
    default_email_provider,
)
from app.services.intelligence.correlation import (
    IndicatorCorrelationResult,
    correlate_investigation_indicators,
)
from app.services.intelligence.providers.domain_provider import (
    OfflineDomainIntelligenceProvider,
)
from app.services.intelligence.providers.ip_provider import (
    OfflineIPIntelligenceProvider,
    classify_ip_address,
)
from app.services.intelligence.providers.url_provider import (
    OfflineURLIntelligenceProvider,
)

logger = logging.getLogger("mailsentinel.intelligence")


class IntelligenceService:
    """
    Unified threat intelligence and entity enrichment coordinator.
    Orchestrates real-time providers (AbuseIPDB), deterministic offline fallbacks,
    domain structural/DNS, and URL intelligence with thread-safe TTL caching.
    """

    def __init__(
        self,
        ip_provider: Optional[BaseIPIntelligenceProvider] = None,
        domain_provider: Optional[BaseDomainIntelligenceProvider] = None,
        url_provider: Optional[BaseURLIntelligenceProvider] = None,
        email_provider: Optional[EmailAddressIntelligenceProvider] = None,
        cache: Optional[IntelligenceCache] = None,
        abuseipdb_provider: Optional[AbuseIPDBProvider] = None,
        offline_ip_provider: Optional[BaseIPIntelligenceProvider] = None,
    ):
        self.ip_provider = ip_provider
        self.abuseipdb_provider = abuseipdb_provider or AbuseIPDBProvider(
            api_key=getattr(settings, "ABUSEIPDB_API_KEY", None)
        )
        self.offline_ip_provider = offline_ip_provider or OfflineIPIntelligenceProvider()
        self.domain_provider = domain_provider or OfflineDomainIntelligenceProvider()
        self.url_provider = url_provider or OfflineURLIntelligenceProvider()
        self.email_provider = email_provider or default_email_provider
        self.cache = cache or default_intel_cache

    async def get_ip_intelligence(self, ip: str) -> IPIntelligenceResult:
        clean_ip = ip.strip()
        entity_id = f"ip:{clean_ip}"

        # 1. RFC Boundary classification check (strict RFC 1918 / 5737 / loopback / reserved isolation)
        category, is_routable, _ = classify_ip_address(clean_ip)
        if category == IPCategory.INVALID:
            return IPIntelligenceResult(
                entity_id=entity_id,
                ip=clean_ip,
                category=category,
                is_routable=False,
                status=LookupStatus.ERROR,
                status_message="Invalid IPv4/IPv6 address syntax.",
                source="rfc_ip_classifier",
                attribution="UNAVAILABLE",
            )
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

        # 2. Check Cache
        cache_key = f"ip:{clean_ip}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            if hasattr(cached, "model_copy"):
                return cached.model_copy(update={"cached": True, "attribution": "CACHED"})
            return cached

        # 3. If explicit custom ip_provider was provided, respect it directly (for test fixtures)
        if self.ip_provider is not None and not isinstance(
            self.ip_provider, (AbuseIPDBProvider, OfflineIPIntelligenceProvider)
        ):
            try:
                result = await self.ip_provider.lookup_ip(clean_ip)
            except Exception as exc:
                logger.error(f"Error querying custom IP provider for {clean_ip}: {exc}", exc_info=True)
                result = IPIntelligenceResult(
                    entity_id=entity_id,
                    ip=clean_ip,
                    category=category,
                    is_routable=True,
                    status=LookupStatus.ERROR,
                    status_message=str(exc),
                    attribution="UNAVAILABLE",
                )
            self.cache.set(cache_key, result)
            return result

        result: Optional[IPIntelligenceResult] = None

        # 4. Attempt Real-Time Lookup (AbuseIPDB) if configured
        real_provider = (
            self.ip_provider
            if isinstance(self.ip_provider, AbuseIPDBProvider)
            else self.abuseipdb_provider
        )
        if real_provider and real_provider.is_configured:
            try:
                real_res = await real_provider.lookup_ip(clean_ip)
                if real_res.status == LookupStatus.SUCCESS:
                    result = real_res
                else:
                    logger.warning(
                        f"Real-time IP provider ({real_provider.name}) failed for {clean_ip}: "
                        f"{real_res.status_message}. Falling back to offline intelligence."
                    )
            except Exception as exc:
                logger.warning(f"Error querying real-time provider for {clean_ip}: {exc}. Falling back to offline intelligence.")

        # 5. Fallback to Offline Intelligence Provider
        if result is None:
            try:
                offline_provider = (
                    self.ip_provider
                    if isinstance(self.ip_provider, OfflineIPIntelligenceProvider)
                    else self.offline_ip_provider
                )
                result = await offline_provider.lookup_ip(clean_ip)
            except Exception as exc:
                logger.error(f"Error querying offline IP provider for {clean_ip}: {exc}", exc_info=True)
                result = IPIntelligenceResult(
                    entity_id=entity_id,
                    ip=clean_ip,
                    category=category,
                    is_routable=True,
                    status=LookupStatus.NOT_AVAILABLE,
                    status_message="External threat intelligence provider unavailable; offline intelligence was also unavailable.",
                    source="Offline Intelligence",
                    attribution="UNAVAILABLE",
                )

        # 6. Save in Cache and Return
        self.cache.set(cache_key, result)
        return result

    async def get_domain_intelligence(self, domain: str) -> DomainIntelligenceResult:
        clean_domain = domain.strip().lower()
        cache_key = f"domain:{clean_domain}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            result = await self.domain_provider.lookup_domain(clean_domain)
        except Exception as exc:
            logger.error(f"Error querying Domain provider for {clean_domain}: {exc}", exc_info=True)
            result = DomainIntelligenceResult(
                entity_id=f"domain:{clean_domain}",
                domain=clean_domain,
                normalized_domain=clean_domain,
                status=LookupStatus.ERROR,
                status_message=str(exc),
            )

        self.cache.set(cache_key, result)
        return result

    async def get_url_intelligence(self, url: str) -> URLIntelligenceResult:
        clean_url = url.strip()
        cache_key = f"url:{clean_url}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            result = await self.url_provider.lookup_url(clean_url)
        except Exception as exc:
            logger.error(f"Error querying URL provider for {clean_url}: {exc}", exc_info=True)
            result = URLIntelligenceResult(
                entity_id=f"url:{clean_url}",
                url=clean_url,
                normalized_url=clean_url,
                domain="",
                status=LookupStatus.ERROR,
                status_message=str(exc),
            )

        self.cache.set(cache_key, result)
        return result

    async def get_email_intelligence(
        self, email: str, role: EmailRole = EmailRole.SENDER
    ) -> EmailAddressIntelligenceResult:
        clean_email = email.strip()
        cache_key = f"email:{clean_email.lower()}:{role.value}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            if hasattr(cached, "model_copy"):
                return cached.model_copy(update={"cached": True, "attribution": "CACHED"})
            return cached

        try:
            result = await self.email_provider.lookup_email(clean_email, role=role)
        except Exception as exc:
            logger.error(f"Error querying Email provider for {clean_email}: {exc}", exc_info=True)
            result = EmailAddressIntelligenceResult(
                entity_id=f"email:{clean_email.lower()}",
                raw_address=clean_email,
                normalized_address=clean_email.lower(),
                role=role,
                status=LookupStatus.ERROR,
                status_message=str(exc),
                attribution="LOCAL ANALYSIS",
            )

        self.cache.set(cache_key, result)
        return result

    async def correlate_investigation(
        self,
        investigation_id: str,
        forensic: Any,
        intelligence: Optional[InvestigationIntelligenceResult] = None,
        emails: Optional[List[EmailAddressIntelligenceResult]] = None,
    ) -> IndicatorCorrelationResult:
        return await correlate_investigation_indicators(
            investigation_id=investigation_id,
            forensic=forensic,
            intelligence=intelligence,
            emails=emails,
        )

    async def enrich_investigation(
        self,
        investigation_id: str,
        ips: List[str],
        domains: List[str],
        urls: List[str],
        emails: Optional[List[str]] = None,
    ) -> InvestigationIntelligenceResult:
        """
        Enriches all unique network entities extracted from an email investigation.
        Executes lookups concurrently with deduplication.
        """
        unique_ips = list(dict.fromkeys(ip.strip() for ip in ips if ip and ip.strip()))
        unique_domains = list(dict.fromkeys(d.strip().lower() for d in domains if d and d.strip()))
        unique_urls = list(dict.fromkeys(u.strip() for u in urls if u and u.strip()))
        unique_emails = list(dict.fromkeys(e.strip() for e in (emails or []) if e and e.strip()))

        ip_tasks = [self.get_ip_intelligence(ip) for ip in unique_ips]
        domain_tasks = [self.get_domain_intelligence(d) for d in unique_domains]
        url_tasks = [self.get_url_intelligence(u) for u in unique_urls]
        email_tasks = [self.get_email_intelligence(e) for e in unique_emails]

        ip_results = await asyncio.gather(*ip_tasks) if ip_tasks else []
        domain_results = await asyncio.gather(*domain_tasks) if domain_tasks else []
        url_results = await asyncio.gather(*url_tasks) if url_tasks else []
        email_results = await asyncio.gather(*email_tasks) if email_tasks else []

        total_analyzed = len(ip_results) + len(domain_results) + len(url_results) + len(email_results)
        successful = 0
        private_skipped = 0
        unknown_or_unavailable = 0

        for r in ip_results:
            if r.status == LookupStatus.SUCCESS:
                successful += 1
            elif r.status == LookupStatus.PRIVATE_IP_SKIPPED:
                private_skipped += 1
            else:
                unknown_or_unavailable += 1

        for r in domain_results:
            if r.status == LookupStatus.SUCCESS:
                successful += 1
            else:
                unknown_or_unavailable += 1

        for r in url_results:
            if r.status == LookupStatus.SUCCESS:
                successful += 1
            else:
                unknown_or_unavailable += 1

        for r in email_results:
            if r.status == LookupStatus.SUCCESS:
                successful += 1
            else:
                unknown_or_unavailable += 1

        summary = InvestigationIntelligenceSummary(
            entities_analyzed=total_analyzed,
            successful_lookups=successful,
            private_skipped=private_skipped,
            unknown_or_unavailable=unknown_or_unavailable,
        )

        return InvestigationIntelligenceResult(
            investigation_id=investigation_id,
            ips=list(ip_results),
            domains=list(domain_results),
            urls=list(url_results),
            emails=list(email_results),
            summary=summary,
        )


default_intelligence_service = IntelligenceService()
