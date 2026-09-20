from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.services.auth import User, get_current_user
from app.services.forensics.service import investigation_registry
from app.services.intelligence import (
    DomainIntelligenceResult,
    EmailAddressIntelligenceResult,
    EmailRole,
    IPIntelligenceResult,
    InvestigationIntelligenceResult,
    ReputationStatus,
    URLIntelligenceResult,
    default_intelligence_service,
)
from app.services.intelligence.correlation import (
    CorrelationRelationship,
    CorrelationSummary,
    CorrelationThreatSignal,
    IndicatorCorrelationResult,
)
from app.services.intelligence.providers.email_provider import DISPOSABLE_EMAIL_DOMAINS

router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence"])


class IPLookupRequest(BaseModel):
    ip: str = Field(..., description="IPv4 or IPv6 address to analyze", json_schema_extra={"example": "185.220.101.5"})


class DomainLookupRequest(BaseModel):
    domain: str = Field(..., description="Domain name to analyze", json_schema_extra={"example": "paypa1-security.com"})


class URLLookupRequest(BaseModel):
    url: str = Field(..., description="URL string to analyze", json_schema_extra={"example": "http://185.220.101.5/auth/login.php"})


class EmailLookupRequest(BaseModel):
    email: str = Field(..., description="Email address to analyze", json_schema_extra={"example": "support@paypa1-security.com"})
    role: Optional[str] = Field(default="SENDER", description="SENDER, REPLY_TO, RETURN_PATH, RECIPIENT, CC, BCC")


class IndicatorCorrelationRequest(BaseModel):
    investigation_id: Optional[str] = Field(default=None, description="Optional existing investigation ID")
    emails: List[str] = Field(default_factory=list, description="Email addresses to correlate")
    domains: List[str] = Field(default_factory=list, description="Domain names to correlate")
    urls: List[str] = Field(default_factory=list, description="URLs to correlate")
    ips: List[str] = Field(default_factory=list, description="IP addresses to correlate")


class InvestigationEnrichmentRequest(BaseModel):
    ips: List[str] = Field(default_factory=list, description="List of IP addresses extracted from investigation")
    domains: List[str] = Field(default_factory=list, description="List of domains extracted from investigation")
    urls: List[str] = Field(default_factory=list, description="List of URLs extracted from investigation")
    emails: List[str] = Field(default_factory=list, description="List of email addresses extracted from investigation")


@router.post("/ip", response_model=IPIntelligenceResult, status_code=status.HTTP_200_OK)
async def lookup_ip_intelligence(
    request: IPLookupRequest,
    current_user: User = Depends(get_current_user),
) -> IPIntelligenceResult:
    """
    Performs deterministic IP classification, RFC private network filtering,
    ASN determination, and backend geolocation enrichment.
    """
    if not request.ip or not request.ip.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IP address cannot be empty.")
    return await default_intelligence_service.get_ip_intelligence(request.ip)


@router.post("/domain", response_model=DomainIntelligenceResult, status_code=status.HTTP_200_OK)
async def lookup_domain_intelligence(
    request: DomainLookupRequest,
    current_user: User = Depends(get_current_user),
) -> DomainIntelligenceResult:
    """
    Performs domain structural analysis, homoglyph / punycode detection,
    TLD risk tagging, and reference threat evaluation.
    """
    if not request.domain or not request.domain.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain cannot be empty.")
    return await default_intelligence_service.get_domain_intelligence(request.domain)


@router.post("/url", response_model=URLIntelligenceResult, status_code=status.HTTP_200_OK)
async def lookup_url_intelligence(
    request: URLLookupRequest,
    current_user: User = Depends(get_current_user),
) -> URLIntelligenceResult:
    """
    Performs URL structural decomposition, IP-in-host detection,
    credential path detection, and destination reputation lookup.
    """
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL cannot be empty.")
    return await default_intelligence_service.get_url_intelligence(request.url)


@router.post("/email", response_model=EmailAddressIntelligenceResult, status_code=status.HTTP_200_OK)
async def lookup_email_intelligence(
    request: EmailLookupRequest,
    current_user: User = Depends(get_current_user),
) -> EmailAddressIntelligenceResult:
    """
    Performs RFC 5322 normalization, disposable email provider identification,
    free consumer provider classification, and syntax validation.
    """
    if not request.email or not request.email.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email address cannot be empty.")
    role_enum = EmailRole.SENDER
    if request.role:
        try:
            role_enum = EmailRole(request.role.upper())
        except ValueError:
            role_enum = EmailRole.SENDER
    return await default_intelligence_service.get_email_intelligence(request.email, role=role_enum)


@router.post("/investigation/{investigation_id}", response_model=InvestigationIntelligenceResult, status_code=status.HTTP_200_OK)
async def enrich_investigation_intelligence(
    investigation_id: str,
    request: InvestigationEnrichmentRequest,
    current_user: User = Depends(get_current_user),
) -> InvestigationIntelligenceResult:
    """
    Batch enriches all observable entities in an investigation.
    """
    return await default_intelligence_service.enrich_investigation(
        investigation_id=investigation_id,
        ips=request.ips,
        domains=request.domains,
        urls=request.urls,
        emails=request.emails,
    )


@router.post("/correlate", response_model=IndicatorCorrelationResult, status_code=status.HTTP_200_OK)
async def correlate_indicators(
    request: IndicatorCorrelationRequest,
    current_user: User = Depends(get_current_user),
) -> IndicatorCorrelationResult:
    """
    Correlates extracted emails, domains, URLs, and IPs into an interconnected
    threat relationship graph with structural threat signal analysis.
    """
    inv_id = request.investigation_id
    if inv_id:
        cached_corr = investigation_registry.get_correlation(inv_id)
        if cached_corr:
            return cached_corr
        forensic = investigation_registry.get_forensic(inv_id)
        if forensic:
            intel = investigation_registry.get_intelligence(inv_id)
            if not intel:
                intel = await default_intelligence_service.enrich_investigation(
                    investigation_id=inv_id,
                    ips=[hop.ip for hop in forensic.received_chain if hop.ip] or [ip.ip for ip in forensic.ip_addresses],
                    domains=[d.domain for d in forensic.domains],
                    urls=[u.normalized_url for u in forensic.urls],
                )
            corr = await default_intelligence_service.correlate_investigation(
                investigation_id=inv_id,
                forensic=forensic,
                intelligence=intel,
            )
            investigation_registry.store(
                inv_id, forensic, investigation_registry.get_threat(inv_id), intel, correlation=corr
            )
            return corr

    # Ad-hoc correlation across provided entity lists
    actual_id = inv_id or "adhoc-correlation"
    unique_emails = list(dict.fromkeys(e.strip() for e in request.emails if e.strip()))
    unique_domains = list(dict.fromkeys(d.strip().lower() for d in request.domains if d.strip()))
    unique_urls = list(dict.fromkeys(u.strip() for u in request.urls if u.strip()))
    unique_ips = list(dict.fromkeys(i.strip() for i in request.ips if i.strip()))

    email_res = [await default_intelligence_service.get_email_intelligence(e) for e in unique_emails]
    dom_res = [await default_intelligence_service.get_domain_intelligence(d) for d in unique_domains]
    url_res = [await default_intelligence_service.get_url_intelligence(u) for u in unique_urls]
    ip_res = [await default_intelligence_service.get_ip_intelligence(i) for i in unique_ips]

    relationships: List[CorrelationRelationship] = []
    signals: List[CorrelationThreatSignal] = []

    # Email -> Domain
    for em in email_res:
        if em.domain:
            relationships.append(
                CorrelationRelationship(
                    source=em.entity_id,
                    source_type="EMAIL",
                    target=f"domain:{em.domain}",
                    target_type="DOMAIN",
                    relationship="BELONGS_TO_DOMAIN",
                    evidence=f"Address @{em.domain} belongs to domain",
                    confidence=1.0,
                )
            )

    # URL -> Domain / Host
    for u in url_res:
        if u.is_ip_host:
            relationships.append(
                CorrelationRelationship(
                    source=u.entity_id,
                    source_type="URL",
                    target=f"ip:{u.domain}",
                    target_type="IP",
                    relationship="HOSTED_ON",
                    evidence="URL destination host is a direct IP address",
                    confidence=1.0,
                )
            )
        elif u.domain:
            relationships.append(
                CorrelationRelationship(
                    source=u.entity_id,
                    source_type="URL",
                    target=f"domain:{u.domain.lower()}",
                    target_type="DOMAIN",
                    relationship="HOSTED_ON",
                    evidence=f"URL host belongs to domain {u.domain.lower()}",
                    confidence=1.0,
                )
            )

    # Domain -> IP
    for d in dom_res:
        for a_rec in d.a_records:
            relationships.append(
                CorrelationRelationship(
                    source=d.entity_id,
                    source_type="DOMAIN",
                    target=f"ip:{a_rec}",
                    target_type="IP",
                    relationship="RESOLVES_TO",
                    evidence=f"DNS resolution: {d.normalized_domain} -> {a_rec}",
                    confidence=0.95,
                )
            )

    mismatches = 0
    infra_overlaps = 0

    # 1. Email domains mismatch
    domains_in_emails = list({e.domain for e in email_res if e.domain})
    if len(domains_in_emails) > 1:
        mismatches += 1
        signals.append(
            CorrelationThreatSignal(
                signal_id="CORR_SENDER_REPLYTO_MISMATCH",
                title="Email Identities Domain Discrepancy",
                description=f"Multiple email entities use divergent domains ({', '.join(domains_in_emails[:3])}).",
                severity="HIGH",
                weight=6.0,
                entities_involved=[e.entity_id for e in email_res],
            )
        )

    # 2. URL IP Host
    ip_urls = [u for u in url_res if u.is_ip_host]
    if ip_urls:
        signals.append(
            CorrelationThreatSignal(
                signal_id="CORR_URL_IP_HOSTNAME",
                title="Direct IP Address in Hyperlink",
                description=f"Found {len(ip_urls)} link(s) using direct IP hosts instead of domain names.",
                severity="HIGH",
                weight=5.0,
                entities_involved=[u.entity_id for u in ip_urls],
            )
        )

    # 3. Disposable email
    for em in email_res:
        if em.is_disposable:
            signals.append(
                CorrelationThreatSignal(
                    signal_id="CORR_DISPOSABLE_EMAIL_SENDER",
                    title="Disposable Email Provider Detected",
                    description=f"Address '{em.normalized_address}' uses disposable provider '@{em.domain}'.",
                    severity="HIGH",
                    weight=6.0,
                    entities_involved=[em.entity_id],
                )
            )

    # 4. Reputation overlaps
    malicious_ips = [i for i in ip_res if i.reputation in (ReputationStatus.KNOWN_MALICIOUS, ReputationStatus.SUSPICIOUS)]
    if malicious_ips:
        infra_overlaps += len(malicious_ips)
        signals.append(
            CorrelationThreatSignal(
                signal_id="CORR_REPUTATION_MALICIOUS_IP",
                title="Suspicious/Malicious Infrastructure Linkage",
                description=f"Detected {len(malicious_ips)} IP entity/entities associated with known attack infrastructure.",
                severity="CRITICAL",
                weight=8.0,
                entities_involved=[i.entity_id for i in malicious_ips],
            )
        )

    summary = CorrelationSummary(
        total_indicators=len(email_res) + len(dom_res) + len(url_res) + len(ip_res),
        total_relationships=len(relationships),
        total_signals=len(signals),
        mismatches_detected=mismatches,
        infrastructure_overlap=infra_overlaps,
    )

    return IndicatorCorrelationResult(
        investigation_id=actual_id,
        emails=email_res,
        domains=dom_res,
        urls=url_res,
        ips=ip_res,
        relationships=relationships,
        signals=signals,
        summary=summary,
    )


@router.get("/investigation/{investigation_id}/correlation", response_model=IndicatorCorrelationResult, status_code=status.HTTP_200_OK)
async def get_investigation_correlation(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
) -> IndicatorCorrelationResult:
    """
    Returns the correlated multi-entity indicator relationship graph and threat signals
    for an existing email investigation.
    """
    await investigation_registry.ensure_seeded()
    corr = investigation_registry.get_correlation(investigation_id)
    if corr:
        return corr

    forensic = investigation_registry.get_forensic(investigation_id)
    if not forensic:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation {investigation_id} not found."
        )

    intel = investigation_registry.get_intelligence(investigation_id)
    if not intel:
        intel = await default_intelligence_service.enrich_investigation(
            investigation_id=investigation_id,
            ips=[hop.ip for hop in forensic.received_chain if hop.ip] or [ip.ip for ip in forensic.ip_addresses],
            domains=[d.domain for d in forensic.domains],
            urls=[u.normalized_url for u in forensic.urls],
        )

    corr = await default_intelligence_service.correlate_investigation(
        investigation_id=investigation_id,
        forensic=forensic,
        intelligence=intel,
    )
    investigation_registry.store(
        investigation_id, forensic, investigation_registry.get_threat(investigation_id), intel, correlation=corr
    )
    return corr
