from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field

from app.services.email.models import EmailForensicResult
from app.services.intelligence.models import (
    DomainIntelligenceResult,
    EmailAddressIntelligenceResult,
    EmailRole,
    IPIntelligenceResult,
    InvestigationIntelligenceResult,
    LookupStatus,
    ReputationStatus,
    URLIntelligenceResult,
)
from app.services.intelligence.providers.email_provider import default_email_provider

logger = logging.getLogger("mailsentinel.intelligence.correlation")


class CorrelationRelationship(BaseModel):
    source: str = Field(..., description="Source entity ID, e.g. url:https://example.com/login")
    source_type: str = Field(..., description="EMAIL, DOMAIN, URL, IP, HEADER")
    target: str = Field(..., description="Target entity ID, e.g. domain:example.com")
    target_type: str = Field(..., description="EMAIL, DOMAIN, URL, IP, ASN")
    relationship: str = Field(..., description="HOSTED_ON, RESOLVES_TO, BELONGS_TO_DOMAIN, SENT_FROM, REPLY_TO, RECEIVED_FROM, ASSOCIATED_WITH")
    evidence: str = Field(..., description="Technical rationale / evidentiary link")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class CorrelationThreatSignal(BaseModel):
    signal_id: str = Field(...)
    title: str = Field(...)
    description: str = Field(...)
    severity: str = Field(default="MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    weight: float = Field(default=5.0)
    entities_involved: List[str] = Field(default_factory=list)


class CorrelationSummary(BaseModel):
    total_indicators: int = Field(default=0)
    total_relationships: int = Field(default=0)
    total_signals: int = Field(default=0)
    mismatches_detected: int = Field(default=0)
    infrastructure_overlap: int = Field(default=0)


class IndicatorCorrelationResult(BaseModel):
    investigation_id: str
    emails: List[EmailAddressIntelligenceResult] = Field(default_factory=list)
    domains: List[DomainIntelligenceResult] = Field(default_factory=list)
    urls: List[URLIntelligenceResult] = Field(default_factory=list)
    ips: List[IPIntelligenceResult] = Field(default_factory=list)
    relationships: List[CorrelationRelationship] = Field(default_factory=list)
    signals: List[CorrelationThreatSignal] = Field(default_factory=list)
    summary: CorrelationSummary
    correlated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


async def correlate_investigation_indicators(
    investigation_id: str,
    forensic: EmailForensicResult,
    intelligence: Optional[InvestigationIntelligenceResult] = None,
    emails: Optional[List[EmailAddressIntelligenceResult]] = None,
) -> IndicatorCorrelationResult:
    """
    Correlates all observable email, domain, URL, and IP indicators into a unified
    evidence graph, establishing structural linkages and computing correlation-based threat signals.
    """
    relationships: List[CorrelationRelationship] = []
    signals: List[CorrelationThreatSignal] = []

    # 1. Normalize Email Addresses
    email_results: List[EmailAddressIntelligenceResult] = []
    if emails:
        email_results = list(emails)
    else:
        # Extract sender, reply-to, return-path, and recipients
        if forensic.metadata.from_address:
            sender_res = await default_email_provider.lookup_email(
                forensic.metadata.from_address, role=EmailRole.SENDER
            )
            email_results.append(sender_res)

        if forensic.metadata.reply_to and forensic.metadata.reply_to != forensic.metadata.from_address:
            reply_res = await default_email_provider.lookup_email(
                forensic.metadata.reply_to, role=EmailRole.REPLY_TO
            )
            email_results.append(reply_res)

        if forensic.metadata.return_path and forensic.metadata.return_path not in (forensic.metadata.from_address, forensic.metadata.reply_to):
            ret_res = await default_email_provider.lookup_email(
                forensic.metadata.return_path, role=EmailRole.RETURN_PATH
            )
            email_results.append(ret_res)

        for to_addr in forensic.metadata.to_addresses:
            to_res = await default_email_provider.lookup_email(to_addr, role=EmailRole.RECIPIENT)
            email_results.append(to_res)

    # 2. Collect Domains, URLs, IPs from intelligence bundle or forensics
    domain_results = intelligence.domains if intelligence else []
    url_results = intelligence.urls if intelligence else []
    ip_results = intelligence.ips if intelligence else []

    domain_map: Dict[str, DomainIntelligenceResult] = {d.normalized_domain: d for d in domain_results}
    ip_map: Dict[str, IPIntelligenceResult] = {ip.ip: ip for ip in ip_results}

    # 3. Establish Relationships:
    # A. Email -> Domain
    for em in email_results:
        if em.domain:
            relationships.append(
                CorrelationRelationship(
                    source=em.entity_id,
                    source_type="EMAIL",
                    target=f"domain:{em.domain}",
                    target_type="DOMAIN",
                    relationship="BELONGS_TO_DOMAIN",
                    evidence=f"Address @{em.domain} associated with role {em.role.value}",
                    confidence=1.0,
                )
            )

    # B. URL -> Domain / Host
    for u in url_results:
        norm_dom = u.domain.lower()
        if u.is_ip_host:
            relationships.append(
                CorrelationRelationship(
                    source=u.entity_id,
                    source_type="URL",
                    target=f"ip:{norm_dom}",
                    target_type="IP",
                    relationship="HOSTED_ON",
                    evidence="URL destination host is a direct IP address",
                    confidence=1.0,
                )
            )
        else:
            relationships.append(
                CorrelationRelationship(
                    source=u.entity_id,
                    source_type="URL",
                    target=f"domain:{norm_dom}",
                    target_type="DOMAIN",
                    relationship="HOSTED_ON",
                    evidence=f"URL host belongs to domain {norm_dom}",
                    confidence=1.0,
                )
            )

    # C. Domain -> IP (DNS A-records or shared threat infrastructure)
    for d in domain_results:
        for a_rec in d.a_records:
            relationships.append(
                CorrelationRelationship(
                    source=d.entity_id,
                    source_type="DOMAIN",
                    target=f"ip:{a_rec}",
                    target_type="IP",
                    relationship="RESOLVES_TO",
                    evidence=f"DNS A-record resolution: {d.normalized_domain} -> {a_rec}",
                    confidence=0.95,
                )
            )

    # D. Hop / Received -> IP
    for hop in forensic.received_chain:
        if hop.ip:
            relationships.append(
                CorrelationRelationship(
                    source=f"email:{investigation_id}",
                    source_type="EMAIL",
                    target=f"ip:{hop.ip}",
                    target_type="IP",
                    relationship="RECEIVED_FROM",
                    evidence=f"SMTP relay hop {hop.hop}: {hop.from_host or 'N/A'} via {hop.by_host or 'N/A'}",
                    confidence=0.95,
                )
            )

    # 4. Compute Correlation Threat Signals
    sender_em = next((e for e in email_results if e.role == EmailRole.SENDER), None)
    reply_em = next((e for e in email_results if e.role == EmailRole.REPLY_TO), None)
    sender_dom = sender_em.domain if sender_em else ""
    reply_dom = reply_em.domain if reply_em else ""

    mismatches = 0
    infra_overlaps = 0

    # Signal 1: Sender domain != Reply-To domain
    if sender_dom and reply_dom and sender_dom != reply_dom:
        mismatches += 1
        signals.append(
            CorrelationThreatSignal(
                signal_id="CORR_SENDER_REPLYTO_MISMATCH",
                title="Sender and Reply-To Domain Discrepancy",
                description=f"From address domain ({sender_dom}) differs from Reply-To domain ({reply_dom}), common in BEC and deceptive routing.",
                severity="HIGH",
                weight=6.0,
                entities_involved=[sender_em.entity_id, reply_em.entity_id],
            )
        )

    # Signal 2: Sender domain vs URL domain mismatch
    url_domains = list({u.domain.lower() for u in url_results if not u.is_ip_host})
    if sender_dom and url_domains:
        # If none of the URL domains match the sender domain or its registrable domain
        mismatched_urls = [u for u in url_results if sender_dom not in u.domain.lower() and not u.is_ip_host]
        if len(mismatched_urls) == len(url_results) and len(url_results) > 0:
            # All URLs point to domains completely unrelated to sender
            mismatches += 1
            signals.append(
                CorrelationThreatSignal(
                    signal_id="CORR_SENDER_URL_DOMAIN_MISMATCH",
                    title="External URL Domain Divergence",
                    description=f"All body hyperlinks direct to external third-party domains ({', '.join(url_domains[:3])}) unrelated to sender domain ({sender_dom}).",
                    severity="HIGH",
                    weight=6.0,
                    entities_involved=[sender_em.entity_id] + [u.entity_id for u in mismatched_urls[:3]],
                )
            )

    # Signal 3: URL host is direct IP address
    ip_urls = [u for u in url_results if u.is_ip_host]
    if ip_urls:
        signals.append(
            CorrelationThreatSignal(
                signal_id="CORR_URL_IP_HOSTNAME",
                title="Direct IP Address in Hyperlink",
                description=f"Found {len(ip_urls)} link(s) using raw IP hosts instead of domain names to bypass standard domain reputation filters.",
                severity="HIGH",
                weight=5.0,
                entities_involved=[u.entity_id for u in ip_urls],
            )
        )

    # Signal 4: Known malicious IP association
    malicious_ips = [
        ip for ip in ip_results
        if ip.reputation in (ReputationStatus.KNOWN_MALICIOUS, ReputationStatus.SUSPICIOUS)
    ]
    if malicious_ips:
        infra_overlaps += len(malicious_ips)
        signals.append(
            CorrelationThreatSignal(
                signal_id="CORR_REPUTATION_MALICIOUS_IP",
                title="Suspicious/Malicious Infrastructure Linkage",
                description=f"Correlated {len(malicious_ips)} IP entity/entities with adverse threat intelligence reputation records.",
                severity="CRITICAL" if any(ip.reputation == ReputationStatus.KNOWN_MALICIOUS for ip in malicious_ips) else "HIGH",
                weight=7.5,
                entities_involved=[ip.entity_id for ip in malicious_ips],
            )
        )

    # Signal 5: Multiple URLs pointing to same suspicious domain
    susp_domains = [
        d for d in domain_results
        if d.reputation in (ReputationStatus.KNOWN_MALICIOUS, ReputationStatus.SUSPICIOUS)
        or any("Typosquatting" in s or "Homoglyph" in s for s in d.structural_indicators)
    ]
    for s_dom in susp_domains:
        related_urls = [u for u in url_results if s_dom.normalized_domain in u.domain.lower()]
        if len(related_urls) >= 2:
            infra_overlaps += 1
            signals.append(
                CorrelationThreatSignal(
                    signal_id="CORR_MULTIPLE_URLS_SAME_SUSP_DOMAIN",
                    title="Repeated Suspicious Domain References",
                    description=f"Multiple body hyperlinks ({len(related_urls)}) converge upon suspicious domain '{s_dom.normalized_domain}'.",
                    severity="MEDIUM",
                    weight=4.0,
                    entities_involved=[s_dom.entity_id] + [u.entity_id for u in related_urls],
                )
            )

    # Signal 6: Excessive disparate external domains (> 5 unique domains)
    if len(domain_results) > 5:
        signals.append(
            CorrelationThreatSignal(
                signal_id="CORR_EXCESSIVE_EXTERNAL_DOMAINS",
                title="High External Domain Density",
                description=f"Message references {len(domain_results)} distinct domains, an anomalous dispersion common in phishing templates and tracking rings.",
                severity="LOW",
                weight=2.0,
                entities_involved=[d.entity_id for d in domain_results[:5]],
            )
        )

    # Signal 7: Disposable email provider in sender or reply-to
    disp_emails = [e for e in email_results if getattr(e, "is_disposable", False) or getattr(e, "is_disposable_domain", False)]
    if disp_emails:
        mismatches += 1
        signals.append(
            CorrelationThreatSignal(
                signal_id="CORR_DISPOSABLE_EMAIL_SENDER",
                title="Disposable Email Provider Detected",
                description=f"Address '{disp_emails[0].normalized_email}' utilizes disposable email provider '@{disp_emails[0].domain}'.",
                severity="HIGH",
                weight=6.0,
                entities_involved=[e.entity_id for e in disp_emails],
            )
        )

    # 5. Build Summary
    total_entities = len(email_results) + len(domain_results) + len(url_results) + len(ip_results)
    summary = CorrelationSummary(
        total_indicators=total_entities,
        total_relationships=len(relationships),
        total_signals=len(signals),
        mismatches_detected=mismatches,
        infrastructure_overlap=infra_overlaps,
    )

    return IndicatorCorrelationResult(
        investigation_id=investigation_id,
        emails=email_results,
        domains=domain_results,
        urls=url_results,
        ips=ip_results,
        relationships=relationships,
        signals=signals,
        summary=summary,
    )
