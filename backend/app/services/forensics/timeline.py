from typing import List, Optional
from email.utils import parsedate_to_datetime

from app.services.email.models import AuthenticationVerdict, EmailForensicResult
from app.services.forensics.models import (
    TimelineEvent,
    TimelineEventType,
    TimestampPrecision,
)
from app.services.intelligence.models import (
    InvestigationIntelligenceResult,
    LookupStatus,
    ReputationStatus,
)
from app.services.risk.models import ThreatAssessmentResult


def parse_rfc_date_to_iso(date_str: Optional[str]) -> Optional[str]:
    """Safely converts an RFC 2822 / 5322 date string to ISO format without inventing data."""
    if not date_str or not date_str.strip():
        return None
    try:
        dt = parsedate_to_datetime(date_str.strip())
        return dt.isoformat()
    except Exception:
        return None


def build_forensic_timeline(
    forensic: EmailForensicResult,
    threat_assessment: Optional[ThreatAssessmentResult] = None,
    intelligence: Optional[InvestigationIntelligenceResult] = None,
) -> List[TimelineEvent]:
    """
    Transforms structured forensic evidence, threat indicators, and intelligence lookups
    into an ordered forensic timeline.
    Strictly preserves evidence timestamps when available; never fabricates fake dates.
    """
    events: List[TimelineEvent] = []
    inv_id = forensic.investigation_id
    seq = 1

    def next_evt_id() -> str:
        nonlocal seq
        eid = f"evt-{seq:03d}"
        seq += 1
        return eid

    # 1. Evidence Ingestion & Hashing
    events.append(
        TimelineEvent(
            event_id=next_evt_id(),
            investigation_id=inv_id,
            timestamp=forensic.analyzed_at,
            timestamp_precision=TimestampPrecision.SECOND,
            event_type=TimelineEventType.EVIDENCE_HASHED,
            title="Evidence Ingested & Cryptographically Hashed",
            description=f"Raw container '{forensic.file_name}' ({forensic.file_size_bytes} bytes) hashed with SHA-256: {forensic.sha256_digest[:16]}...",
            source="Forensic Ingestion Pipeline",
            entity_type="EMAIL",
            entity_id=inv_id,
            severity="INFO",
            evidence_reference=f"sha256:{forensic.sha256_digest}",
            metadata={"sha256": forensic.sha256_digest, "file_size": forensic.file_size_bytes},
        )
    )

    # 2. Email Creation / Sent Date
    iso_date = parse_rfc_date_to_iso(forensic.metadata.date)
    events.append(
        TimelineEvent(
            event_id=next_evt_id(),
            investigation_id=inv_id,
            timestamp=iso_date,
            timestamp_precision=TimestampPrecision.SECOND if iso_date else TimestampPrecision.UNKNOWN,
            event_type=TimelineEventType.EMAIL_CREATED,
            title="Message Sent by Author / Client",
            description=f"From: {forensic.metadata.from_address} | Subject: '{forensic.metadata.subject}'",
            source="Date header / RFC 5322 Metadata",
            entity_type="EMAIL",
            entity_id=forensic.metadata.message_id or inv_id,
            severity="INFO",
            evidence_reference="Header: Date",
            metadata={"from": forensic.metadata.from_address, "to": forensic.metadata.to_addresses},
        )
    )

    # 3. Received Header Relay Sequence (Hop 1 -> Hop N)
    for hop in forensic.received_chain:
        hop_iso = parse_rfc_date_to_iso(hop.timestamp)
        hop_title = f"SMTP Relay Hop {hop.hop}"
        if hop.hop == 1:
            hop_title = "SMTP Relay Hop 1 (First Observed Relay / Sender Infrastructure)"
        elif hop.hop == len(forensic.received_chain):
            hop_title = f"SMTP Relay Hop {hop.hop} (Target Mail Exchanger)"

        desc_parts = []
        if hop.from_host:
            desc_parts.append(f"from: {hop.from_host}")
        if hop.by_host:
            desc_parts.append(f"by: {hop.by_host}")
        if hop.ip:
            desc_parts.append(f"IP: {hop.ip}")
        if hop.protocol:
            desc_parts.append(f"protocol: {hop.protocol}")

        events.append(
            TimelineEvent(
                event_id=next_evt_id(),
                investigation_id=inv_id,
                timestamp=hop_iso,
                timestamp_precision=TimestampPrecision.SECOND if hop_iso else TimestampPrecision.UNKNOWN,
                event_type=TimelineEventType.SMTP_RELAY,
                title=hop_title,
                description=" | ".join(desc_parts) if desc_parts else "Observed relay hop",
                source=f"Received header (Hop {hop.hop})",
                entity_type="IP" if hop.ip else "RELAY",
                entity_id=hop.ip or hop.from_host,
                severity="HIGH" if hop.hop == 1 and hop.ip else "INFO",
                evidence_reference=f"Hop {hop.hop}: {hop.raw[:60]}...",
                metadata={"hop_number": hop.hop, "ip": hop.ip, "from_host": hop.from_host, "by_host": hop.by_host},
            )
        )

    # 4. Authentication Check Verification
    auth = forensic.authentication
    auth_failed = (
        auth.spf in (AuthenticationVerdict.FAIL, AuthenticationVerdict.SOFTFAIL)
        or auth.dmarc == AuthenticationVerdict.FAIL
        or auth.dkim == AuthenticationVerdict.FAIL
    )
    auth_severity = "HIGH" if auth_failed else "CLEAN" if auth.spf == AuthenticationVerdict.PASS else "INFO"
    events.append(
        TimelineEvent(
            event_id=next_evt_id(),
            investigation_id=inv_id,
            timestamp=iso_date,  # Associated with received time
            timestamp_precision=TimestampPrecision.UNKNOWN if not iso_date else TimestampPrecision.MINUTE,
            event_type=TimelineEventType.AUTHENTICATION_CHECK,
            title="Mail Authentication Evaluation (SPF / DKIM / DMARC)",
            description=f"SPF: {auth.spf.value} | DKIM: {auth.dkim.value} | DMARC: {auth.dmarc.value}",
            source="Authentication-Results / Received-SPF headers",
            entity_type="EMAIL",
            entity_id=inv_id,
            severity=auth_severity,
            evidence_reference=auth.raw_header or f"SPF={auth.spf.value}; DKIM={auth.dkim.value}; DMARC={auth.dmarc.value}",
            metadata={"spf": auth.spf.value, "dkim": auth.dkim.value, "dmarc": auth.dmarc.value},
        )
    )

    # 5. Extracted Domains
    for domain_item in forensic.domains:
        events.append(
            TimelineEvent(
                event_id=next_evt_id(),
                investigation_id=inv_id,
                timestamp=None,
                timestamp_precision=TimestampPrecision.UNKNOWN,
                event_type=TimelineEventType.DOMAIN_DISCOVERED,
                title=f"Domain Discovered: {domain_item.domain}",
                description=f"Observed in message body / headers ({domain_item.occurrence_count} occurrences)",
                source="Message Body / URLs",
                entity_type="DOMAIN",
                entity_id=domain_item.domain,
                severity="INFO",
                evidence_reference=f"domain:{domain_item.domain}",
                metadata={"domain": domain_item.domain, "count": domain_item.occurrence_count},
            )
        )

    # 6. Extracted URLs
    for url_item in forensic.urls:
        events.append(
            TimelineEvent(
                event_id=next_evt_id(),
                investigation_id=inv_id,
                timestamp=None,
                timestamp_precision=TimestampPrecision.UNKNOWN,
                event_type=TimelineEventType.URL_DISCOVERED,
                title=f"Hyperlink Discovered: {url_item.domain}",
                description=f"Extracted URL ({url_item.scheme}://) from {url_item.source}: {url_item.normalized_url}",
                source=f"Body extraction ({url_item.source})",
                entity_type="URL",
                entity_id=url_item.normalized_url,
                severity="INFO",
                evidence_reference=url_item.url,
                metadata={"scheme": url_item.scheme, "domain": url_item.domain, "path": url_item.path},
            )
        )

    # 7. Extracted Attachments
    for att in forensic.attachments:
        events.append(
            TimelineEvent(
                event_id=next_evt_id(),
                investigation_id=inv_id,
                timestamp=None,
                timestamp_precision=TimestampPrecision.UNKNOWN,
                event_type=TimelineEventType.ATTACHMENT_DISCOVERED,
                title=f"Attachment Discovered: {att.filename}",
                description=f"Payload {att.extension} ({att.mime_type}, {att.size_bytes} bytes) | SHA-256: {att.sha256[:16]}...",
                source="MIME multipart payload",
                entity_type="ATTACHMENT",
                entity_id=att.filename,
                severity="HIGH" if att.extension.lower() in [".html", ".exe", ".vbs", ".scr", ".iso", ".zip"] else "INFO",
                evidence_reference=f"sha256:{att.sha256}",
                metadata={"filename": att.filename, "sha256": att.sha256, "mime": att.mime_type, "size": att.size_bytes},
            )
        )

    # 8. Threat Indicators (if Step 6 assessment is provided)
    if threat_assessment:
        for ind in threat_assessment.indicators:
            events.append(
                TimelineEvent(
                    event_id=next_evt_id(),
                    investigation_id=inv_id,
                    timestamp=threat_assessment.evaluated_at,
                    timestamp_precision=TimestampPrecision.SECOND,
                    event_type=TimelineEventType.THREAT_INDICATOR,
                    title=f"Threat Indicator: {ind.name}",
                    description=f"Category: {ind.category.value} | Evidence: {ind.evidence} (Score contribution: +{ind.weight})",
                    source=f"Detection Rule [{ind.id}]",
                    entity_type="INDICATOR",
                    entity_id=ind.id,
                    severity="CRITICAL" if ind.severity.value in ("CRITICAL", "HIGH") else "MEDIUM",
                    evidence_reference=f"Rule: {ind.id} | {ind.evidence}",
                    metadata={"indicator_id": ind.id, "category": ind.category.value, "weight": ind.weight},
                )
            )


    # 9. Intelligence Enrichment Lookups (if Step 7 intelligence is provided)
    if intelligence:
        for ip_intel in intelligence.ips:
            if ip_intel.status == LookupStatus.SUCCESS and ip_intel.country:
                events.append(
                    TimelineEvent(
                        event_id=next_evt_id(),
                        investigation_id=inv_id,
                        timestamp=ip_intel.looked_up_at,
                        timestamp_precision=TimestampPrecision.SECOND,
                        event_type=TimelineEventType.GEOLOCATION_RESOLVED,
                        title=f"Observed Infrastructure Resolved: {ip_intel.ip}",
                        description=f"Location: {ip_intel.city or 'N/A'}, {ip_intel.country} | ASN: {ip_intel.asn or 'N/A'} ({ip_intel.organization or 'N/A'})",
                        source=f"Threat Intelligence Feed ({ip_intel.source})",
                        entity_type="IP",
                        entity_id=ip_intel.ip,
                        severity="CRITICAL" if ip_intel.reputation == ReputationStatus.KNOWN_MALICIOUS else "HIGH" if ip_intel.reputation == ReputationStatus.SUSPICIOUS else "INFO",
                        evidence_reference=f"ASN: {ip_intel.asn} | {ip_intel.country}",
                        metadata={"ip": ip_intel.ip, "country": ip_intel.country, "asn": ip_intel.asn},
                    )
                )

    # 10. Risk Assessment Summary (if Step 6 assessment is provided)
    if threat_assessment:
        events.append(
            TimelineEvent(
                event_id=next_evt_id(),
                investigation_id=inv_id,
                timestamp=threat_assessment.evaluated_at,
                timestamp_precision=TimestampPrecision.SECOND,
                event_type=TimelineEventType.RISK_ASSESSMENT,
                title=f"Risk Assessment Verdict: {threat_assessment.risk_score}/100 ({threat_assessment.severity.value})",
                description=f"Classification: {threat_assessment.classification.value} (Confidence: {threat_assessment.confidence_percentage}%). {threat_assessment.summary}",
                source="Threat Detection & Risk Engine",
                entity_type="ASSESSMENT",
                entity_id=inv_id,
                severity=threat_assessment.severity.value,
                evidence_reference=f"Risk Score: {threat_assessment.risk_score}/100 | Severity: {threat_assessment.severity.value}",
                metadata={"risk_score": threat_assessment.risk_score, "severity": threat_assessment.severity.value, "confidence": threat_assessment.confidence},
            )
        )

    return events
