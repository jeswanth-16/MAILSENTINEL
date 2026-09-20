from typing import Dict, List, Any, Optional
from app.services.reporting.models import (
    ReportFinding,
    FindingSeverity,
    FindingCategory,
    ReportEvidenceReference,
    ReportRecommendation,
    ReportSignature,
)
import hashlib


def generate_evidence_references(
    evidence_sha256: str,
    email_data: Optional[Dict[str, Any]] = None,
    auth_data: Optional[Dict[str, Any]] = None,
    urls: Optional[List[Dict[str, Any]]] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
    blockchain_tx: Optional[str] = None,
) -> List[ReportEvidenceReference]:
    """Generates structured evidence references (EV-001, EV-002, etc.) for traceability."""
    refs: List[ReportEvidenceReference] = []
    ref_idx = 1

    # EV-001: Original Evidence Payload
    refs.append(
        ReportEvidenceReference(
            reference_id=f"EV-{ref_idx:03d}",
            evidence_type="EMAIL_EML",
            description="Raw RFC 5322/MIME .EML payload cryptographically hashed on ingestion",
            sha256=evidence_sha256,
            source_locator="file:raw_evidence.eml",
            metadata={"status": "IMMUTABLE_PRESERVED"},
        )
    )
    ref_idx += 1

    # Headers & Authentication
    if auth_data:
        refs.append(
            ReportEvidenceReference(
                reference_id=f"EV-{ref_idx:03d}",
                evidence_type="SPF_RECORD",
                description=f"SPF authentication evaluation result: {auth_data.get('spf_status', 'NONE')}",
                source_locator="headers.received-spf",
                metadata=auth_data,
            )
        )
        ref_idx += 1

        refs.append(
            ReportEvidenceReference(
                reference_id=f"EV-{ref_idx:03d}",
                evidence_type="DKIM_SIGNATURE",
                description=f"DKIM cryptographic signature evaluation: {auth_data.get('dkim_status', 'NONE')}",
                source_locator="headers.dkim-signature",
                metadata=auth_data,
            )
        )
        ref_idx += 1

        refs.append(
            ReportEvidenceReference(
                reference_id=f"EV-{ref_idx:03d}",
                evidence_type="DMARC_POLICY",
                description=f"DMARC policy alignment result: {auth_data.get('dmarc_status', 'NONE')}",
                source_locator="dns._dmarc",
                metadata=auth_data,
            )
        )
        ref_idx += 1

    # Suspicious URLs
    if urls:
        for u in urls[:5]:
            url_str = u.get("url", "")
            u_hash = hashlib.sha256(url_str.encode("utf-8")).hexdigest()
            refs.append(
                ReportEvidenceReference(
                    reference_id=f"EV-{ref_idx:03d}",
                    evidence_type="URL_PAYLOAD",
                    description=f"Extracted weaponized / suspicious URL indicator: {url_str[:60]}",
                    sha256=u_hash,
                    source_locator="body.hyperlinks",
                    metadata=u,
                )
            )
            ref_idx += 1

    # Attachments
    if attachments:
        for att in attachments:
            refs.append(
                ReportEvidenceReference(
                    reference_id=f"EV-{ref_idx:03d}",
                    evidence_type="ATTACHMENT_HASH",
                    description=f"Email attachment: {att.get('filename', 'unnamed')}",
                    sha256=att.get("sha256"),
                    source_locator=f"mime.part.{att.get('filename', 'part')}",
                    metadata=att,
                )
            )
            ref_idx += 1

    # Blockchain Anchor
    if blockchain_tx:
        refs.append(
            ReportEvidenceReference(
                reference_id=f"EV-{ref_idx:03d}",
                evidence_type="BLOCKCHAIN_ANCHOR",
                description="Cryptographic on-chain evidence state anchor",
                sha256=evidence_sha256,
                source_locator=f"tx:{blockchain_tx}",
                metadata={"blockchain_tx": blockchain_tx},
            )
        )
        ref_idx += 1

    return refs


def generate_findings_from_indicators(
    indicators: List[Dict[str, Any]],
    auth_data: Optional[Dict[str, Any]] = None,
    urls: Optional[List[Dict[str, Any]]] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
    refs: Optional[List[ReportEvidenceReference]] = None,
) -> List[ReportFinding]:
    """Generates structured, traceable findings (F-001, F-002...) from actual threat indicators."""
    findings: List[ReportFinding] = []
    finding_idx = 1
    ref_map = {r.evidence_type: r.reference_id for r in (refs or [])}

    # Indicator-driven findings
    for ind in indicators:
        name = ind.get("name", "")
        desc = ind.get("description", "")
        weight = ind.get("score_impact", ind.get("weight", 10))
        category_str = ind.get("category", "ANOMALY")

        sev = FindingSeverity.MEDIUM
        if weight >= 25 or "CRITICAL" in name.upper():
            sev = FindingSeverity.CRITICAL
        elif weight >= 15 or "HIGH" in name.upper() or "FAIL" in name.upper():
            sev = FindingSeverity.HIGH
        elif weight <= 5:
            sev = FindingSeverity.LOW

        cat = FindingCategory.ANOMALY
        if "AUTH" in category_str.upper() or "SPF" in name.upper() or "DKIM" in name.upper() or "DMARC" in name.upper():
            cat = FindingCategory.AUTHENTICATION
        elif "DOMAIN" in category_str.upper() or "LOOKALIKE" in name.upper():
            cat = FindingCategory.DOMAIN_REPUTATION
        elif "URL" in category_str.upper() or "LINK" in name.upper():
            cat = FindingCategory.URL_ANALYSIS
        elif "ATTACH" in category_str.upper() or "MALWARE" in name.upper():
            cat = FindingCategory.ATTACHMENT
        elif "BEHAVIOR" in category_str.upper() or "URGENCY" in name.upper():
            cat = FindingCategory.BEHAVIORAL

        ev_ref = ref_map.get("EMAIL_EML", "EV-001")
        if cat == FindingCategory.AUTHENTICATION and "SPF_RECORD" in ref_map:
            ev_ref = ref_map["SPF_RECORD"]
        elif cat == FindingCategory.URL_ANALYSIS and "URL_PAYLOAD" in ref_map:
            ev_ref = ref_map["URL_PAYLOAD"]
        elif cat == FindingCategory.ATTACHMENT and "ATTACHMENT_HASH" in ref_map:
            ev_ref = ref_map["ATTACHMENT_HASH"]

        impact = "Potential unauthorized credential exposure or initial malicious payload delivery."
        recommendation = "Enforce strict gateway blocking and reset credentials for targeted recipient."
        if cat == FindingCategory.AUTHENTICATION:
            impact = "Adversary successfully impersonated legitimate domain due to sender verification failure."
            recommendation = "Reject unauthenticated sender IPs at MTA perimeter and update DMARC to p=reject."
        elif cat == FindingCategory.URL_ANALYSIS:
            impact = "Victim directed to deceptive credential harvester mimicking enterprise single sign-on."
            recommendation = "Block destination domain on proxy / DNS resolvers and revoke active victim session tokens."

        raw_conf = float(ind.get("confidence", 0.9))
        if raw_conf > 1.0:
            raw_conf = raw_conf / 100.0
        norm_conf = max(0.0, min(1.0, raw_conf))

        findings.append(
            ReportFinding(
                finding_id=f"F-{finding_idx:03d}",
                title=name or f"Security Finding {finding_idx}",
                severity=sev,
                category=cat,
                description=desc or "Identified forensic anomaly during static header and payload analysis.",
                evidence_reference=ev_ref,
                confidence=norm_conf,
                impact=impact,
                recommendation=recommendation,
            )
        )
        finding_idx += 1

    # Fallback if no specific indicators provided
    if not findings:
        findings.append(
            ReportFinding(
                finding_id="F-001",
                title="Forensic Static Analysis Complete",
                severity=FindingSeverity.INFO,
                category=FindingCategory.ANOMALY,
                description="Static forensic analysis completed with no severe policy indicators flagged.",
                evidence_reference=ref_map.get("EMAIL_EML", "EV-001"),
                confidence=0.95,
                impact="Low security exposure detected.",
                recommendation="Routine monitoring and adherence to standard enterprise email policies.",
            )
        )

    return findings


def generate_recommendations(
    findings: List[ReportFinding],
    risk_score: int,
    classification: str,
) -> List[ReportRecommendation]:
    """Generates prioritized and grounded mitigation recommendations."""
    recs: List[ReportRecommendation] = []
    rec_idx = 1

    if risk_score >= 70 or classification in ["PHISHING", "MALICIOUS", "BUSINESS_EMAIL_COMPROMISE", "CREDENTIAL_HARVESTING"]:
        recs.append(
            ReportRecommendation(
                recommendation_id=f"REC-{rec_idx:03d}",
                priority="P1_CRITICAL",
                category="CONTAINMENT",
                title="Quarantine Malicious Payload & Block Sender Domain",
                action="Immediately purge message from user inboxes and block sender domain at enterprise mail gateway.",
                rationale="High authoritative risk score and active threat indicators present severe risk of credential compromise.",
            )
        )
        rec_idx += 1

        recs.append(
            ReportRecommendation(
                recommendation_id=f"REC-{rec_idx:03d}",
                priority="P1_CRITICAL",
                category="ERADICATION",
                title="Revoke Active User Sessions & Reset Authentication Secrets",
                action="Force logout of targeted recipient accounts and enforce multi-factor authentication re-enrollment.",
                rationale="Prevents lateral threat propagation in case victim clicked credential harvesting URLs.",
            )
        )
        rec_idx += 1

    if any(f.category == FindingCategory.AUTHENTICATION for f in findings):
        recs.append(
            ReportRecommendation(
                recommendation_id=f"REC-{rec_idx:03d}",
                priority="P2_HIGH",
                category="POLICY",
                title="Enforce Strict DMARC and SPF Verification Policies",
                action="Configure email perimeter filters to reject messages failing SPF alignment and DKIM verification.",
                rationale="Mitigates future spoofing attacks attempting domain masquerading.",
            )
        )
        rec_idx += 1

    recs.append(
        ReportRecommendation(
            recommendation_id=f"REC-{rec_idx:03d}",
            priority="P3_MEDIUM",
            category="MONITORING",
            title="Preserve Evidence & Maintain Blockchain Anchor Integrity",
            action="Retain forensic .EML digest, timeline, and audit custody records for compliance and judicial audit.",
            rationale="Ensures evidence immutability and verifiable proof against post-incident tampering.",
        )
    )

    return recs


def generate_executive_summary_data(
    title: str,
    classification: str,
    severity: str,
    risk_score: int,
    primary_indicators: List[str],
    sender: str,
    target: str,
    ai_narrative: Optional[str] = None,
) -> Dict[str, Any]:
    """Builds a structured executive summary strictly adhering to authoritative facts."""
    return {
        "incident_title": title,
        "classification": classification,
        "severity": severity,
        "authoritative_risk_score": risk_score,
        "target_recipient": target or "Enterprise Staff",
        "sender_identity": sender or "Unknown Sender",
        "primary_threat_indicators": primary_indicators or ["Header Anomaly", "Unverified Route"],
        "recommended_response": "Contain, preserve cryptographic evidence, block malicious indicators on perimeter firewalls, and monitor correlated endpoints.",
        "ai_executive_narrative": ai_narrative or f"MAILSENTINEL forensic assessment confirmed an authoritative threat score of {risk_score}/100 with classification '{classification}'. Immediate containment and evidence preservation are recommended.",
    }
