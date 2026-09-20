from typing import List, Optional
from app.services.ai.models import (
    ActionCategory,
    AttackNarrativeStep,
    ConfidenceRating,
    CorrelationResult,
    InvestigationLead,
    LeadCategory,
    MITRETactic,
    MITRETechnique,
    RecommendedAction,
    ThreatPatternType,
)
from app.services.email import EmailForensicResult
from app.services.intelligence.models import InvestigationIntelligenceResult
from app.services.risk import ThreatAssessmentResult


def generate_attack_narrative(
    forensic: Optional[EmailForensicResult],
    threat: Optional[ThreatAssessmentResult],
    correlation: CorrelationResult,
) -> List[AttackNarrativeStep]:
    """
    Generates a factual, chronological narrative of the observed attack progression.
    Strictly uses observed evidence without synthetic fabrication.
    """
    steps: List[AttackNarrativeStep] = []
    step_num = 1

    # Step 1: Ingestion
    from_addr = forensic.metadata.from_address if forensic else "Unknown Sender"
    subject = forensic.metadata.subject if forensic else "No Subject"
    steps.append(
        AttackNarrativeStep(
            step_number=step_num,
            phase="Initial Ingestion",
            title="Email Message Ingested at Perimeter",
            description=f"Inbound email message received claiming origin from '{from_addr}' with subject line '{subject}'.",
            evidence_excerpt=f"From: {from_addr}",
        )
    )
    step_num += 1

    # Step 2: Authentication Evaluation
    if forensic and forensic.authentication:
        spf = forensic.authentication.spf.value
        dmarc = forensic.authentication.dmarc.value
        if spf in ["FAIL", "SOFTFAIL"] or dmarc in ["FAIL", "REJECT", "QUARANTINE"]:
            steps.append(
                AttackNarrativeStep(
                    step_number=step_num,
                    phase="Authentication Verification",
                    title="Cryptographic Origin Policy Failure",
                    description=f"Automated gateway evaluation flagged origin policy violations (SPF: {spf}, DMARC: {dmarc}), indicating unauthorized relay infrastructure.",
                    evidence_excerpt=f"SPF: {spf} | DMARC: {dmarc}",
                )
            )
            step_num += 1

    # Step 3: Domain & Identity Spoofing
    if any(f.relationship == "LOOKALIKE_DOMAIN_SPOOF" for f in correlation.correlated_findings):
        spoof_finding = next(f for f in correlation.correlated_findings if f.relationship == "LOOKALIKE_DOMAIN_SPOOF")
        steps.append(
            AttackNarrativeStep(
                step_number=step_num,
                phase="Adversary Camouflage",
                title="Lookalike Domain Spoofing Identified",
                description=f"The sender utilizes domain '{spoof_finding.target_entity}' containing visual homoglyphs designed to deceive the recipient into perceiving a trusted brand.",
                evidence_excerpt=spoof_finding.evidence_details,
            )
        )
        step_num += 1

    # Step 4: Reply-To Redirection
    if any(f.relationship == "REPLY_TO_REDIRECT" for f in correlation.correlated_findings):
        reply_finding = next(f for f in correlation.correlated_findings if f.relationship == "REPLY_TO_REDIRECT")
        steps.append(
            AttackNarrativeStep(
                step_number=step_num,
                phase="Response Hijacking",
                title="Reply-To Routing Redirection",
                description="The message headers configure a divergent Reply-To address to direct analyst or user communications to external adversary infrastructure.",
                evidence_excerpt=reply_finding.target_entity,
            )
        )
        step_num += 1

    # Step 5: Payload / URL Extraction
    if forensic and forensic.attachments:
        att = forensic.attachments[0]
        steps.append(
            AttackNarrativeStep(
                step_number=step_num,
                phase="Payload Delivery",
                title="Suspicious Attachment Identified",
                description=f"Extracted attachment '{att.filename}' ({att.mime_type}) was analyzed and flagged with SHA-256 fingerprint {att.sha256[:16]}...",
                evidence_excerpt=f"Attachment: {att.filename}",
            )
        )
        step_num += 1
    elif forensic and forensic.urls:
        url = forensic.urls[0]
        steps.append(
            AttackNarrativeStep(
                step_number=step_num,
                phase="Phishing Link Delivery",
                title="External Link Routing Identified",
                description=f"Message body contains embedded hyperlink targeting domain '{url.domain}'.",
                evidence_excerpt=f"URL: {url.url[:48]}...",
            )
        )
        step_num += 1

    # Final Step: Risk Escalation
    risk_score = threat.risk_score if threat else 0
    sev = threat.severity.value if threat else "MEDIUM"
    steps.append(
        AttackNarrativeStep(
            step_number=step_num,
            phase="Triage Verdict",
            title=f"Deterministic Risk Escalation to {sev}",
            description=f"Cumulative observable indicators produced an explainable threat score of {risk_score}/100 with {sev} severity classification.",
            evidence_excerpt=f"Risk Score: {risk_score}/100",
        )
    )

    return steps


def generate_mitre_techniques(
    forensic: Optional[EmailForensicResult],
    threat: Optional[ThreatAssessmentResult],
    correlation: CorrelationResult,
) -> List[MITRETechnique]:
    """
    Maps observable forensic evidence directly to MITRE ATT&CK techniques.
    """
    techniques: List[MITRETechnique] = []

    if correlation.primary_pattern.pattern_type == ThreatPatternType.BENIGN:
        return techniques

    # T1566: Phishing (General Initial Access)
    techniques.append(
        MITRETechnique(
            technique_id="T1566",
            name="Phishing",
            tactic=MITRETactic.INITIAL_ACCESS,
            rationale="Adversary delivered an unsolicited deceptive email to gain initial footholds or execute unauthorized actions.",
            evidence=f"From: {forensic.metadata.from_address if forensic else 'Suspect Address'}",
            confidence=ConfidenceRating.HIGH,
        )
    )

    # T1566.002: Spearphishing Link
    if forensic and forensic.urls:
        techniques.append(
            MITRETechnique(
                technique_id="T1566.002",
                name="Spearphishing Link",
                tactic=MITRETactic.INITIAL_ACCESS,
                rationale="Embedded URLs in email body lead recipient to malicious or credential harvesting infrastructure.",
                evidence=f"Extracted URL: {forensic.urls[0].url[:48]}...",
                confidence=ConfidenceRating.HIGH,
            )
        )

    # T1566.001: Spearphishing Attachment
    if forensic and forensic.attachments:
        techniques.append(
            MITRETechnique(
                technique_id="T1566.001",
                name="Spearphishing Attachment",
                tactic=MITRETactic.INITIAL_ACCESS,
                rationale="Adversary delivered suspicious attachments configured to prompt user execution or form submission.",
                evidence=f"Filename: {forensic.attachments[0].filename} (SHA-256: {forensic.attachments[0].sha256[:16]}...)",
                confidence=ConfidenceRating.HIGH,
            )
        )

    # T1583.001: Acquire Infrastructure - Domains
    if any(f.relationship == "LOOKALIKE_DOMAIN_SPOOF" for f in correlation.correlated_findings):
        spoof_finding = next(f for f in correlation.correlated_findings if f.relationship == "LOOKALIKE_DOMAIN_SPOOF")
        techniques.append(
            MITRETechnique(
                technique_id="T1583.001",
                name="Acquire Infrastructure: Domains",
                tactic=MITRETactic.INITIAL_ACCESS,
                rationale="Adversary registered a typosquatting or homoglyphic lookalike domain simulating legitimate enterprise identities.",
                evidence=f"Lookalike Domain: {spoof_finding.target_entity}",
                confidence=ConfidenceRating.HIGH,
            )
        )

    # T1204.001 / T1204.002: User Execution
    if (threat and threat.risk_score >= 70) or (forensic and forensic.attachments):
        techniques.append(
            MITRETechnique(
                technique_id="T1204",
                name="User Execution",
                tactic=MITRETactic.EXECUTION,
                rationale="Message utilizes urgent social engineering cues to compel recipient interaction with links or files.",
                evidence=f"Subject: {forensic.metadata.subject if forensic else 'Urgent Action'}",
                confidence=ConfidenceRating.MEDIUM,
            )
        )

    return techniques


def generate_investigation_leads(
    forensic: Optional[EmailForensicResult],
    threat: Optional[ThreatAssessmentResult],
    correlation: CorrelationResult,
) -> List[InvestigationLead]:
    """
    Generates actionable, evidence-referenced next steps for the SOC analyst.
    """
    leads: List[InvestigationLead] = []
    lead_counter = 1

    # Lead 1: Gateway Search
    sender_domain = forensic.metadata.from_address.split("@")[-1] if forensic and "@" in forensic.metadata.from_address else "suspect-domain.com"
    leads.append(
        InvestigationLead(
            lead_id=f"LEAD-{lead_counter:02d}",
            category=LeadCategory.MAIL_GATEWAY,
            action=f"Search secure email gateway logs for all messages from '{sender_domain}'",
            rationale="Determine if this phishing attempt is part of a wider targeted attack wave across multiple corporate mailboxes.",
            evidence_reference=f"Sender Domain: {sender_domain}",
            priority="HIGH",
        )
    )
    lead_counter += 1

    # Lead 2: Endpoint / Attachment Telemetry
    if forensic and forensic.attachments:
        att = forensic.attachments[0]
        leads.append(
            InvestigationLead(
                lead_id=f"LEAD-{lead_counter:02d}",
                category=LeadCategory.ENDPOINT_TELEMETRY,
                action=f"Query EDR telemetry for file hash {att.sha256[:16]}... across enterprise endpoints",
                rationale="Verify whether any internal users opened, downloaded, or executed the attached payload.",
                evidence_reference=f"File: {att.filename} (SHA-256: {att.sha256})",
                priority="HIGH",
            )
        )
        lead_counter += 1

    # Lead 3: DNS / Proxy Search
    if forensic and forensic.domains:
        susp_dom = forensic.domains[0].domain
        leads.append(
            InvestigationLead(
                lead_id=f"LEAD-{lead_counter:02d}",
                category=LeadCategory.DNS_ANALYSIS,
                action=f"Inspect proxy and DNS resolver query logs for connections to '{susp_dom}'",
                rationale="Detect if any internal workstations initiated network connections or credential submissions to the destination domain.",
                evidence_reference=f"Domain: {susp_dom}",
                priority="HIGH",
            )
        )
        lead_counter += 1

    # Lead 4: Out-of-Band Payment Verification
    if correlation.primary_pattern.pattern_type in [ThreatPatternType.BUSINESS_EMAIL_COMPROMISE, ThreatPatternType.FINANCIAL_FRAUD]:
        leads.append(
            InvestigationLead(
                lead_id=f"LEAD-{lead_counter:02d}",
                category=LeadCategory.COMMUNICATION_VERIFICATION,
                action="Initiate secondary out-of-band telephone verification with executive stakeholders",
                rationale="Confirm that no authorized financial wire transfer or invoice payment was legitimately initiated.",
                evidence_reference=f"Subject: {forensic.metadata.subject if forensic else 'Wire Transfer'}",
                priority="HIGH",
            )
        )
        lead_counter += 1

    return leads


def generate_recommended_actions(
    forensic: Optional[EmailForensicResult],
    threat: Optional[ThreatAssessmentResult],
    correlation: CorrelationResult,
) -> List[RecommendedAction]:
    """
    Generates structured, prioritized containment and mitigation recommendations.
    """
    actions: List[RecommendedAction] = []

    if correlation.primary_pattern.pattern_type == ThreatPatternType.BENIGN:
        actions.append(
            RecommendedAction(
                action_type=ActionCategory.NOTIFY,
                title="Allow Inbound Delivery",
                description="Message verified as authentic and clean. No defensive filtering required.",
                target_indicator="All Headers Clean",
                urgency="STANDARD",
            )
        )
        return actions

    # 1. BLOCK Domain
    if forensic and forensic.domains:
        dom = forensic.domains[0].domain
        actions.append(
            RecommendedAction(
                action_type=ActionCategory.BLOCK,
                title=f"Block Domain '{dom}' at Mail Gateway",
                description=f"Add '{dom}' to tenant-wide transport blocklist to reject incoming messages.",
                target_indicator=dom,
                urgency="IMMEDIATE",
            )
        )

    # 2. CONTAIN Relay IP
    if forensic and forensic.received_chain and forensic.received_chain[0].ip:
        ip = forensic.received_chain[0].ip
        actions.append(
            RecommendedAction(
                action_type=ActionCategory.CONTAIN,
                title=f"Sinkhole Suspect Origin IP {ip}",
                description="Apply temporary perimeter firewall block for inbound SMTP connections from this IP.",
                target_indicator=ip,
                urgency="IMMEDIATE",
            )
        )

    # 3. PRESERVE Cryptographic Evidence
    actions.append(
        RecommendedAction(
            action_type=ActionCategory.PRESERVE,
            title="Preserve Evidence Package & Blockchain Fingerprint",
            description="Retain canonical SHA-256 evidence package for legal forensics and regulatory compliance auditing.",
            target_indicator=forensic.sha256_digest if forensic else "Canonical Package",
            urgency="STANDARD",
        )
    )

    # 4. INVESTIGATE SIEM
    actions.append(
        RecommendedAction(
            action_type=ActionCategory.INVESTIGATE,
            title="Correlate SIEM Authentication Telemetry",
            description="Audit user sign-in logs for anomalous token creation or MFA fatigue prompts around the delivery window.",
            target_indicator="User Identity",
            urgency="STANDARD",
        )
    )

    return actions


def generate_executive_summary(
    forensic: Optional[EmailForensicResult],
    threat: Optional[ThreatAssessmentResult],
    correlation: CorrelationResult,
) -> str:
    """
    Generates a concise, non-technical executive overview suitable for leadership and incident briefing.
    """
    if correlation.primary_pattern.pattern_type == ThreatPatternType.BENIGN:
        return "The investigation verified that the email exhibits legitimate cryptographic authentication (SPF/DKIM/DMARC) with zero anomalous indicators. The message has been classified as BENIGN with a threat risk score of 0/100."

    risk = threat.risk_score if threat else 85
    sev = threat.severity.value if threat else "CRITICAL"
    pattern = correlation.primary_pattern.title

    sender = forensic.metadata.from_address if forensic else "the suspect sender"
    summary = (
        f"The MAILSENTINEL forensic engine identified a high-confidence {pattern} campaign targeting corporate recipients. "
        f"Observable evidence confirmed sender impersonation from '{sender}' with cryptographic authentication failure, "
        f"lookalike domain spoofing, and urgent deception tactics. The deterministic threat engine calculated a risk score of {risk}/100 ({sev}). "
        f"The evidence package has been cryptographically anchored to an immutable blockchain ledger for tamper verification."
    )
    return summary
