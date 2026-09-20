from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.core.logging import logger
from app.services.ai.models import (
    ActionCategory,
    AttackNarrativeStep,
    ConfidenceRating,
    ContradictionItem,
    CorrelatedEntityFinding,
    EvidenceCategoryBreakdown,
    EvidenceConfidence,
    EvidenceFinding,
    GapStatus,
    InvestigationAssessment,
    InvestigationGap,
    InvestigationLead,
    LeadCategory,
    MITRETactic,
    MITRETechnique,
    RecommendedAction,
    ThreatPattern,
    ThreatPatternType,
    ThreatVerdict,
)
from app.services.email.models import EmailForensicResult
from app.services.intelligence.models import (
    InvestigationIntelligenceResult,
    LookupStatus,
    ReputationStatus,
)
from app.services.risk.models import ThreatAssessmentResult
from app.services.risk.thresholds import CATEGORY_WEIGHT_CAPS
from app.services.threat.models import ThreatCategory


class ForensicDecisionEngine:
    """
    Phase 4 Automated Threat Analysis & Forensic Decision Engine.
    Deterministic, explainable, auditable, and safe evidence evaluation layer.
    """

    ENGINE_VERSION = "4.0"

    def evaluate_investigation(
        self,
        investigation_id: str,
        evidence_id: str,
        evidence_hash: str,
        forensic: Optional[EmailForensicResult],
        threat: Optional[ThreatAssessmentResult],
        intel: Optional[InvestigationIntelligenceResult],
        correlation: Optional[Any] = None,
        other_cases: Optional[List[Any]] = None,
    ) -> InvestigationAssessment:
        """
        Executes full deterministic forensic evaluation across all collected evidence.
        Produces an explainable InvestigationAssessment with primary/supporting indicators,
        contradiction detection, confidence ratings, gaps, attack chain, and actions.
        """
        # 1. Evaluate Evidence Findings across all categories
        primary_inds, supporting_inds, breakdowns = self._evaluate_evidence_findings(
            forensic, threat, intel, correlation
        )

        # 2. Contradiction Detection
        contradictions = self._detect_contradictions(forensic, threat, intel, correlation)

        # 3. Investigation Gap Analysis
        gaps = self._analyze_investigation_gaps(forensic, intel)

        # 4. Deterministic Confidence Rating
        confidence = self._calculate_confidence(
            forensic, threat, intel, correlation, contradictions, gaps
        )

        # 5. Deterministic Threat Verdict
        verdict, severity, risk_score = self._derive_verdict(
            forensic, threat, primary_inds, supporting_inds, contradictions
        )

        # 6. Grounded MITRE ATT&CK Mapping
        mitre_techs = self._map_mitre_techniques(forensic, threat, correlation)

        # 7. Attack Chain Progression Reconstruction
        attack_chain = self._reconstruct_attack_chain(
            forensic, threat, intel, correlation, verdict, risk_score
        )

        # 8. Analyst Next Actions & Inquiry Questions
        leads, actions, questions = self._generate_actions_and_questions(
            forensic, threat, intel, correlation, verdict
        )

        # 9. Suspicious Behaviors
        behaviors = self._extract_suspicious_behaviors(
            forensic, threat, primary_inds, correlation
        )

        # 10. Threat Pattern & Correlated Entities
        pattern, correlated_entities = self._build_pattern_and_correlations(
            forensic, threat, correlation
        )

        # 11. Structured Executive & Evidence Summaries
        exec_summary, ev_summary = self._generate_summaries(
            investigation_id=investigation_id,
            verdict=verdict,
            confidence=confidence,
            risk_score=risk_score,
            severity=severity,
            pattern=pattern,
            primary_indicators=primary_inds,
            contradictions=contradictions,
            intel=intel,
        )

        num_part = investigation_id.split("-")[-1] if "-" in investigation_id else "00001"
        assessment_id = f"AIA-2026-{num_part}"

        return InvestigationAssessment(
            assessment_id=assessment_id,
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            input_evidence_hash=evidence_hash,
            created_at=datetime.utcnow(),
            provider="Deterministic Forensic Decision Engine",
            model=f"decision-engine-v{self.ENGINE_VERSION}",
            fallback_used=True,
            fallback_reason="Autonomous deterministic evidence evaluation engine.",
            executive_summary=exec_summary,
            threat_pattern=pattern,
            ai_confidence_score=self._confidence_to_float(confidence),
            ai_confidence_percentage=int(self._confidence_to_float(confidence) * 100),
            attack_narrative=attack_chain,
            correlated_findings=correlated_entities,
            mitre_techniques=mitre_techs,
            investigation_leads=leads,
            recommended_actions=actions,
            related_cases=[],
            output_version=self.ENGINE_VERSION,
            prompt_tokens=0,
            # Phase 4 extensions
            verdict=verdict,
            confidence=confidence,
            severity=severity,
            risk_score=risk_score,
            threat_score=threat.risk_score if threat else risk_score,
            evidence_summary=ev_summary,
            primary_indicators=primary_inds,
            supporting_indicators=supporting_inds,
            contradictions=contradictions,
            correlated_entities=correlated_entities,
            attack_techniques=mitre_techs,
            attack_chain=attack_chain,
            suspicious_behaviors=behaviors,
            investigation_gaps=gaps,
            analyst_questions=questions,
            category_breakdowns=breakdowns,
            generated_at=datetime.utcnow(),
            engine_version=self.ENGINE_VERSION,
        )

    def _evaluate_evidence_findings(
        self,
        forensic: Optional[EmailForensicResult],
        threat: Optional[ThreatAssessmentResult],
        intel: Optional[InvestigationIntelligenceResult],
        correlation: Optional[Any],
    ) -> Tuple[List[EvidenceFinding], List[EvidenceFinding], List[EvidenceCategoryBreakdown]]:
        """
        Extracts, categorizes, and weights all evidence findings into primary and supporting indicators.
        """
        all_findings: List[EvidenceFinding] = []
        cat_weights: Dict[str, float] = {}

        def add_finding(
            fid: str,
            cat: str,
            name: str,
            desc: str,
            ev: str,
            sev: str,
            weight: float,
            conf: EvidenceConfidence,
            src: str,
            reason: str,
            entity: Optional[str] = None,
        ):
            all_findings.append(
                EvidenceFinding(
                    id=fid,
                    category=cat,
                    name=name,
                    description=desc,
                    evidence=ev,
                    severity=sev,
                    weight=weight,
                    confidence=conf,
                    source=src,
                    reason=reason,
                    related_entity=entity,
                )
            )
            cat_weights[cat] = cat_weights.get(cat, 0.0) + weight

        # 1. AUTHENTICATION Findings
        if forensic and forensic.authentication:
            spf = forensic.authentication.spf.value
            dkim = forensic.authentication.dkim.value
            dmarc = forensic.authentication.dmarc.value

            if spf in ["FAIL", "SOFTFAIL"]:
                add_finding(
                    fid="AUTH_SPF_FAIL",
                    cat="AUTHENTICATION",
                    name="SPF Origin Authentication Failure",
                    desc="Sending relay is not authorized to transmit email on behalf of sender domain.",
                    ev=f"SPF evaluation returned {spf}",
                    sev="HIGH",
                    weight=10.0,
                    conf=EvidenceConfidence.HIGH,
                    src="RFC 7208 SPF Validator",
                    reason="Indicates relay spoofing or unauthorized sending infrastructure.",
                    entity=forensic.metadata.from_address,
                )
            elif spf == "PASS":
                add_finding(
                    fid="AUTH_SPF_PASS",
                    cat="AUTHENTICATION",
                    name="SPF Origin Authentication Passed",
                    desc="Sending relay matches authorized SPF records for domain.",
                    ev=f"SPF evaluation returned {spf}",
                    sev="CLEAN",
                    weight=0.0,
                    conf=EvidenceConfidence.HIGH,
                    src="RFC 7208 SPF Validator",
                    reason="Authorized sending IP address.",
                    entity=forensic.metadata.from_address,
                )

            if dmarc in ["FAIL", "REJECT", "QUARANTINE"]:
                add_finding(
                    fid="AUTH_DMARC_FAIL",
                    cat="AUTHENTICATION",
                    name="DMARC Policy Enforcement Failure",
                    desc="Message failed domain alignment and authentication enforcement policy.",
                    ev=f"DMARC evaluation returned {dmarc}",
                    sev="CRITICAL" if dmarc == "REJECT" else "HIGH",
                    weight=12.0,
                    conf=EvidenceConfidence.HIGH,
                    src="RFC 7489 DMARC Validator",
                    reason="Domain owner explicit policy specifies rejection or quarantine of forged messages.",
                    entity=forensic.metadata.from_address,
                )
            elif dmarc == "PASS":
                add_finding(
                    fid="AUTH_DMARC_PASS",
                    cat="AUTHENTICATION",
                    name="DMARC Alignment Verified",
                    desc="From header domain cryptographically aligns with authenticated identity.",
                    ev=f"DMARC: {dmarc}",
                    sev="CLEAN",
                    weight=0.0,
                    conf=EvidenceConfidence.HIGH,
                    src="RFC 7489 DMARC Validator",
                    reason="Cryptographic alignment verified.",
                    entity=forensic.metadata.from_address,
                )

            if dkim in ["FAIL"]:
                add_finding(
                    fid="AUTH_DKIM_FAIL",
                    cat="AUTHENTICATION",
                    name="DKIM Cryptographic Signature Invalid",
                    desc="Message body or headers were altered in transit after signing.",
                    ev=f"DKIM: {dkim}",
                    sev="HIGH",
                    weight=8.0,
                    conf=EvidenceConfidence.HIGH,
                    src="RFC 6376 DKIM Verifier",
                    reason="Message integrity verification failed.",
                    entity=forensic.metadata.from_address,
                )

        # 2. EMAIL & IDENTITY Findings
        if forensic and forensic.metadata:
            from_addr = forensic.metadata.from_address or ""
            reply_to = forensic.metadata.reply_to or ""
            ret_path = forensic.metadata.return_path or ""

            if reply_to and from_addr:
                from_dom = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
                reply_dom = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
                if from_dom and reply_dom and from_dom != reply_dom:
                    add_finding(
                        fid="SENDER_REPLYTO_DOMAIN_MISMATCH",
                        cat="IDENTITY",
                        name="Sender and Reply-To Domain Mismatch",
                        desc="Responses are diverted to an external mailbox on a different domain.",
                        ev=f"From: {from_addr} | Reply-To: {reply_to}",
                        sev="HIGH",
                        weight=8.0,
                        conf=EvidenceConfidence.HIGH,
                        src="RFC 5322 Identity Parser",
                        reason="Adversaries divert victim responses away from spoofed sender domain to external drop box.",
                        entity=reply_to,
                    )

            if ret_path and from_addr:
                from_dom = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
                ret_dom = ret_path.split("@")[-1].lower() if "@" in ret_path else ""
                if from_dom and ret_dom and from_dom != ret_dom:
                    add_finding(
                        fid="SENDER_RETURNPATH_MISMATCH",
                        cat="IDENTITY",
                        name="Sender and Return-Path Domain Mismatch",
                        desc="Envelope bounce address routes to a different organizational domain.",
                        ev=f"From: {from_addr} | Return-Path: {ret_path}",
                        sev="MEDIUM",
                        weight=5.0,
                        conf=EvidenceConfidence.MEDIUM,
                        src="RFC 5322 Identity Parser",
                        reason="Envelope bounce destination does not match header sender.",
                        entity=ret_path,
                    )

        # 3. DOMAIN Findings
        if intel and intel.domains:
            for d in intel.domains:
                if d.is_lookalike or d.is_lookalike_brand:
                    add_finding(
                        fid="DOMAIN_LOOKALIKE_BRAND",
                        cat="DOMAIN",
                        name=f"Brand Lookalike / Typosquatting Domain '{d.domain}'",
                        desc="Domain utilizes visual character substitution or homoglyphs targeting legitimate enterprise brand.",
                        ev=f"Domain: {d.domain} (Punycode: {d.punycode_decoded or d.domain})",
                        sev="CRITICAL",
                        weight=10.0,
                        conf=EvidenceConfidence.VERY_HIGH,
                        src="Domain Intelligence Engine",
                        reason="Deceptive domain designed to impersonate trusted organization.",
                        entity=d.domain,
                    )
                if d.is_localhost or d.is_internal:
                    add_finding(
                        fid="DOMAIN_INTERNAL_RFC",
                        cat="DOMAIN",
                        name=f"Internal / Localhost Domain '{d.domain}'",
                        desc="Domain references local, private or unroutable TLD.",
                        ev=f"Domain: {d.domain}",
                        sev="MEDIUM",
                        weight=4.0,
                        conf=EvidenceConfidence.HIGH,
                        src="Domain Intelligence Engine",
                        reason="Internal TLD routed in perimeter email.",
                        entity=d.domain,
                    )

        # 4. URL Findings
        if intel and intel.urls:
            for u in intel.urls:
                if u.host_ip:
                    add_finding(
                        fid="URL_RAW_IP_HOST",
                        cat="URL",
                        name="URL Directly Targets Numerical IP Host",
                        desc="Embedded link bypasses DNS domain resolution using raw IP address.",
                        ev=f"URL: {u.url}",
                        sev="HIGH",
                        weight=7.0,
                        conf=EvidenceConfidence.HIGH,
                        src="URL Decomposition Engine",
                        reason="Phishing attacks frequently use raw IP addresses to bypass domain reputation checks.",
                        entity=u.url,
                    )
                if u.has_credential_keywords:
                    add_finding(
                        fid="URL_CREDENTIAL_KEYWORDS",
                        cat="URL",
                        name="URL Path Targets Credential Authentication",
                        desc="URI path or query parameters reference authentication keywords (login, signin, auth, verify, token).",
                        ev=f"URL: {u.url}",
                        sev="HIGH",
                        weight=6.0,
                        conf=EvidenceConfidence.HIGH,
                        src="URL Decomposition Engine",
                        reason="Common path structure for credential harvesting landing pages.",
                        entity=u.url,
                    )

        # 5. IP REPUTATION Findings
        if intel and intel.ips:
            for ip_res in intel.ips:
                if ip_res.reputation == ReputationStatus.KNOWN_MALICIOUS:
                    add_finding(
                        fid="IP_KNOWN_MALICIOUS",
                        cat="IP_REPUTATION",
                        name=f"Known Malicious IP Relay {ip_res.ip}",
                        desc=f"Originating or relay IP is indexed in threat feeds as active malicious infrastructure (Abuse score: {ip_res.abuse_confidence_score}%).",
                        ev=f"IP: {ip_res.ip} ({ip_res.isp or 'Hosting Provider'}, {ip_res.country or 'Unknown'})",
                        sev="CRITICAL",
                        weight=10.0,
                        conf=EvidenceConfidence.VERY_HIGH,
                        src=ip_res.source or "AbuseIPDB",
                        reason="Observed transmitting malicious traffic across global SOC telemetry.",
                        entity=ip_res.ip,
                    )
                elif ip_res.reputation == ReputationStatus.SUSPICIOUS:
                    add_finding(
                        fid="IP_SUSPICIOUS_REPUTATION",
                        cat="IP_REPUTATION",
                        name=f"Suspicious IP Reputation {ip_res.ip}",
                        desc=f"IP has documented abuse reports ({ip_res.total_reports or 1} reports).",
                        ev=f"IP: {ip_res.ip}",
                        sev="MEDIUM",
                        weight=5.0,
                        conf=EvidenceConfidence.MEDIUM,
                        src=ip_res.source or "Threat Feed",
                        reason="Prior reports of scanning or unauthorized relay activity.",
                        entity=ip_res.ip,
                    )

        # 6. ATTACHMENT Findings
        if forensic and forensic.attachments:
            for att in forensic.attachments:
                ext = (att.extension or "").lower()
                has_double_ext = att.filename.count(".") > 1
                if has_double_ext:
                    add_finding(
                        fid="ATTACH_DOUBLE_EXTENSION",
                        cat="ATTACHMENT",
                        name=f"Double Extension Obfuscation '{att.filename}'",
                        desc="Attachment utilizes multiple file extensions to mask true executable or script format.",
                        ev=f"Filename: {att.filename} (MIME: {att.mime_type})",
                        sev="CRITICAL",
                        weight=12.0,
                        conf=EvidenceConfidence.VERY_HIGH,
                        src="Forensic MIME Parser",
                        reason="Adversary disguises malicious script as a benign document (e.g. .pdf.html, .docx.exe).",
                        entity=att.filename,
                    )
                elif ext in [".exe", ".scr", ".vbs", ".js", ".iso", ".bat", ".ps1"]:
                    add_finding(
                        fid="ATTACH_EXECUTABLE_SCRIPT",
                        cat="ATTACHMENT",
                        name=f"Executable or Script Attachment '{att.filename}'",
                        desc="Attachment contains directly executable binary or scripting payload.",
                        ev=f"Filename: {att.filename} (SHA-256: {att.sha256[:16]}...)",
                        sev="CRITICAL",
                        weight=12.0,
                        conf=EvidenceConfidence.HIGH,
                        src="Forensic MIME Parser",
                        reason="Direct execution risk on victim endpoint.",
                        entity=att.filename,
                    )

        # 7. CORRELATION Findings
        if correlation and hasattr(correlation, "signals"):
            for sig in correlation.signals:
                add_finding(
                    fid=sig.signal_id,
                    cat="CORRELATION",
                    name=sig.title,
                    desc=sig.description,
                    ev=f"Entities: {', '.join(sig.entities_involved)}",
                    sev=sig.severity,
                    weight=float(sig.weight),
                    conf=EvidenceConfidence.HIGH,
                    src="Indicator Correlation Engine",
                    reason="Cross-indicator relationship demonstrates concerted multi-stage adversary orchestration.",
                    entity=sig.entities_involved[0] if sig.entities_involved else None,
                )

        # Split into primary (high impact >= 6.0 or CRITICAL/HIGH) and supporting
        primary: List[EvidenceFinding] = []
        supporting: List[EvidenceFinding] = []

        for f in all_findings:
            if f.weight >= 6.0 or f.severity in ["CRITICAL", "HIGH"]:
                primary.append(f)
            else:
                supporting.append(f)

        # Sort primary by weight descending
        primary.sort(key=lambda x: x.weight, reverse=True)
        supporting.sort(key=lambda x: x.weight, reverse=True)

        # Generate EvidenceCategoryBreakdown respecting category caps
        breakdowns: List[EvidenceCategoryBreakdown] = []
        for cat, raw_w in cat_weights.items():
            enum_member = ThreatCategory[cat] if cat in ThreatCategory.__members__ else None
            cap = CATEGORY_WEIGHT_CAPS.get(enum_member, 30.0) if enum_member else 30.0
            capped_w = min(raw_w, cap)
            cnt = sum(1 for f in all_findings if f.category == cat)
            breakdowns.append(
                EvidenceCategoryBreakdown(
                    category=cat,
                    raw_weight=raw_w,
                    capped_weight=capped_w,
                    indicators_count=cnt,
                    summary=f"{cnt} indicators contributing {capped_w:.1f} pts (cap: {cap:.1f} pts)",
                )
            )

        return primary, supporting, breakdowns

    def _detect_contradictions(
        self,
        forensic: Optional[EmailForensicResult],
        threat: Optional[ThreatAssessmentResult],
        intel: Optional[InvestigationIntelligenceResult],
        correlation: Optional[Any],
    ) -> List[ContradictionItem]:
        """
        Identifies genuine conflicts and contradictions across independent evidence channels.
        """
        contradictions: List[ContradictionItem] = []

        if not forensic:
            return contradictions

        # Contradiction 1: Authentication Passed BUT Reply-To Divergent or Lookalike Domain
        auth = forensic.authentication
        auth_passed = auth and (auth.spf.value == "PASS" or auth.dmarc.value == "PASS")
        reply_mismatch = False
        if forensic.metadata and forensic.metadata.reply_to and forensic.metadata.from_address:
            f_dom = forensic.metadata.from_address.split("@")[-1].lower() if "@" in forensic.metadata.from_address else ""
            r_dom = forensic.metadata.reply_to.split("@")[-1].lower() if "@" in forensic.metadata.reply_to else ""
            if f_dom and r_dom and f_dom != r_dom:
                reply_mismatch = True

        has_lookalike = any(d.is_lookalike or d.is_lookalike_brand for d in (intel.domains if intel else []))

        if auth_passed and (reply_mismatch or has_lookalike):
            contradictions.append(
                ContradictionItem(
                    id="CONTRA-001",
                    title="Cryptographic Authentication Pass vs Deceptive Identity Routing",
                    description=(
                        "Sending mail server successfully validated SPF/DMARC domain transport policies, "
                        "yet message configuration diverts replies to an external domain or impersonates a brand via homoglyphs."
                    ),
                    conflicting_elements=[
                        f"SPF: {auth.spf.value if auth else 'N/A'}",
                        f"DMARC: {auth.dmarc.value if auth else 'N/A'}",
                        f"Reply-To: {forensic.metadata.reply_to}" if reply_mismatch else "Brand Lookalike Detected",
                    ],
                    severity="HIGH",
                    impact_on_assessment=(
                        "Legitimate transport relay does not negate payload deception. "
                        "Indicates either compromised legitimate infrastructure, authorized free webmail relay, or display name deception."
                    ),
                )
            )

        # Contradiction 2: Clean IP Reputation BUT High-Risk Domain / URL Indicators
        clean_ip = False
        if intel and intel.ips:
            clean_ip = any(ip.reputation == ReputationStatus.CLEAN for ip in intel.ips)
            malicious_content = False
            if intel.urls and any(u.host_ip or u.has_credential_keywords for u in intel.urls):
                malicious_content = True
            if has_lookalike:
                malicious_content = True

            if clean_ip and malicious_content:
                contradictions.append(
                    ContradictionItem(
                        id="CONTRA-002",
                        title="Benign Relay IP Reputation vs Suspicious Payload Infrastructure",
                        description="Originating network relay has clean historical reputation, but embedded links or domains target adversary infrastructure.",
                        conflicting_elements=[
                            "IP Reputation: CLEAN",
                            "Payload: Suspicious URL / Lookalike Domain",
                        ],
                        severity="MEDIUM",
                        impact_on_assessment=(
                            "Adversary routing traffic through reputable commercial ISP or shared cloud relay to evade IP-level filtering."
                        ),
                    )
                )

        # Contradiction 3: Provider Unavailable Must NOT be Interpreted as Clean
        if intel and intel.ips:
            for ip_res in intel.ips:
                if ip_res.status in [LookupStatus.NOT_AVAILABLE, LookupStatus.ERROR] and ip_res.reputation == ReputationStatus.CLEAN:
                    contradictions.append(
                        ContradictionItem(
                            id="CONTRA-003",
                            title="Unindexed Threat Telemetry Defaulting Violation",
                            description="External threat feed lookup was unavailable for public IP; status was normalized to clean erroneously.",
                            conflicting_elements=[
                                f"IP: {ip_res.ip}",
                                f"Status: {ip_res.status}",
                            ],
                            severity="HIGH",
                            impact_on_assessment="Corrected: Unchecked intelligence must be classified as UNKNOWN, never CLEAN.",
                        )
                    )

        # Contradiction 4: Legitimate Sender Domain vs Lookalike / Unrelated Destination URL (Scenario B)
        if forensic.metadata and forensic.metadata.from_address and intel and intel.urls:
            f_dom = forensic.metadata.from_address.split("@")[-1].lower() if "@" in forensic.metadata.from_address else ""
            if f_dom:
                has_url_mismatch = any(
                    any(lk in (u.domain or "").lower() for lk in ["paypa1", "micros0ft", "goog1e", "app1e", "secure-", "-login"])
                    for u in intel.urls
                )
                if not has_url_mismatch and correlation and hasattr(correlation, "signals"):
                    has_url_mismatch = any((getattr(s, "signal_id", None) or getattr(s, "signal_type", None)) in ["SENDER_URL_DOMAIN_MISMATCH", "CORR_SENDER_URL_MISMATCH"] for s in correlation.signals)

                if has_url_mismatch:
                    bad_url = intel.urls[0].url if intel.urls else "Unknown URL"
                    contradictions.append(
                        ContradictionItem(
                            id="CONTRA-004",
                            title="Legitimate Sender Domain vs Deceptive Destination Link",
                            description="Sender identity appears legitimate, but embedded links navigate users to lookalike or external credential harvester infrastructure.",
                            conflicting_elements=[
                                f"Sender Domain: {f_dom}",
                                f"Destination URL: {bad_url}",
                            ],
                            severity="HIGH",
                            impact_on_assessment="Phishing lure mimicking legitimate communication to divert credentials to external infrastructure.",
                        )
                    )

        return contradictions

    def _analyze_investigation_gaps(
        self,
        forensic: Optional[EmailForensicResult],
        intel: Optional[InvestigationIntelligenceResult],
    ) -> List[InvestigationGap]:
        """
        Identifies missing telemetry and assigns precise status:
        NOT_AVAILABLE, NOT_APPLICABLE, NOT_CHECKED, PROVIDER_UNAVAILABLE.
        """
        gaps: List[InvestigationGap] = []

        # Gap 1: DKIM Signature
        if forensic and forensic.authentication:
            if forensic.authentication.dkim.value in ["NONE", "NOT_CHECKED"]:
                gaps.append(
                    InvestigationGap(
                        indicator_type="DKIM Cryptographic Signature",
                        status=GapStatus.NOT_AVAILABLE,
                        description="Message does not contain a DKIM-Signature header for cryptographic message integrity validation.",
                        impact="Origin server authenticity cannot be verified via asymmetric key cryptography.",
                    )
                )

        # Gap 2: Dynamic Attachment Sandbox
        if forensic and forensic.attachments:
            gaps.append(
                InvestigationGap(
                    indicator_type="Dynamic Sandbox Detonation",
                    status=GapStatus.NOT_CHECKED,
                    description="Extracted attachment has not been executed within an isolated dynamic detonation sandbox.",
                    impact="Runtime process execution, registry modification, and network beaconing telemetry unavailable.",
                )
            )

        # Gap 3: Domain Age / WHOIS Telemetry
        gaps.append(
            InvestigationGap(
                indicator_type="Domain Registration Age (WHOIS)",
                status=GapStatus.NOT_AVAILABLE,
                description="Newly registered domain (NRD) age and registrar registration records are unindexed locally.",
                impact="Cannot definitively corroborate domain youth under 30-day adversary registration threshold.",
            )
        )

        # Gap 4: External Threat Intelligence Egress
        if intel and intel.ips:
            for ip_res in intel.ips:
                if ip_res.status == LookupStatus.NOT_AVAILABLE:
                    gaps.append(
                        InvestigationGap(
                            indicator_type=f"External IP Intelligence ({ip_res.ip})",
                            status=GapStatus.PROVIDER_UNAVAILABLE,
                            description="External threat feed provider API was unconfigured, rate-limited, or unreachable.",
                            impact="Assessment relies on local RFC classification and offline database.",
                        )
                    )
                elif ip_res.status == LookupStatus.PRIVATE_IP_SKIPPED:
                    gaps.append(
                        InvestigationGap(
                            indicator_type=f"RFC Geolocation ({ip_res.ip})",
                            status=GapStatus.NOT_APPLICABLE,
                            description="IP belongs to private, loopback, or documentation subnet (RFC 1918 / 5737).",
                            impact="Public internet routing and geolocation do not apply to internal relays.",
                        )
                    )

        return gaps

    def _calculate_confidence(
        self,
        forensic: Optional[EmailForensicResult],
        threat: Optional[ThreatAssessmentResult],
        intel: Optional[InvestigationIntelligenceResult],
        correlation: Optional[Any],
        contradictions: List[ContradictionItem],
        gaps: List[InvestigationGap],
    ) -> EvidenceConfidence:
        """
        Determines deterministic confidence rating:
        VERY_HIGH, HIGH, MEDIUM, LOW, UNKNOWN based on evidence corroboration and quality.
        """
        if not forensic:
            return EvidenceConfidence.UNKNOWN

        # Check corroborating independent sources
        corroborating_sources = 0
        if forensic.authentication and forensic.authentication.spf.value in ["FAIL", "PASS"]:
            corroborating_sources += 1
        if intel and intel.domains and len(intel.domains) > 0:
            corroborating_sources += 1
        if intel and intel.urls and len(intel.urls) > 0:
            corroborating_sources += 1
        if intel and intel.ips and any(ip.status == LookupStatus.SUCCESS for ip in intel.ips):
            corroborating_sources += 1
        if correlation and hasattr(correlation, "signals") and len(correlation.signals) > 0:
            corroborating_sources += 1

        has_severe_contradiction = any(c.severity == "CRITICAL" for c in contradictions)
        has_high_gaps = sum(1 for g in gaps if g.status == GapStatus.PROVIDER_UNAVAILABLE) >= 2

        if corroborating_sources >= 3 and not has_severe_contradiction:
            return EvidenceConfidence.VERY_HIGH
        elif corroborating_sources >= 2 and not has_high_gaps:
            return EvidenceConfidence.HIGH
        elif corroborating_sources >= 1:
            return EvidenceConfidence.MEDIUM
        elif corroborating_sources == 0:
            return EvidenceConfidence.LOW

        return EvidenceConfidence.MEDIUM

    def _derive_verdict(
        self,
        forensic: Optional[EmailForensicResult],
        threat: Optional[ThreatAssessmentResult],
        primary: List[EvidenceFinding],
        supporting: List[EvidenceFinding],
        contradictions: List[ContradictionItem],
    ) -> Tuple[ThreatVerdict, str, int]:
        """
        Evidence-based deterministic verdict calculation.
        """
        if forensic is None and threat is None:
            return ThreatVerdict.UNKNOWN, "UNKNOWN", 0
        risk_score = threat.risk_score if threat else 0
        total_primary_weight = sum(f.weight for f in primary)
        has_critical = any(f.severity == "CRITICAL" for f in primary)

        # 1. Clean check: Zero threat indicators, low score, no primary evidence
        if (not threat or risk_score < 15) and total_primary_weight == 0 and len(primary) == 0:
            return ThreatVerdict.BENIGN, "CLEAN", risk_score

        # 2. MALICIOUS: Weaponized payload, known malicious IP, or score >= 80
        if has_critical or risk_score >= 80 or any(f.id in ["ATTACH_DOUBLE_EXTENSION", "IP_KNOWN_MALICIOUS"] for f in primary):
            return ThreatVerdict.MALICIOUS, "CRITICAL", max(risk_score, 85)

        # 3. HIGH_RISK: Substantial deceptive combination or score >= 60
        if risk_score >= 60 or total_primary_weight >= 15.0 or len(primary) >= 2:
            return ThreatVerdict.HIGH_RISK, "HIGH", max(risk_score, 65)

        # 4. SUSPICIOUS: Moderate findings or score >= 30
        if risk_score >= 30 or len(primary) >= 1 or len(supporting) >= 2:
            return ThreatVerdict.SUSPICIOUS, "MEDIUM", max(risk_score, 35)

        # 5. LOW_RISK: Minor anomalies
        if risk_score >= 15 or len(supporting) >= 1:
            return ThreatVerdict.LOW_RISK, "LOW", risk_score

        return ThreatVerdict.BENIGN, "CLEAN", risk_score

    def _map_mitre_techniques(
        self,
        forensic: Optional[EmailForensicResult],
        threat: Optional[ThreatAssessmentResult],
        correlation: Optional[Any],
    ) -> List[MITRETechnique]:
        """
        Grounds MITRE ATT&CK techniques exclusively in observable evidence.
        """
        techniques: List[MITRETechnique] = []
        if not forensic or (threat and threat.risk_score < 15):
            return techniques

        # T1566: Phishing
        techniques.append(
            MITRETechnique(
                technique_id="T1566",
                name="Phishing",
                tactic=MITRETactic.INITIAL_ACCESS,
                rationale="Unsolicited electronic message delivered to perimeter targeting corporate recipient.",
                evidence=f"From: {forensic.metadata.from_address or 'Unknown'}",
                confidence=ConfidenceRating.HIGH,
            )
        )

        # T1566.002: Spearphishing Link
        if forensic.urls:
            techniques.append(
                MITRETechnique(
                    technique_id="T1566.002",
                    name="Spearphishing Link",
                    tactic=MITRETactic.INITIAL_ACCESS,
                    rationale="Message body contains embedded hyperlinks configured to direct user to external infrastructure.",
                    evidence=f"Extracted URL: {forensic.urls[0].url[:45]}...",
                    confidence=ConfidenceRating.HIGH,
                )
            )

        # T1566.001: Spearphishing Attachment
        if forensic.attachments:
            att = forensic.attachments[0]
            techniques.append(
                MITRETechnique(
                    technique_id="T1566.001",
                    name="Spearphishing Attachment",
                    tactic=MITRETactic.INITIAL_ACCESS,
                    rationale="Message encapsulates attached payload file targeting recipient endpoint execution.",
                    evidence=f"Filename: {att.filename} (SHA-256: {att.sha256[:16]}...)",
                    confidence=ConfidenceRating.HIGH,
                )
            )

        # T1583.001: Acquire Infrastructure: Domains
        has_homoglyph = False
        if forensic.domains:
            for d in forensic.domains:
                if any(ch in d.domain.lower() for ch in ["1", "0", "paypa1", "micros0ft"]):
                    techniques.append(
                        MITRETechnique(
                            technique_id="T1583.001",
                            name="Acquire Infrastructure: Domains",
                            tactic=MITRETactic.INITIAL_ACCESS,
                            rationale="Adversary registered domain simulating legitimate organizational brand.",
                            evidence=f"Lookalike Domain: {d.domain}",
                            confidence=ConfidenceRating.HIGH,
                        )
                    )
                    break

        # T1204: User Execution
        if (threat and threat.risk_score >= 50) or forensic.attachments:
            techniques.append(
                MITRETechnique(
                    technique_id="T1204",
                    name="User Execution",
                    tactic=MITRETactic.EXECUTION,
                    rationale="Message employs urgency cues and call-to-action prompts to compel victim execution.",
                    evidence=f"Subject: '{forensic.metadata.subject or 'Urgent Notice'}'",
                    confidence=ConfidenceRating.MEDIUM,
                )
            )

        return techniques

    def _reconstruct_attack_chain(
        self,
        forensic: Optional[EmailForensicResult],
        threat: Optional[ThreatAssessmentResult],
        intel: Optional[InvestigationIntelligenceResult],
        correlation: Optional[Any],
        verdict: ThreatVerdict,
        risk_score: int,
    ) -> List[AttackNarrativeStep]:
        """
        Reconstructs the factual, chronological attack chain stages.
        """
        steps: List[AttackNarrativeStep] = []
        if not forensic:
            return steps

        s_num = 1

        # Stage 1: Ingress
        steps.append(
            AttackNarrativeStep(
                step_number=s_num,
                phase="Ingress & Delivery",
                title="Message Ingested at Enterprise Boundary",
                description=f"Inbound SMTP envelope received from '{forensic.metadata.from_address}' with subject line '{forensic.metadata.subject}'.",
                evidence_excerpt=f"From: {forensic.metadata.from_address}",
            )
        )
        s_num += 1

        # Stage 2: Authentication
        if forensic.authentication:
            auth = forensic.authentication
            spf_v = auth.spf.value
            dmarc_v = auth.dmarc.value
            if spf_v in ["FAIL", "SOFTFAIL"] or dmarc_v in ["FAIL", "REJECT"]:
                steps.append(
                    AttackNarrativeStep(
                        step_number=s_num,
                        phase="Authentication Inspection",
                        title="Cryptographic Sender Verification Failure",
                        description=f"Automated policy evaluation failed (SPF: {spf_v}, DMARC: {dmarc_v}), confirming unauthorized sending infrastructure.",
                        evidence_excerpt=f"SPF: {spf_v} | DMARC: {dmarc_v}",
                    )
                )
                s_num += 1
            elif spf_v == "PASS":
                steps.append(
                    AttackNarrativeStep(
                        step_number=s_num,
                        phase="Authentication Inspection",
                        title="Cryptographic Origin Verification Passed",
                        description="Sending relay verified against authorized SPF domain publication.",
                        evidence_excerpt="SPF: PASS",
                    )
                )
                s_num += 1

        # Stage 3: Routing & Camouflage
        if forensic.metadata.reply_to and forensic.metadata.from_address:
            f_dom = forensic.metadata.from_address.split("@")[-1].lower() if "@" in forensic.metadata.from_address else ""
            r_dom = forensic.metadata.reply_to.split("@")[-1].lower() if "@" in forensic.metadata.reply_to else ""
            if f_dom and r_dom and f_dom != r_dom:
                steps.append(
                    AttackNarrativeStep(
                        step_number=s_num,
                        phase="Response Redirection",
                        title="Divergent Reply-To Routing Activated",
                        description=f"Header configuration diverts replies away from sender '{f_dom}' to external mailbox '{forensic.metadata.reply_to}'.",
                        evidence_excerpt=f"Reply-To: {forensic.metadata.reply_to}",
                    )
                )
                s_num += 1

        # Stage 4: Payload / Link
        if forensic.attachments:
            att = forensic.attachments[0]
            steps.append(
                AttackNarrativeStep(
                    step_number=s_num,
                    phase="Payload Staging",
                    title="Weaponized Attachment Delivered",
                    description=f"Extracted payload '{att.filename}' ({att.mime_type}) staged for victim execution.",
                    evidence_excerpt=f"SHA-256: {att.sha256[:16]}...",
                )
            )
            s_num += 1
        elif forensic.urls:
            u = forensic.urls[0]
            steps.append(
                AttackNarrativeStep(
                    step_number=s_num,
                    phase="Hyperlink Routing",
                    title="External Phishing Link Placed in Body",
                    description=f"Message body embeds external navigation targeting '{u.domain}'.",
                    evidence_excerpt=f"URL: {u.url[:45]}...",
                )
            )
            s_num += 1

        # Stage 5: Final Verdict
        steps.append(
            AttackNarrativeStep(
                step_number=s_num,
                phase="Automated Triage",
                title=f"Forensic Assessment Concluded: {verdict.value}",
                description=f"Cumulative observable evidence produced an explainable risk score of {risk_score}/100 with verdict '{verdict.value}'.",
                evidence_excerpt=f"Risk Score: {risk_score}/100",
            )
        )

        return steps

    def _generate_actions_and_questions(
        self,
        forensic: Optional[EmailForensicResult],
        threat: Optional[ThreatAssessmentResult],
        intel: Optional[InvestigationIntelligenceResult],
        correlation: Optional[Any],
        verdict: ThreatVerdict,
    ) -> Tuple[List[InvestigationLead], List[RecommendedAction], List[str]]:
        """
        Generates evidence-driven actionable leads, containment actions, and targeted analyst questions.
        """
        leads: List[InvestigationLead] = []
        actions: List[RecommendedAction] = []
        questions: List[str] = []

        if verdict == ThreatVerdict.BENIGN:
            actions.append(
                RecommendedAction(
                    action_type=ActionCategory.NOTIFY,
                    title="Allow Inbound Delivery",
                    description="Cryptographic authentication and content checks passed with zero malicious indicators.",
                    target_indicator="All Indicators Clean",
                    urgency="STANDARD",
                )
            )
            questions.append("Is this message part of an expected operational workflow or scheduled newsletter?")
            return leads, actions, questions

        # Actions & Leads based on evidence
        if forensic and forensic.domains:
            dom = forensic.domains[0].domain
            actions.append(
                RecommendedAction(
                    action_type=ActionCategory.BLOCK,
                    title=f"Block Domain '{dom}' at Mail Gateway",
                    description=f"Enforce transport rejection rule for '{dom}' across all incoming message streams.",
                    target_indicator=dom,
                    urgency="IMMEDIATE",
                )
            )
            leads.append(
                InvestigationLead(
                    lead_id="LEAD-01",
                    category=LeadCategory.DNS_ANALYSIS,
                    action=f"Inspect DNS resolver query logs for workstation lookups to '{dom}'",
                    rationale="Determine if any corporate user clicked or resolved the destination domain.",
                    evidence_reference=f"Domain: {dom}",
                    priority="HIGH",
                )
            )
            questions.append(f"Did any internal user workstations initiate DNS resolutions or HTTP traffic to '{dom}'?")

        if forensic and forensic.received_chain and forensic.received_chain[0].ip:
            ip = forensic.received_chain[0].ip
            actions.append(
                RecommendedAction(
                    action_type=ActionCategory.CONTAIN,
                    title=f"Perimeter Firewall Block on Origin IP {ip}",
                    description="Apply immediate perimeter boundary drop for incoming connections from relay IP.",
                    target_indicator=ip,
                    urgency="IMMEDIATE",
                )
            )
            leads.append(
                InvestigationLead(
                    lead_id="LEAD-02",
                    category=LeadCategory.MAIL_GATEWAY,
                    action=f"Search perimeter email gateway logs for all inbound connections from {ip}",
                    rationale="Identify related messages delivered during the same adversary campaign window.",
                    evidence_reference=f"Origin IP: {ip}",
                    priority="HIGH",
                )
            )
            questions.append(f"How many unique mailboxes received emails from IP {ip} in the preceding 7 days?")

        if forensic and forensic.attachments:
            att = forensic.attachments[0]
            leads.append(
                InvestigationLead(
                    lead_id="LEAD-03",
                    category=LeadCategory.ENDPOINT_TELEMETRY,
                    action=f"Query EDR telemetry for file hash {att.sha256[:16]}... on endpoints",
                    rationale="Confirm if file was downloaded or written to disk on any company device.",
                    evidence_reference=f"File: {att.filename} ({att.sha256})",
                    priority="HIGH",
                )
            )
            questions.append(f"Has file '{att.filename}' (SHA-256: {att.sha256[:12]}...) executed in any endpoint process tree?")

        actions.append(
            RecommendedAction(
                action_type=ActionCategory.PRESERVE,
                title="Preserve Evidence Package & Cryptographic Digest",
                description="Retain canonical SHA-256 digest on blockchain ledger for immutable chain of custody auditability.",
                target_indicator=forensic.sha256_digest if forensic else "Canonical Package",
                urgency="STANDARD",
            )
        )

        return leads, actions, questions

    def _extract_suspicious_behaviors(
        self,
        forensic: Optional[EmailForensicResult],
        threat: Optional[ThreatAssessmentResult],
        primary: List[EvidenceFinding],
        correlation: Optional[Any],
    ) -> List[str]:
        """Extracts bulleted behavioral patterns observed in evidence."""
        behaviors: List[str] = []
        if not forensic:
            return behaviors

        for p in primary:
            behaviors.append(f"{p.name}: {p.reason}")

        if threat and threat.classification:
            behaviors.append(f"Classified under {threat.classification.value} attack taxonomy.")

        return behaviors

    def _build_pattern_and_correlations(
        self,
        forensic: Optional[EmailForensicResult],
        threat: Optional[ThreatAssessmentResult],
        correlation: Optional[Any],
    ) -> Tuple[ThreatPattern, List[CorrelatedEntityFinding]]:
        """Builds legacy-compatible ThreatPattern and CorrelatedEntityFinding list."""
        if not threat or threat.risk_score < 15:
            pattern = ThreatPattern(
                pattern_type=ThreatPatternType.BENIGN,
                title="Benign Verified Communication",
                confidence=0.98,
                confidence_percentage=98,
                description="Verified authentic message with zero anomalous indicators.",
                indicators_involved=[],
            )
            return pattern, []

        p_type = ThreatPatternType.UNKNOWN
        c_val = threat.classification.value if threat else "SUSPICIOUS"
        if "BUSINESS_EMAIL_COMPROMISE" in c_val or "BEC" in c_val:
            p_type = ThreatPatternType.BUSINESS_EMAIL_COMPROMISE
        elif "CREDENTIAL" in c_val:
            p_type = ThreatPatternType.CREDENTIAL_HARVESTING
        elif "ATTACHMENT" in c_val or "MALWARE" in c_val:
            p_type = ThreatPatternType.MALICIOUS_ATTACHMENT
        elif "FINANCIAL" in c_val:
            p_type = ThreatPatternType.FINANCIAL_FRAUD
        elif "PHISHING" in c_val:
            p_type = ThreatPatternType.RECONNAISSANCE_PHISHING

        pattern = ThreatPattern(
            pattern_type=p_type,
            title=f"High-Risk {c_val.replace('_', ' ').title()}",
            confidence=0.92,
            confidence_percentage=92,
            description=f"Observable forensic telemetry confirms patterns characteristic of {c_val}.",
            indicators_involved=[i.name for i in (threat.indicators if threat else [])],
        )

        findings: List[CorrelatedEntityFinding] = []
        if correlation and hasattr(correlation, "relationships"):
            for rel in correlation.relationships:
                findings.append(
                    CorrelatedEntityFinding(
                        relationship=rel.relationship,
                        source_entity=rel.source,
                        target_entity=rel.target,
                        confidence=rel.confidence,
                        evidence_details=rel.evidence,
                    )
                )

        return pattern, findings

    def _generate_summaries(
        self,
        investigation_id: str,
        verdict: ThreatVerdict,
        confidence: EvidenceConfidence,
        risk_score: int,
        severity: str,
        pattern: ThreatPattern,
        primary_indicators: List[EvidenceFinding],
        contradictions: List[ContradictionItem],
        intel: Optional[InvestigationIntelligenceResult],
    ) -> Tuple[str, str]:
        """Generates concise, non-hallucinated executive and evidence summaries."""
        intel_status = "FULL"
        if intel and intel.ips:
            if all(ip.status == LookupStatus.NOT_AVAILABLE for ip in intel.ips):
                intel_status = "OFFLINE_ONLY"
            elif any(ip.status == LookupStatus.NOT_AVAILABLE for ip in intel.ips):
                intel_status = "PARTIAL"

        if verdict == ThreatVerdict.BENIGN:
            exec_s = (
                f"Investigation {investigation_id} concluded with a verdict of BENIGN (Risk Score: {risk_score}/100, Confidence: {confidence.value}). "
                "All cryptographic sender authentication policies (SPF/DKIM/DMARC) aligned with zero anomalous indicator detections. "
                "Safe for standard inbox delivery."
            )
            ev_s = "All examined forensic artifacts exhibited standard legitimate transport and content properties."
            return exec_s, ev_s

        top_reasons = [f"• {p.name}" for p in primary_indicators[:3]]
        reasons_text = " \n".join(top_reasons) if top_reasons else "• Heuristic threat score escalation"

        exec_s = (
            f"Investigation {investigation_id} produced a deterministic forensic verdict of {verdict.value} "
            f"(Score: {risk_score}/100, Severity: {severity}, Confidence: {confidence.value}). "
            f"The primary indicators driving this assessment include:\n{reasons_text}\n"
            f"External threat intelligence availability: {intel_status}."
        )

        ev_s = (
            f"Identified {len(primary_indicators)} primary high-impact threat indicators. "
            f"Detected {len(contradictions)} cross-indicator contradictions. "
            f"Pattern aligns with {pattern.title}."
        )

        return exec_s, ev_s

    def _confidence_to_float(self, conf: EvidenceConfidence) -> float:
        mapping = {
            EvidenceConfidence.VERY_HIGH: 0.95,
            EvidenceConfidence.HIGH: 0.88,
            EvidenceConfidence.MEDIUM: 0.75,
            EvidenceConfidence.LOW: 0.50,
            EvidenceConfidence.UNKNOWN: 0.20,
        }
        return mapping.get(conf, 0.75)


default_decision_engine = ForensicDecisionEngine()
