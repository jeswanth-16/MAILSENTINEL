import asyncio
import copy
from datetime import datetime
import pytest

from app.services.ai.models import (
    AIAnalystAssessment,
    EvidenceConfidence,
    GapStatus,
    InvestigationAssessment,
    ThreatVerdict,
)
from app.services.ai.service import default_ai_service
from app.services.decision import default_decision_engine
from app.services.email.models import AuthenticationVerdict
from app.services.forensics.service import investigation_registry
from app.services.intelligence.models import (
    DomainIntelligenceResult,
    IPIntelligenceResult,
    InvestigationIntelligenceResult,
    InvestigationIntelligenceSummary,
    LookupStatus,
    ReputationStatus,
    URLIntelligenceResult,
)
from app.services.persistence.assessment_repository import (
    AssessmentSqliteRepository,
    default_assessment_sqlite_repository,
)


def test_assessment_generation_phishing():
    """Verifies that high-risk phishing emails produce MALICIOUS/HIGH_RISK verdicts with explainable primary evidence."""
    async def run():
        await investigation_registry.ensure_seeded()
        f = investigation_registry.get_forensic("INV-2026-00001")
        t = investigation_registry.get_threat("INV-2026-00001")
        i = investigation_registry.get_intelligence("INV-2026-00001")
        c = investigation_registry.get_correlation("INV-2026-00001")

        assessment = default_decision_engine.evaluate_investigation(
            investigation_id="INV-2026-00001",
            evidence_id="EVD-2026-00001",
            evidence_hash="test_hash_phish",
            forensic=f,
            threat=t,
            intel=i,
            correlation=c,
        )

        assert assessment.investigation_id == "INV-2026-00001"
        assert assessment.verdict in [ThreatVerdict.MALICIOUS, ThreatVerdict.HIGH_RISK]
        assert assessment.confidence in [EvidenceConfidence.VERY_HIGH, EvidenceConfidence.HIGH]
        assert assessment.risk_score >= 80
        assert len(assessment.primary_indicators) >= 2

        # Check primary indicator structure
        p1 = assessment.primary_indicators[0]
        assert p1.weight > 0
        assert len(p1.evidence) > 0
        assert len(p1.reason) > 0
        assert p1.source is not None
        assert p1.confidence in [EvidenceConfidence.VERY_HIGH, EvidenceConfidence.HIGH]

        # Check engine version
        assert assessment.engine_version == "4.0"

    asyncio.run(run())


def test_assessment_generation_clean():
    """Verifies that clean emails produce BENIGN verdict without unsupported malicious indicators."""
    async def run():
        await investigation_registry.ensure_seeded()
        f = investigation_registry.get_forensic("INV-2026-00004")
        t = investigation_registry.get_threat("INV-2026-00004")
        i = investigation_registry.get_intelligence("INV-2026-00004")
        c = investigation_registry.get_correlation("INV-2026-00004")

        assessment = default_decision_engine.evaluate_investigation(
            investigation_id="INV-2026-00004",
            evidence_id="EVD-2026-00004",
            evidence_hash="test_hash_clean",
            forensic=f,
            threat=t,
            intel=i,
            correlation=c,
        )

        assert assessment.verdict in [ThreatVerdict.BENIGN, ThreatVerdict.LOW_RISK]
        assert assessment.risk_score <= 15
        assert len(assessment.primary_indicators) == 0
        assert len(assessment.mitre_techniques) == 0
        assert "BENIGN" in assessment.executive_summary

    asyncio.run(run())


def test_contradiction_detection_auth_pass_with_replyto_mismatch():
    """Verifies explicit contradiction detection when transport auth passes but reply-to redirects."""
    async def run():
        await investigation_registry.ensure_seeded()
        f = copy.deepcopy(investigation_registry.get_forensic("INV-2026-00001"))
        t = copy.deepcopy(investigation_registry.get_threat("INV-2026-00001"))
        i = copy.deepcopy(investigation_registry.get_intelligence("INV-2026-00001"))

        # Simulate authentication PASS but spoofed reply-to
        f.authentication.spf = AuthenticationVerdict.PASS
        f.authentication.dmarc = AuthenticationVerdict.PASS
        f.metadata.from_address = "legitimate-ceo@corporate.com"
        f.metadata.reply_to = "attacker-drop@external-mailinator.com"

        contradictions = default_decision_engine._detect_contradictions(f, t, i, None)
        assert len(contradictions) >= 1
        c = contradictions[0]
        assert "CONTRA-001" in c.id or "Authentication Pass" in c.title
        assert any("Reply-To" in el or "attacker-drop" in el for el in c.conflicting_elements)
        assert "compromised" in c.impact_on_assessment.lower() or "deception" in c.impact_on_assessment.lower()

    asyncio.run(run())


def test_contradiction_detection_clean_ip_with_suspicious_payload():
    """Verifies contradiction detection when relay IP is clean but payload contains credential phishing."""
    async def run():
        await investigation_registry.ensure_seeded()
        f = copy.deepcopy(investigation_registry.get_forensic("INV-2026-00001"))
        t = copy.deepcopy(investigation_registry.get_threat("INV-2026-00001"))

        # Intel with CLEAN IP but credential phishing URL
        clean_ip_res = IPIntelligenceResult(
            entity_id="ip:8.8.8.8",
            ip="8.8.8.8",
            reputation=ReputationStatus.CLEAN,
            status=LookupStatus.SUCCESS,
        )
        susp_url_res = URLIntelligenceResult(
            entity_id="url:test",
            url="http://8.8.8.8/auth/login.php",
            domain="8.8.8.8",
            normalized_url="http://8.8.8.8/auth/login.php",
            host_ip="8.8.8.8",
            has_credential_keywords=True,
        )
        custom_intel = InvestigationIntelligenceResult(
            investigation_id="INV-TEST",
            ips=[clean_ip_res],
            domains=[],
            urls=[susp_url_res],
            summary=InvestigationIntelligenceSummary(),
        )

        contradictions = default_decision_engine._detect_contradictions(f, t, custom_intel, None)
        assert any("Benign Relay IP" in c.title or "CLEAN" in str(c.conflicting_elements) for c in contradictions)

    asyncio.run(run())


def test_investigation_gaps_classification():
    """Verifies that missing telemetry is classified into proper GapStatus categories."""
    async def run():
        await investigation_registry.ensure_seeded()
        f = copy.deepcopy(investigation_registry.get_forensic("INV-2026-00001"))

        # IP intel with NOT_AVAILABLE and PRIVATE_IP_SKIPPED
        unavail_ip = IPIntelligenceResult(
            entity_id="ip:198.51.100.1",
            ip="198.51.100.1",
            reputation=ReputationStatus.UNKNOWN,
            status=LookupStatus.NOT_AVAILABLE,
        )
        priv_ip = IPIntelligenceResult(
            entity_id="ip:192.168.1.1",
            ip="192.168.1.1",
            reputation=ReputationStatus.UNKNOWN,
            status=LookupStatus.PRIVATE_IP_SKIPPED,
        )
        intel = InvestigationIntelligenceResult(
            investigation_id="INV-TEST",
            ips=[unavail_ip, priv_ip],
            domains=[],
            urls=[],
            summary=InvestigationIntelligenceSummary(),
        )

        gaps = default_decision_engine._analyze_investigation_gaps(f, intel)

        statuses = {g.status for g in gaps}
        assert GapStatus.PROVIDER_UNAVAILABLE in statuses
        assert GapStatus.NOT_APPLICABLE in statuses
        assert GapStatus.NOT_CHECKED in statuses  # Dynamic sandbox
        assert GapStatus.NOT_AVAILABLE in statuses  # WHOIS / DKIM

    asyncio.run(run())


def test_evidence_weighting_and_category_caps():
    """Verifies that evidence category breakdown enforces defined category caps."""
    async def run():
        await investigation_registry.ensure_seeded()
        f = investigation_registry.get_forensic("INV-2026-00001")
        t = investigation_registry.get_threat("INV-2026-00001")
        i = investigation_registry.get_intelligence("INV-2026-00001")
        c = investigation_registry.get_correlation("INV-2026-00001")

        _, _, breakdowns = default_decision_engine._evaluate_evidence_findings(f, t, i, c)

        assert len(breakdowns) >= 2
        for b in breakdowns:
            assert b.capped_weight <= b.raw_weight
            assert b.capped_weight >= 0
            if b.category == "CORRELATION":
                assert b.capped_weight <= 15.0

    asyncio.run(run())


def test_mitre_mapping_requires_supporting_evidence():
    """Verifies that MITRE ATT&CK techniques are only mapped when justified by observable artifacts."""
    async def run():
        await investigation_registry.ensure_seeded()
        f = investigation_registry.get_forensic("INV-2026-00001")
        t = investigation_registry.get_threat("INV-2026-00001")
        c = investigation_registry.get_correlation("INV-2026-00001")

        techs = default_decision_engine._map_mitre_techniques(f, t, c)
        tech_ids = {t.technique_id for t in techs}

        assert "T1566" in tech_ids  # Phishing
        if f.urls:
            assert "T1566.002" in tech_ids  # Spearphishing Link
        if f.attachments:
            assert "T1566.001" in tech_ids  # Spearphishing Attachment

        for tech in techs:
            assert len(tech.evidence) > 0
            assert len(tech.rationale) > 0

    asyncio.run(run())


def test_attack_chain_reconstruction_factual():
    """Verifies that the attack chain stages are factual and sequential."""
    async def run():
        await investigation_registry.ensure_seeded()
        f = investigation_registry.get_forensic("INV-2026-00001")
        t = investigation_registry.get_threat("INV-2026-00001")
        i = investigation_registry.get_intelligence("INV-2026-00001")
        c = investigation_registry.get_correlation("INV-2026-00001")

        steps = default_decision_engine._reconstruct_attack_chain(
            f, t, i, c, ThreatVerdict.MALICIOUS, 95
        )

        assert len(steps) >= 4
        # Verify sequential numbering
        for idx, s in enumerate(steps, 1):
            assert s.step_number == idx
            assert len(s.phase) > 0
            assert len(s.title) > 0

    asyncio.run(run())


def test_assessment_sqlite_persistence_and_restart():
    """Verifies that assessments survive application restarts via SQLite persistence."""
    async def run():
        assessment = await default_ai_service.analyze_investigation("INV-2026-00001", force_refresh=True)
        assert assessment is not None
        assert assessment.verdict in [ThreatVerdict.MALICIOUS, ThreatVerdict.HIGH_RISK]

        # Simulate fresh repository instance
        new_repo = AssessmentSqliteRepository()
        persisted = new_repo.get_assessment("INV-2026-00001")

        assert persisted is not None
        assert persisted.assessment_id == assessment.assessment_id
        assert persisted.verdict == assessment.verdict
        assert persisted.risk_score == assessment.risk_score
        assert persisted.engine_version == "4.0"
        assert len(persisted.primary_indicators) == len(assessment.primary_indicators)

    asyncio.run(run())


def test_api_assessment_endpoints_and_backward_compatibility(client):
    """Verifies GET and POST assessment endpoints and backward compatibility with /ai/assessment."""
    # 1. Test Phase 4 endpoint: GET /api/v1/investigations/{id}/assessment
    res_phase4 = client.get("/api/v1/investigations/INV-2026-00001/assessment")
    assert res_phase4.status_code == 200
    data4 = res_phase4.json()
    assert "verdict" in data4
    assert data4["verdict"] in ["MALICIOUS", "HIGH_RISK"]
    assert "confidence" in data4
    assert "primary_indicators" in data4
    assert "contradictions" in data4
    assert "investigation_gaps" in data4
    assert data4["engine_version"] == "4.0"

    # 2. Test backward compatibility: GET /api/v1/ai/assessment/{id}
    res_legacy = client.get("/api/v1/ai/assessment/INV-2026-00001")
    assert res_legacy.status_code == 200
    data_legacy = res_legacy.json()
    assert "executive_summary" in data_legacy
    assert "threat_pattern" in data_legacy
    assert "attack_narrative" in data_legacy
    assert "mitre_techniques" in data_legacy

    # 3. Test recalculate endpoint: POST /api/v1/investigations/{id}/assessment/recalculate
    res_recalc = client.post("/api/v1/investigations/INV-2026-00001/assessment/recalculate")
    assert res_recalc.status_code == 200
    data_recalc = res_recalc.json()
    assert data_recalc["investigation_id"] == "INV-2026-00001"
    assert data_recalc["verdict"] in ["MALICIOUS", "HIGH_RISK"]


def test_zero_secret_or_key_leakage_in_assessment():
    """Verifies that API keys, authentication tokens, and secrets are never exposed in assessments."""
    async def run():
        assessment = await default_ai_service.analyze_investigation("INV-2026-00001")
        dump = assessment.model_dump_json()

        forbidden_patterns = [
            "ABUSEIPDB_API_KEY",
            "GEMINI_API_KEY",
            "PRIVATE_KEY",
            "SECRET_KEY",
            "Bearer ",
            "password123",
        ]

        for p in forbidden_patterns:
            assert p not in dump, f"Sensitive secret pattern '{p}' leaked in assessment!"

    asyncio.run(run())
