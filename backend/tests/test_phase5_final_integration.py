import pytest
from app.services.ai.models import ThreatVerdict, EvidenceConfidence, GapStatus
from app.services.ai.service import default_ai_service
from app.services.case_management.models import IncidentVerdict
from app.services.case_management.service import default_incident_case_service
from app.services.forensics.service import investigation_registry, ForensicsService
from app.services.investigations.service import default_case_service


@pytest.mark.anyio
async def test_demo1_malicious_phishing_scenario():
    """DEMO 1: Phishing investigation evaluation with multiple corroborating indicators."""
    await investigation_registry.ensure_seeded()
    await default_case_service.ensure_seeded()

    assessment = await default_ai_service.get_assessment("INV-2026-00001")
    assert assessment is not None
    assert assessment.investigation_id == "INV-2026-00001"
    assert assessment.verdict == ThreatVerdict.MALICIOUS
    assert assessment.confidence == EvidenceConfidence.VERY_HIGH
    assert assessment.risk_score >= 80
    assert len(assessment.primary_indicators) >= 2
    assert any("paypa1" in ind.evidence.lower() or "paypa1" in ind.name.lower() for ind in assessment.primary_indicators)
    assert len(assessment.mitre_techniques) >= 1
    assert any("T1566" in t.technique_id for t in assessment.mitre_techniques)


@pytest.mark.anyio
async def test_demo2_benign_clean_scenario():
    """DEMO 2: Verified benign internal email evaluation."""
    await investigation_registry.ensure_seeded()
    await default_case_service.ensure_seeded()

    assessment = await default_ai_service.get_assessment("INV-2026-00004")
    assert assessment is not None
    assert assessment.investigation_id == "INV-2026-00004"
    assert assessment.verdict == ThreatVerdict.BENIGN
    assert assessment.confidence == EvidenceConfidence.VERY_HIGH
    assert assessment.risk_score < 15
    assert len(assessment.primary_indicators) == 0
    assert len(assessment.mitre_techniques) == 0


@pytest.mark.anyio
async def test_demo3_contradictory_scenario():
    """DEMO 3: SPF/DMARC pass with divergent Reply-To and lookalike URL."""
    await investigation_registry.ensure_seeded()
    await default_case_service.ensure_seeded()

    assessment = await default_ai_service.refresh_assessment("INV-2026-00003")
    assert assessment is not None
    assert assessment.investigation_id == "INV-2026-00003"
    # Contradiction must be exposed
    assert len(assessment.contradictions) >= 1
    assert any("CONTRA-001" in c.id or "CONTRA-004" in c.id or "CONTRA-002" in c.id for c in assessment.contradictions)
    # Verdict must reflect elevated risk despite passing auth
    assert assessment.verdict in [ThreatVerdict.HIGH_RISK, ThreatVerdict.SUSPICIOUS, ThreatVerdict.MALICIOUS]


@pytest.mark.anyio
async def test_demo4_incomplete_intelligence_scenario():
    """DEMO 4: RFC private relay and unindexed remote IP must surface explicit gaps without false clean."""
    await investigation_registry.ensure_seeded()
    await default_case_service.ensure_seeded()

    assessment = await default_ai_service.refresh_assessment("INV-2026-00005")
    assert assessment is not None
    assert assessment.investigation_id == "INV-2026-00005"
    assert len(assessment.investigation_gaps) >= 1
    # Gaps must include NOT_APPLICABLE or PROVIDER_UNAVAILABLE/NOT_AVAILABLE
    gap_statuses = [g.status for g in assessment.investigation_gaps]
    assert GapStatus.NOT_APPLICABLE in gap_statuses or GapStatus.PROVIDER_UNAVAILABLE in gap_statuses or GapStatus.NOT_AVAILABLE in gap_statuses
    # Missing intelligence must NOT default to benign
    assert assessment.verdict != ThreatVerdict.BENIGN


@pytest.mark.anyio
async def test_attack_graph_hardening_no_dangling_or_duplicate_edges():
    """Validates attack graph construction invariants: valid node references and zero duplicate edges."""
    await investigation_registry.ensure_seeded()
    forensics_svc = ForensicsService()

    graph = await forensics_svc.get_investigation_graph("INV-2026-00001")
    assert graph is not None

    node_ids = {n.id for n in graph.nodes}
    seen_edges = set()

    for edge in graph.edges:
        # 1. No dangling edges
        assert edge.source in node_ids, f"Dangling edge source: {edge.source}"
        assert edge.target in node_ids, f"Dangling edge target: {edge.target}"

        # 2. No duplicate edge of same type between same endpoints
        key = (edge.source, edge.target, edge.type)
        assert key not in seen_edges, f"Duplicate edge detected: {key}"
        seen_edges.add(key)


def test_api_404_hardening(client):
    """Calling assessment routes with non-existent investigation ID must cleanly return HTTP 404."""
    # 1. Phase 4 route
    res1 = client.get("/api/v1/investigations/INV-DOES-NOT-EXIST-9999/assessment")
    assert res1.status_code == 404
    assert "not found" in res1.json()["detail"].lower()

    # 2. Recalculate route
    res2 = client.post("/api/v1/investigations/INV-DOES-NOT-EXIST-9999/assessment/recalculate")
    assert res2.status_code == 404
    assert "not found" in res2.json()["detail"].lower()

    # 3. AI route
    res3 = client.get("/api/v1/ai/assessment/INV-DOES-NOT-EXIST-9999")
    assert res3.status_code == 404
    assert "not found" in res3.json()["detail"].lower()


@pytest.mark.anyio
async def test_verdict_consistency_across_case_promotion():
    """Case promotion from investigation inherits the decision engine assessment verdict."""
    await investigation_registry.ensure_seeded()
    await default_case_service.ensure_seeded()

    # Get assessment verdict for INV-2026-00001
    assessment = await default_ai_service.get_assessment("INV-2026-00001")
    assert assessment.verdict == ThreatVerdict.MALICIOUS

    # Promote to incident case
    case = await default_incident_case_service.create_case_from_investigation(
        investigation_id="INV-2026-00001",
        title="Escalated P1 BEC Fraud",
    )
    assert case is not None
    assert case.verdict == IncidentVerdict.MALICIOUS


def test_zero_secret_or_key_leakage_across_demos(client):
    """Ensures no API keys, private tokens, or secrets leak in demo responses."""
    for inv_id in ["INV-2026-00001", "INV-2026-00003", "INV-2026-00004", "INV-2026-00005"]:
        res = client.get(f"/api/v1/investigations/{inv_id}/assessment")
        if res.status_code == 200:
            text = res.text
            assert "AIzaSy" not in text
            assert "sk-" not in text
            assert "PRIVATE_KEY" not in text
            assert "ABUSEIPDB_API_KEY" not in text
