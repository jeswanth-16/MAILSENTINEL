import os
import pytest
from app.core.database import init_db
from app.services.blockchain.service import BlockchainService
from app.services.blockchain.storage import BlockchainEvidenceStore
from app.services.case_management.repository import CaseRepository
from app.services.case_management.service import IncidentCaseManagementService
from app.services.forensics.service import ForensicsService, InvestigationRegistry
from app.services.investigations.service import CaseManagementService
from app.services.persistence.case_repository import CaseSqliteRepository
from app.services.persistence.investigation_repository import InvestigationSqliteRepository


@pytest.mark.anyio
async def test_full_e2e_restart_persistence_simulation(tmp_path):
    """
    Simulates the full end-to-end lifecycle across a complete server restart:
    1. Ingest & analyze real sample email via full automated triage pipeline
    2. Verify investigation, threat assessment, intel, timeline, graph, blockchain anchor
    3. Create incident case with actions and notes
    4. Simulate complete server shutdown & memory wipe
    5. Spin up fresh backend services connected to the same SQLite database
    6. Verify that all investigation details, overview, timeline, graph, and case survive 100% intact
    """
    db_file = str(tmp_path / "mailsentinel_e2e.db")
    init_db(db_file)

    inv_repo_1 = InvestigationSqliteRepository(db_path=db_file)
    case_repo_1 = CaseSqliteRepository(db_path=db_file)

    # Isolated service stack 1 (Pre-restart)
    investigation_service_1 = CaseManagementService(persistence=inv_repo_1)
    case_repository_1 = CaseRepository(persistence=case_repo_1)
    case_service_1 = IncidentCaseManagementService(repository=case_repository_1)

    # Read real phishing fixture
    fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
    phishing_path = os.path.join(fixtures_dir, "sample_phishing.eml")
    assert os.path.exists(phishing_path), "sample_phishing.eml fixture must exist"

    with open(phishing_path, "rb") as f:
        eml_bytes = f.read()

    # Step 1: Run full automated investigation pipeline
    triage_result = await investigation_service_1.run_full_investigation(
        file_bytes=eml_bytes,
        filename="sample_phishing.eml",
        analyst="SOC-LEAD-ANALYST",
    )
    inv = triage_result["investigation"]
    inv_id = inv.id
    assert inv_id.startswith("INV-2026-")
    assert inv.risk_score > 70
    assert inv.blockchain_status == "ANCHORED"

    # Step 2: Create an incident case for this investigation
    case = await case_service_1.create_case_from_investigation(
        investigation_id=inv_id,
        title="Automated Triage: CEO Wire Transfer Impersonation",
        assigned_analyst="SOC-LEAD-ANALYST",
        actor="SOC-LEAD-ANALYST",
    )
    case_id = case.case_id
    assert case_id.startswith("CASE-2026-")
    assert case.risk_score == inv.risk_score

    # Add a note and action to the case
    await case_service_1.add_note(
        case_id=case_id,
        content="Analyzed lookalike domain. Confirmed homoglyph bypass.",
        author="SOC-LEAD-ANALYST",
    )

    # =========================================================================
    # Step 3: SIMULATE COMPLETE PROCESS SHUTDOWN & RESTART
    # All in-memory registries, caches, and service instances are destroyed
    # =========================================================================
    del investigation_service_1
    del case_service_1
    del case_repository_1
    del inv_repo_1
    del case_repo_1

    # =========================================================================
    # Step 4: RE-INITIALIZE FRESH BACKEND SERVICES CONNECTED TO SQLITE
    # =========================================================================
    inv_repo_2 = InvestigationSqliteRepository(db_path=db_file)
    case_repo_2 = CaseSqliteRepository(db_path=db_file)

    investigation_service_2 = CaseManagementService(persistence=inv_repo_2)
    case_repository_2 = CaseRepository(persistence=case_repo_2)
    case_service_2 = IncidentCaseManagementService(repository=case_repository_2)

    # Rehydrate services from SQLite
    await investigation_service_2.ensure_seeded()
    case_repository_2.ensure_seeded()

    # Step 5: VERIFY INVESTIGATION PERSISTENCE ACROSS RESTART
    loaded_inv = await investigation_service_2.get_investigation(inv_id)
    assert loaded_inv is not None, f"Investigation {inv_id} must survive backend restart"
    assert loaded_inv.id == inv_id
    assert loaded_inv.risk_score == inv.risk_score
    assert loaded_inv.severity == inv.severity
    assert loaded_inv.classification == inv.classification
    assert loaded_inv.blockchain_status == "ANCHORED"

    # Step 6: VERIFY OVERVIEW PERSISTENCE ACROSS RESTART
    overview = await investigation_service_2.get_overview(inv_id)
    assert overview is not None, "Overview must survive backend restart"
    assert overview.investigation.id == inv_id
    assert len(overview.top_indicators) > 0, "Threat indicators must survive restart"
    assert "spf" in overview.auth_summary, "Authentication summary must survive restart"
    assert overview.blockchain_summary["status"] == "ANCHORED"

    # Step 7: VERIFY TIMELINE PERSISTENCE ACROSS RESTART
    timeline = await ForensicsService().get_investigation_timeline(inv_id)
    assert timeline is not None, "Forensic timeline must be reconstructible after restart"
    assert timeline.total_events > 0

    # Step 8: VERIFY ATTACK GRAPH PERSISTENCE ACROSS RESTART
    graph = await ForensicsService().get_investigation_graph(inv_id)
    assert graph is not None, "Attack graph must be reconstructible after restart"
    assert len(graph.nodes) > 0
    assert len(graph.edges) > 0

    # Step 9: VERIFY REPORT DATA PERSISTENCE ACROSS RESTART
    report = await investigation_service_2.get_report_data(inv_id)
    assert report is not None, "Report dossier must survive restart"
    assert report["case"]["id"] == inv_id
    assert report["forensic_summary"] is not None
    assert report["threat_assessment"] is not None

    # Step 10: VERIFY CASE PERSISTENCE ACROSS RESTART
    loaded_case = await case_service_2.get_case(case_id)
    assert loaded_case is not None, f"Case {case_id} must survive backend restart"
    assert loaded_case.case_id == case_id
    assert loaded_case.investigation_id == inv_id
    assert loaded_case.risk_score == inv.risk_score
    assert any("Confirmed homoglyph bypass" in n.content for n in loaded_case.notes)

    # Step 11: VERIFY AUDIT TRAIL ACROSS RESTART
    audit_trail = await case_service_2.get_audit_trail(case_id)
    assert len(audit_trail) >= 1
    assert any("CASE_CREATED" in str(a.event_type) for a in audit_trail)
