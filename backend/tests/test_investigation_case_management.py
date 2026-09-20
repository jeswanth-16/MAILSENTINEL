import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.investigations.models import (
    InvestigationStatus,
    InvestigationSeverity,
    InvestigationClassification,
    InvestigationPriority,
    NoteType,
)
from app.services.investigations.service import default_case_service



@pytest.mark.anyio
async def test_case_management_service_lifecycle():
    # 1. Create a new case
    new_case = await default_case_service.create_investigation(
        title="Test Phishing Case for Unit Testing",
        description="Suspicious payment link received in customer service queue.",
        source="SOC_MANUAL",
        severity=InvestigationSeverity.HIGH,
        classification=InvestigationClassification.PHISHING,
        risk_score=78,
        assigned_analyst="UNASSIGNED",
        priority=InvestigationPriority.P2_HIGH,
        tags=["TestTag", "PaymentScam"],
        sender="phisher@scam-payments.xyz",
        subject="Action Required: Update Bank Account",
    )

    assert new_case.id.startswith("INV-2026-")
    assert new_case.status == InvestigationStatus.NEW
    assert new_case.severity == InvestigationSeverity.HIGH
    assert len(new_case.notes) >= 1

    case_id = new_case.id

    # 2. Assign analyst
    assigned = await default_case_service.assign_analyst(case_id, "SOC-L2-ANALYST")
    assert assigned is not None
    assert assigned.assigned_analyst == "SOC-L2-ANALYST"
    assert assigned.status == InvestigationStatus.TRIAGING
    assert any("assigned to SOC-L2-ANALYST" in n.content for n in assigned.notes)

    # 3. Add analyst note
    note = await default_case_service.add_note(
        case_id,
        content="Analyzed domain scam-payments.xyz. Registered 2 hours ago on Namecheap.",
        author="SOC-L2-ANALYST",
        note_type=NoteType.ACTION,
    )
    assert note is not None
    assert note.note_type == NoteType.ACTION

    # 4. Update status to INVESTIGATING
    updated_status = await default_case_service.update_status(
        case_id,
        InvestigationStatus.INVESTIGATING,
        reason="Evidence corroborated with threat intel.",
        analyst="SOC-L2-ANALYST",
    )
    assert updated_status.status == InvestigationStatus.INVESTIGATING

    # 5. Escalate
    escalated = await default_case_service.escalate(
        case_id,
        reason="Detected lateral movement indicators.",
        escalate_to="TIER_3_INCIDENT_RESPONSE",
        analyst="SOC-L2-ANALYST",
    )
    assert escalated.priority == InvestigationPriority.P1_CRITICAL
    assert "ESCALATED" in escalated.tags

    # 6. Retrieve overview
    overview = await default_case_service.get_overview(case_id)
    assert overview is not None
    assert overview.investigation.id == case_id
    assert len(overview.latest_activity) >= 3

    # 7. Mark False Positive
    fp_case = await default_case_service.mark_false_positive(
        case_id,
        reason="Internal red-team exercise test email.",
        analyst="SOC-L2-ANALYST",
    )
    assert fp_case.status == InvestigationStatus.FALSE_POSITIVE
    assert fp_case.severity == InvestigationSeverity.CLEAN


def test_api_investigations_endpoints(client):
    # 1. List investigations
    res = client.get("/api/v1/investigations")
    assert res.status_code == 200
    data = res.json()
    assert "investigations" in data
    assert data["total"] >= 4
    assert any(i["id"] == "INV-2026-00001" for i in data["investigations"])

    # 2. Get specific investigation
    res = client.get("/api/v1/investigations/INV-2026-00001")
    assert res.status_code == 200
    case_data = res.json()
    assert case_data["id"] == "INV-2026-00001"
    assert case_data["severity"] == "CRITICAL"
    assert case_data["threat_score"] >= 80

    # 3. Get overview
    res = client.get("/api/v1/investigations/INV-2026-00001/overview")
    assert res.status_code == 200
    overview_data = res.json()
    assert "investigation" in overview_data
    assert "auth_summary" in overview_data
    assert "top_indicators" in overview_data
    assert "blockchain_summary" in overview_data

    # 4. Add note
    res = client.post(
        "/api/v1/investigations/INV-2026-00001/notes",
        json={"author": "SOC-L1-ANALYST", "content": "Manual header trace verified.", "note_type": "ACTION"},
    )
    assert res.status_code == 200
    note_data = res.json()
    assert note_data["content"] == "Manual header trace verified."

    # 5. Assign analyst
    res = client.post(
        "/api/v1/investigations/INV-2026-00001/assign",
        json={"analyst": "LEAD-FORENSIC-EXPERT"},
    )
    assert res.status_code == 200
    assert res.json()["assigned_analyst"] == "LEAD-FORENSIC-EXPERT"

    # 6. Update status
    res = client.post(
        "/api/v1/investigations/INV-2026-00001/status",
        json={"status": "INVESTIGATING", "reason": "Deep dive underway."},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "INVESTIGATING"

    # 7. Dashboard stats
    res = client.get("/api/v1/investigations/stats/dashboard")
    assert res.status_code == 200
    stats = res.json()
    assert stats["total_investigations"] >= 4
    assert stats["critical_cases"] >= 1
    assert "classification_breakdown" in stats
    assert "top_source_ips" in stats

    # 8. Report endpoint
    res = client.get("/api/v1/investigations/INV-2026-00001/report")
    assert res.status_code == 200
    report = res.json()
    assert "case" in report
    assert "forensic_summary" in report
    assert "threat_assessment" in report
    assert "timeline_events" in report
    assert "custody_chain" in report

    # 9. 404 for nonexistent investigation
    res = client.get("/api/v1/investigations/INV-NONEXISTENT")
    assert res.status_code == 404


def test_api_run_full_investigation(client):
    fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
    phishing_path = os.path.join(fixtures_dir, "sample_phishing.eml")

    if os.path.exists(phishing_path):
        with open(phishing_path, "rb") as f:
            files = {"file": ("sample_phishing.eml", f, "message/rfc822")}
            data = {"analyst": "SOC-AUTO-BOT"}
            res = client.post("/api/v1/investigations/run-full", files=files, data=data)

        assert res.status_code == 200
        result = res.json()
        assert "investigation" in result
        assert "steps_completed" in result
        assert len(result["steps_completed"]) >= 5
        assert result["investigation"]["risk_score"] > 70
        assert result["investigation"]["blockchain_status"] == "ANCHORED"
        assert result["verdict"]["integrity_verified"] is True
