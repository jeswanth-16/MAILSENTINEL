import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.services.case_management.models import (
    ActionStatus,
    ActionType,
    ArtifactType,
    CasePriority,
    CaseStatus,
    IncidentVerdict,
    NoteCategory,
)
from app.services.case_management.service import default_incident_case_service
from app.services.case_management.workflow import InvalidCaseStateTransitionError


@pytest.mark.anyio
async def test_case_management_service_unit():
    """Unit tests for IncidentCaseManagementService business logic and state machine."""
    service = default_incident_case_service
    await service.ensure_seeded()

    # 1. create_case_from_investigation & risk_score_is_inherited
    case = await service.create_case_from_investigation(
        investigation_id="INV-2026-00001",
        title="Unit Test Executive Impersonation Case",
        priority=CasePriority.P1_CRITICAL,
        assigned_analyst="SOC-LEAD-IR",
        tags=["TestTag1", "TestTag2"],
    )
    assert case.case_id.startswith("CASE-2026-")
    assert case.investigation_id == "INV-2026-00001"
    assert case.risk_score == 94  # inherited from INV-2026-00001
    assert case.severity == "CRITICAL"
    assert case.evidence_hash == "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"

    case_id = case.case_id

    # 2. get_case
    retrieved = await service.get_case(case_id)
    assert retrieved is not None
    assert retrieved.case_id == case_id

    # 3. artifact_reference_integrity
    assert len(retrieved.artifacts) > 0
    art_types = [a.artifact_type for a in retrieved.artifacts]
    assert ArtifactType.EMAIL in art_types
    assert ArtifactType.DOMAIN in art_types

    # 4. list_cases
    cases, total = await service.list_cases(status=case.status)
    assert total >= 1
    assert any(c.case_id == case_id for c in cases)

    # 5. update_case
    updated = await service.update_case(case_id, {"title": "Updated Title for Unit Test", "priority": CasePriority.P2_HIGH})
    assert updated.title == "Updated Title for Unit Test"
    assert updated.priority == CasePriority.P2_HIGH

    # 6. valid_status_transition (INVESTIGATING -> CONTAINMENT)
    await service.update_case(case_id, {"status": CaseStatus.INVESTIGATING})
    trans = await service.transition_status(case_id, CaseStatus.CONTAINMENT, reason="Isolating suspect domain.")
    assert trans.status == CaseStatus.CONTAINMENT

    # 7. invalid_status_transition (CONTAINMENT -> MONITORING without eradication/recovery)
    with pytest.raises(InvalidCaseStateTransitionError):
        await service.transition_status(case_id, CaseStatus.MONITORING, reason="Illegal jump.")

    # 8. assignment
    assigned = await service.assign_analyst(case_id, "SOC-NEW-ANALYST")
    assert assigned.assigned_analyst == "SOC-NEW-ANALYST"

    # 9. add_note & delete_note
    note = await service.add_note(case_id, content="Unit test note for case.", author="SOC Tester", category=NoteCategory.ANALYSIS)
    assert note.content == "Unit test note for case."
    assert note.category == NoteCategory.ANALYSIS
    case_after_note = await service.get_case(case_id)
    assert any(n.note_id == note.note_id for n in case_after_note.notes)

    del_res = await service.delete_note(case_id, note.note_id)
    assert del_res is True

    # 10. create_action & action_status_update
    action = await service.create_action(
        case_id=case_id,
        action_type=ActionType.BLOCK_DOMAIN,
        title="Block paypa1-security.com",
        description="Add to DNS sinkhole.",
        priority=CasePriority.P1_CRITICAL,
    )
    assert action.action_id.startswith("ACT-")
    assert action.status == ActionStatus.PROPOSED

    act_updated = await service.update_action_status(case_id, action.action_id, ActionStatus.APPROVED)
    assert act_updated.status == ActionStatus.APPROVED

    act_completed = await service.update_action_status(case_id, action.action_id, ActionStatus.COMPLETED, notes="Executed by DNS team.")
    assert act_completed.status == ActionStatus.COMPLETED
    assert act_completed.completed_at is not None

    # 11. closure_requires_reason
    with pytest.raises(ValueError):
        await service.close_case(case_id, verdict=IncidentVerdict.MALICIOUS, closure_reason="")

    # 12. case_closure
    closed_case = await service.close_case(
        case_id=case_id,
        verdict=IncidentVerdict.MALICIOUS,
        closure_reason="All containment actions completed and mailbox audit clean.",
        lessons_learned="Improve perimeter SPF reject rules.",
    )
    assert closed_case.status == CaseStatus.CLOSED
    assert closed_case.verdict == IncidentVerdict.MALICIOUS
    assert closed_case.closed_at is not None

    # 13. audit_event_generation
    audit_events = await service.get_audit_trail(case_id)
    assert len(audit_events) >= 5
    event_types = [e.event_type for e in audit_events]
    assert "CASE_CREATED" in event_types
    assert "CASE_CLOSED" in event_types

    # 14. blockchain_verification_reference
    verify_res = await service.verify_case_blockchain(case_id)
    assert verify_res["match"] is True
    assert verify_res["status"] == "VERIFIED"

    # 15. AI_assessment_reference
    ai_res = await service.refresh_case_ai(case_id)
    assert "threat_pattern" in ai_res
    assert "mitre_techniques" in ai_res

    # 16. Case Metrics
    metrics = await service.get_case_metrics()
    assert metrics.total_cases >= 3
    assert metrics.open_cases >= 1
    assert metrics.closed_cases >= 1


@pytest.mark.anyio
async def test_case_management_api_endpoints(auth_headers):
    """Integration test for Case Management REST API routes."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers=auth_headers) as client:
        # 1. List cases
        resp = await client.get("/api/v1/cases")
        assert resp.status_code == 200
        data = resp.json()
        assert "cases" in data
        assert data["total"] >= 1

        # 2. Get single case
        case_id = data["cases"][0]["case_id"]
        get_resp = await client.get(f"/api/v1/cases/{case_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["case_id"] == case_id

        # 3. Patch case
        patch_resp = await client.patch(
            f"/api/v1/cases/{case_id}",
            json={"priority": "P1_CRITICAL", "assigned_analyst": "SOC-LEAD-TEST"},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["assigned_analyst"] == "SOC-LEAD-TEST"

        # 4. Add & Delete note
        note_resp = await client.post(
            f"/api/v1/cases/{case_id}/notes",
            json={"content": "API test note content", "author": "API Tester", "category": "DECISION"},
        )
        assert note_resp.status_code in [200, 201]
        note_id = note_resp.json()["note_id"]

        del_note_resp = await client.delete(f"/api/v1/cases/{case_id}/notes/{note_id}")
        assert del_note_resp.status_code in [200, 204]

        # 5. Add & Remove tag
        tag_resp = await client.post(
            f"/api/v1/cases/{case_id}/tags",
            json={"tag": "API_TEST_TAG", "actor": "Tester"},
        )
        assert tag_resp.status_code == 200
        assert "API_TEST_TAG" in tag_resp.json()["tags"]

        del_tag_resp = await client.delete(f"/api/v1/cases/{case_id}/tags/API_TEST_TAG")
        assert del_tag_resp.status_code == 200
        assert "API_TEST_TAG" not in del_tag_resp.json()["tags"]

        # 6. Create and update Action
        act_resp = await client.post(
            f"/api/v1/cases/{case_id}/actions",
            json={
                "type": "CONTAIN",
                "title": "Network isolation test action",
                "description": "Testing action API endpoint.",
                "priority": "P2_HIGH",
            },
        )
        assert act_resp.status_code in [200, 201]
        action_id = act_resp.json()["action_id"]

        patch_act_resp = await client.patch(
            f"/api/v1/cases/{case_id}/actions/{action_id}",
            json={"status": "APPROVED", "actor": "SOC-LEAD"},
        )
        assert patch_act_resp.status_code == 200
        assert patch_act_resp.json()["status"] == "APPROVED"

        # 7. Audit log endpoint
        audit_resp = await client.get(f"/api/v1/cases/{case_id}/audit")
        assert audit_resp.status_code == 200
        assert isinstance(audit_resp.json(), list)

        # 8. Metrics endpoint
        metrics_resp = await client.get("/api/v1/cases/stats/metrics")
        assert metrics_resp.status_code == 200
        m = metrics_resp.json()
        assert "total_cases" in m
        assert "critical_cases" in m
