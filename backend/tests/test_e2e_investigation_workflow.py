import io
import os
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
PHISHING_EML_PATH = os.path.join(FIXTURES_DIR, "sample_phishing.eml")
CLEAN_EML_PATH = os.path.join(FIXTURES_DIR, "valid_clean.eml")


@pytest.mark.anyio
async def test_end_to_end_phishing_investigation_workflow(auth_headers):
    """
    End-to-End Test for the full SOC triage pipeline using sample_phishing.eml.
    Verifies:
    Upload -> Forensics -> Threat Scoring -> Intel -> Timeline -> Graph -> AI Analyst -> Blockchain -> Custody -> Notes
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers=auth_headers) as client:
        with open(PHISHING_EML_PATH, "rb") as f:
            eml_bytes = f.read()

        # Step 1: Execute 1-click full automated triage pipeline
        files = {"file": ("sample_phishing.eml", eml_bytes, "message/rfc822")}
        data = {"analyst": "SOC-LEAD-ANALYST"}
        resp = await client.post("/api/v1/investigations/run-full", files=files, data=data)
        assert resp.status_code == 200, f"run-full failed: {resp.text}"
        res = resp.json()

        inv = res["investigation"]
        inv_id = inv["id"]
        evidence_id = inv["evidence_id"]
        evidence_hash = inv["evidence_hash"]

        assert inv_id.startswith("INV-2026-")
        assert len(evidence_hash) == 64
        assert inv["risk_score"] >= 75
        assert inv["severity"] in ["CRITICAL", "HIGH"]
        assert len(res["steps_completed"]) >= 8

        # Step 2: Query Unified Investigation Overview
        overview_resp = await client.get(f"/api/v1/investigations/{inv_id}/overview")
        assert overview_resp.status_code == 200
        overview = overview_resp.json()
        assert overview["investigation"]["id"] == inv_id
        assert overview["investigation"]["risk_score"] == inv["risk_score"]
        assert len(overview["top_indicators"]) > 0
        assert overview["auth_summary"]["spf"] == "FAIL"

        # Step 3: Query Forensic Timeline
        timeline_resp = await client.get(f"/api/v1/investigations/{inv_id}/timeline")
        assert timeline_resp.status_code == 200
        timeline = timeline_resp.json()
        assert len(timeline["events"]) > 0

        # Step 4: Query Attack Graph
        graph_resp = await client.get(f"/api/v1/investigations/{inv_id}/graph")
        assert graph_resp.status_code == 200
        graph = graph_resp.json()
        assert len(graph["nodes"]) > 0
        assert len(graph["edges"]) > 0

        # Step 5: Query AI SOC Analyst Assessment
        ai_resp = await client.get(f"/api/v1/ai/assessment/{inv_id}")
        assert ai_resp.status_code == 200
        ai = ai_resp.json()
        assert ai["investigation_id"] == inv_id
        assert ai["ai_confidence_percentage"] >= 70
        assert len(ai["mitre_techniques"]) > 0
        assert len(ai["attack_narrative"]) > 0
        assert len(ai["recommended_actions"]) > 0

        # Step 6: Verify Blockchain Cryptographic Integrity
        verify_resp = await client.post(f"/api/v1/blockchain/verify/{evidence_id}")
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()
        assert verify_data["match"] is True
        assert verify_data["status"] == "VERIFIED"

        # Step 7: Simulate Evidence Modification & Confirm Tamper Detection
        tamper_resp = await client.post(f"/api/v1/blockchain/tamper-simulate/{evidence_id}")
        assert tamper_resp.status_code == 200
        tamper_verify = await client.post(f"/api/v1/blockchain/verify/{evidence_id}")
        assert tamper_verify.status_code == 200
        assert tamper_verify.json()["match"] is False
        assert tamper_verify.json()["status"] == "TAMPERED"

        # Step 8: Restore Authentic Evidence & Re-Verify
        reset_resp = await client.post(f"/api/v1/blockchain/tamper-reset/{evidence_id}")
        assert reset_resp.status_code == 200
        reverify_resp = await client.post(f"/api/v1/blockchain/verify/{evidence_id}")
        assert reverify_resp.status_code == 200
        assert reverify_resp.json()["match"] is True
        assert reverify_resp.json()["status"] == "VERIFIED"

        # Step 9: Add Analyst Note & Delete Note
        note_resp = await client.post(
            f"/api/v1/investigations/{inv_id}/notes",
            json={"content": "E2E verification note by SOC Lead", "author": "SOC-LEAD", "note_type": "NOTE"},
        )
        assert note_resp.status_code == 200
        note_data = note_resp.json()
        note_id = note_data["note_id"]

        del_resp = await client.delete(f"/api/v1/investigations/{inv_id}/notes/{note_id}")
        assert del_resp.status_code == 204

        # Step 10: Query Full Investigation Dossier Report
        report_resp = await client.get(f"/api/v1/investigations/{inv_id}/report")
        assert report_resp.status_code == 200
        report = report_resp.json()
        assert report["case"]["id"] == inv_id
        assert report["case"]["evidence_id"] == evidence_id


@pytest.mark.anyio
async def test_end_to_end_clean_email_workflow(auth_headers):
    """
    End-to-End Test for benign corporate email triage using valid_clean.eml.
    Verifies:
    Low Risk Score -> Passing SPF/DKIM/DMARC -> Benign Classification -> Blockchain Anchored
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers=auth_headers) as client:
        with open(CLEAN_EML_PATH, "rb") as f:
            eml_bytes = f.read()

        files = {"file": ("valid_clean.eml", eml_bytes, "message/rfc822")}
        resp = await client.post("/api/v1/investigations/run-full", files=files)
        assert resp.status_code == 200
        res = resp.json()
        inv = res["investigation"]

        assert inv["risk_score"] < 25
        assert inv["severity"] in ["CLEAN", "LOW"]
        assert inv["classification"] == "BENIGN"
        assert inv["blockchain_verified"] is True
