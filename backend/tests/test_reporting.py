import json
import io
import zipfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.case_management import default_case_repository
from app.services.reporting import (
    ForensicReportingService,
    ReportType,
    ReportStatus,
    default_reporting_service,
)


@pytest.fixture
def reporting_service():
    return ForensicReportingService(default_case_repository)


def test_generate_executive_report(reporting_service):
    report = reporting_service.generate_report(
        case_id="CASE-2026-00001",
        report_type=ReportType.EXECUTIVE,
        generated_by="SOC Executive Lead",
    )
    assert report.metadata.report_type == ReportType.EXECUTIVE
    assert report.metadata.case_id == "CASE-2026-00001"
    assert "incident_title" in report.executive_summary
    assert report.metadata.risk_score >= 0


def test_generate_full_report(reporting_service):
    report = reporting_service.generate_report(
        case_id="CASE-2026-00001",
        report_type=ReportType.FULL_INVESTIGATION,
        generated_by="Lead Forensics Specialist",
    )
    assert report.metadata.report_type == ReportType.FULL_INVESTIGATION
    assert len(report.findings) > 0
    assert len(report.evidence_references) > 0
    assert len(report.recommendations) > 0
    assert report.metadata.report_sha256 is not None


def test_report_contains_case_metadata(reporting_service):
    report = reporting_service.generate_report("CASE-2026-00001")
    assert report.metadata.case_id == "CASE-2026-00001"
    assert report.case_info["case_id"] == "CASE-2026-00001"
    assert report.case_info["status"] in ["NEW", "TRIAGING", "INVESTIGATING", "CONTAINMENT", "ERADICATION", "RECOVERY", "MONITORING", "RESOLVED", "CLOSED"]
    assert report.metadata.severity is not None


def test_report_contains_forensic_evidence(reporting_service):
    report = reporting_service.generate_report("CASE-2026-00001")
    assert len(report.evidence_references) >= 1
    ev0 = report.evidence_references[0]
    assert ev0.reference_id == "EV-001"
    assert ev0.evidence_type == "EMAIL_EML"
    assert ev0.sha256 is not None


def test_report_contains_threat_findings(reporting_service):
    report = reporting_service.generate_report("CASE-2026-00001")
    assert len(report.findings) > 0
    f0 = report.findings[0]
    assert f0.finding_id.startswith("F-")
    assert f0.severity is not None
    assert f0.evidence_reference.startswith("EV-")
    assert len(f0.impact) > 0
    assert len(f0.recommendation) > 0


def test_report_contains_timeline(reporting_service):
    report = reporting_service.generate_report("CASE-2026-00001")
    assert isinstance(report.attack_timeline, list)
    if report.attack_timeline:
        evt = report.attack_timeline[0]
        assert "timestamp" in evt
        assert "title" in evt


def test_report_contains_blockchain_reference(reporting_service):
    report = reporting_service.generate_report("CASE-2026-00001")
    assert "blockchain_integrity" in report.model_dump()
    b_info = report.blockchain_integrity
    assert "tx_hash" in b_info
    assert "block_number" in b_info
    assert b_info["evidence_hash"] == report.metadata.evidence_sha256


def test_deterministic_json_export(reporting_service):
    report = reporting_service.generate_report("CASE-2026-00001")
    json_str_1 = reporting_service.get_report_json("CASE-2026-00001")
    json_str_2 = reporting_service.get_report_json("CASE-2026-00001")
    assert json_str_1 == json_str_2
    parsed = json.loads(json_str_1)
    assert parsed["metadata"]["case_id"] == "CASE-2026-00001"


def test_pdf_generation(reporting_service):
    pdf_bytes = reporting_service.get_report_pdf("CASE-2026-00001")
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")


def test_csv_ioc_export(reporting_service):
    csv_content = reporting_service.get_iocs_csv("CASE-2026-00001")
    assert "type,value,source,severity,confidence,evidence_reference" in csv_content
    lines = csv_content.strip().split("\n")
    assert len(lines) >= 2


def test_csv_timeline_export(reporting_service):
    csv_content = reporting_service.get_timeline_csv("CASE-2026-00001")
    assert "timestamp,event_type,severity,title,source,entity_type,entity_id" in csv_content


def test_findings_export(reporting_service):
    csv_content = reporting_service.get_findings_csv("CASE-2026-00001")
    assert "finding_id,title,severity,category,description,evidence_reference,confidence,impact,recommendation" in csv_content
    assert "F-001" in csv_content


def test_manifest_generation(reporting_service):
    manifest = reporting_service.get_manifest("CASE-2026-00001")
    assert manifest is not None
    assert manifest.case_id == "CASE-2026-00001"
    assert "report.pdf" in manifest.files
    assert "report.json" in manifest.files
    assert "iocs.csv" in manifest.files
    assert "manifest.json" not in manifest.files
    assert len(manifest.file_sha256) >= 5


def test_artifact_sha256_generation(reporting_service):
    zip_bytes, manifest = reporting_service.build_evidence_package("CASE-2026-00001")
    assert len(zip_bytes) > 0
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        namelist = zf.namelist()
        assert "report.pdf" in namelist
        assert "report.json" in namelist
        assert "manifest.json" in namelist


def test_report_integrity_verification(reporting_service):
    report = reporting_service.generate_report("CASE-2026-00001")
    res = reporting_service.verify_report_integrity(report.metadata.report_id)
    assert res.verified is True
    assert res.tamper_detected is False
    assert res.status == ReportStatus.VERIFIED


def test_tamper_detection(reporting_service):
    report = reporting_service.generate_report("CASE-2026-00001")
    res = reporting_service.verify_report_integrity(
        report.metadata.report_id,
        expected_hash="tampered_fake_hash_00000000000000000000000000000000000000000000",
    )
    assert res.verified is False
    assert res.tamper_detected is True
    assert res.status == ReportStatus.TAMPER_DETECTED


def test_missing_evidence_handling(reporting_service):
    # Test on a case with minimal/missing fields
    report = reporting_service.generate_report("CASE-2026-00004")
    assert report.metadata.case_id == "CASE-2026-00004"
    assert len(report.findings) >= 1
    assert len(report.evidence_references) >= 1


def test_invalid_case_handling(reporting_service):
    with pytest.raises(ValueError):
        reporting_service.generate_report("CASE-NONEXISTENT-999")


def test_no_secret_leakage(reporting_service):
    json_export = reporting_service.get_report_json("CASE-2026-00001")
    assert "PRIVATE_KEY" not in json_export.upper()
    assert "API_KEY" not in json_export.upper()
    assert "DATABASE_PASSWORD" not in json_export.upper()
    assert "SECRET_KEY" not in json_export.upper()


def test_evidence_hash_preserved(reporting_service):
    report = reporting_service.generate_report("CASE-2026-00001")
    case = default_case_repository.get_case("CASE-2026-00001")
    expected_hash = case.artifacts[0].sha256 if case.artifacts else "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert report.metadata.evidence_sha256 == expected_hash


def test_api_reporting_endpoints(client):
    # 1. Generate Report
    res = client.post(
        "/api/v1/reports/generate/CASE-2026-00001",
        json={"report_type": "FULL_INVESTIGATION", "generated_by": "Test Analyst"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["metadata"]["case_id"] == "CASE-2026-00001"

    # 2. Get Report
    res = client.get("/api/v1/reports/CASE-2026-00001")
    assert res.status_code == 200

    # 3. Get JSON Export
    res = client.get("/api/v1/reports/CASE-2026-00001/json")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/json"

    # 4. Get PDF
    res = client.get("/api/v1/reports/CASE-2026-00001/pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF")

    # 5. Get CSVs
    res = client.get("/api/v1/reports/CASE-2026-00001/iocs.csv")
    assert res.status_code == 200
    res = client.get("/api/v1/reports/CASE-2026-00001/timeline.csv")
    assert res.status_code == 200
    res = client.get("/api/v1/reports/CASE-2026-00001/findings.csv")
    assert res.status_code == 200

    # 6. Build Package
    res = client.post("/api/v1/reports/CASE-2026-00001/package")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/zip"

    # 7. Get Manifest
    res = client.get("/api/v1/reports/CASE-2026-00001/manifest")
    assert res.status_code == 200
    assert "package_id" in res.json()

    # 8. Verify Report
    res = client.post("/api/v1/reports/CASE-2026-00001/verify")
    assert res.status_code == 200
    assert res.json()["verified"] is True
