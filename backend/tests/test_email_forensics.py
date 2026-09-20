import io
import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.email import (
    AuthenticationVerdict,
    MalformedEmailError,
    OversizedFileError,
    analyze_email_bytes,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(filename: str) -> bytes:
    filepath = os.path.join(FIXTURES_DIR, filename)
    with open(filepath, "rb") as f:
        return f.read()


def test_sample_phishing_eml_forensics():
    """
    Tests complete forensic extraction on sample_phishing.eml fixture.
    """
    file_bytes = read_fixture("sample_phishing.eml")
    result = analyze_email_bytes(file_bytes, original_filename="sample_phishing.eml")

    # 1. Verification of Investigation & File Metadata
    assert result.investigation_id.startswith("INV-2026-")
    assert len(result.sha256_digest) == 64
    assert result.file_name == "sample_phishing.eml"
    assert result.file_size_bytes == len(file_bytes)

    # 2. Metadata Extraction
    assert "executive-desk@paypa1-security.com" in result.metadata.from_address
    assert len(result.metadata.to_addresses) == 1
    assert "cfo@target-corp.com" in result.metadata.to_addresses[0]
    assert "Acquisition Wire Authorization" in result.metadata.subject
    assert result.metadata.reply_to == "attacker-inbox-drop@evil-domain-proxy.ru"
    assert result.metadata.return_path == "<bounce-collector@paypa1-security.com>"

    # 3. Authentication Parsing
    assert result.authentication.spf == AuthenticationVerdict.FAIL
    assert result.authentication.dkim == AuthenticationVerdict.NONE
    assert result.authentication.dmarc == AuthenticationVerdict.FAIL

    # 4. Received Hop Chain & Order
    assert len(result.received_chain) == 2
    # Hop 1 is earliest origin relay
    hop1 = result.received_chain[0]
    assert hop1.hop == 1
    assert hop1.ip == "185.220.101.5"
    assert "amsterdam-node.net" in (hop1.from_host or "")
    
    # Hop 2 is receiving MTA
    hop2 = result.received_chain[1]
    assert hop2.hop == 2
    assert "mx.target-corp.com" in (hop2.by_host or "")

    # 5. IP Addresses
    ip_list = [item.ip for item in result.ip_addresses]
    assert "185.220.101.5" in ip_list
    assert "192.0.2.1" in ip_list

    # 6. URL & Domain Extraction
    urls = [u.normalized_url for u in result.urls]
    domains = [d.domain for d in result.domains]
    assert any("login.paypa1-security.com" in u for u in urls)
    assert any("185.220.101.5:8080" in u or "185.220.101.5" in u for u in urls)
    assert "login.paypa1-security.com" in domains or "paypa1-security.com" in domains

    # 7. Attachment Metadata & SHA-256
    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.filename == "Urgent_Invoice_Doc.pdf.html"
    assert att.extension == ".html"
    assert len(att.sha256) == 64
    assert att.size_bytes > 0

    # 8. Body Analysis
    assert result.body_analysis.has_html is True
    assert result.body_analysis.character_count > 0
    assert result.body_analysis.word_count > 0
    assert result.body_analysis.link_count >= 2
    assert result.body_analysis.attachment_count == 1
    assert "emergency wire instructions" in result.body_analysis.normalized_text_preview

    # 9. Forensic Consistency Warnings
    assert len(result.warnings) > 0
    assert any("Reply-To mismatch" in w for w in result.warnings)
    assert any("SPF Authentication" in w for w in result.warnings)


def test_clean_valid_eml_forensics():
    """
    Tests clean email extraction with passing SPF/DKIM/DMARC.
    """
    file_bytes = read_fixture("valid_clean.eml")
    result = analyze_email_bytes(file_bytes, original_filename="valid_clean.eml")

    assert "Partner Service Notifications" in result.metadata.from_address
    assert "notifications@partner-service.com" in result.metadata.from_address
    assert result.authentication.spf == AuthenticationVerdict.PASS
    assert result.authentication.dkim == AuthenticationVerdict.PASS
    assert result.authentication.dmarc == AuthenticationVerdict.PASS
    assert len(result.attachments) == 0
    assert result.body_analysis.has_plain_text is True
    assert len(result.urls) == 1
    assert "app.partner-service.com" in result.urls[0].domain


def test_malformed_empty_email():
    """
    Tests error handling for empty or corrupted inputs.
    """
    with pytest.raises(MalformedEmailError):
        analyze_email_bytes(b"")


def test_oversized_file_error():
    """
    Tests error handling for files exceeding size limit.
    """
    oversized = b"A" * (26 * 1024 * 1024)
    with pytest.raises(OversizedFileError):
        analyze_email_bytes(oversized)


def test_api_endpoint_success(client):
    """
    Tests POST /api/v1/analysis/email endpoint returns structured 200 response.
    """
    file_bytes = read_fixture("sample_phishing.eml")
    response = client.post(
        "/api/v1/analysis/email",
        files={"file": ("sample_phishing.eml", io.BytesIO(file_bytes), "message/rfc822")}
    )

    assert response.status_code == 200
    data = response.json()
    assert "investigation_id" in data
    assert "sha256_digest" in data
    assert data["metadata"]["subject"] == "URGENT: Outstanding Acquisition Wire Authorization Required"
    assert data["authentication"]["spf"] == "FAIL"
    assert len(data["received_chain"]) == 2
    assert len(data["attachments"]) == 1


def test_api_endpoint_unsupported_format(client):
    """
    Tests POST /api/v1/analysis/email with invalid file format returns 422.
    """
    response = client.post(
        "/api/v1/analysis/email",
        files={"file": ("executable.exe", io.BytesIO(b"MZ123"), "application/x-msdownload")}
    )
    assert response.status_code == 422
    assert "Unsupported file format" in response.json()["detail"]


def test_api_endpoint_empty_file(client):
    """
    Tests POST /api/v1/analysis/email with empty file returns 400.
    """
    response = client.post(
        "/api/v1/analysis/email",
        files={"file": ("empty.eml", io.BytesIO(b""), "message/rfc822")}
    )
    assert response.status_code == 400

