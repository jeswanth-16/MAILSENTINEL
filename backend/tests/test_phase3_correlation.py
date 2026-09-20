import asyncio
import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.email import analyze_email_bytes
from app.services.forensics.graph import build_attack_graph
from app.services.forensics.models import GraphEdgeType, GraphNodeType
from app.services.intelligence import (
    EmailRole,
    LookupStatus,
    ReputationStatus,
    default_intelligence_service,
)
from app.services.intelligence.correlation import (
    correlate_investigation_indicators,
    IndicatorCorrelationResult,
)
from app.services.intelligence.providers.domain_provider import (
    extract_registrable_domain,
)
from app.services.intelligence.providers.email_provider import (
    default_email_provider,
    parse_and_normalize_email,
    DISPOSABLE_DOMAINS,
)
from app.services.risk import CATEGORY_WEIGHT_CAPS, assess_email_threat
from app.services.threat.models import ThreatCategory, ThreatSeverityLevel


@pytest.fixture
def client():
    return TestClient(app)


def get_auth_headers(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@mailsentinel.local", "password": "Admin@12345!"},
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# 1. DOMAIN INTELLIGENCE TESTS
def test_domain_registrable_domain_extraction():
    assert extract_registrable_domain("auth.paypa1-security.com") == "paypa1-security.com"
    assert extract_registrable_domain("sub.domain.co.uk") == "domain.co.uk"
    assert extract_registrable_domain("mail.google.com") == "google.com"
    assert extract_registrable_domain("localhost") == "localhost"
    assert extract_registrable_domain("server.lan") == "server.lan"


def test_domain_localhost_and_internal_isolation():
    # Localhost
    res_local = asyncio.run(default_intelligence_service.get_domain_intelligence("localhost"))
    assert res_local.is_localhost is True
    assert res_local.attribution == "LOCAL ANALYSIS"
    assert res_local.status == LookupStatus.SUCCESS

    # Internal TLD (.local, .lan, .corp)
    res_lan = asyncio.run(default_intelligence_service.get_domain_intelligence("workstation.local"))
    assert res_lan.is_internal is True
    assert res_lan.attribution == "LOCAL ANALYSIS"

    # External Domain with attribution
    res_ext = asyncio.run(default_intelligence_service.get_domain_intelligence("paypa1-security.com"))
    assert res_ext.registrable_domain == "paypa1-security.com"
    assert res_ext.is_lookalike is True
    assert res_ext.attribution in ("LOCAL ANALYSIS", "OFFLINE FALLBACK", "CACHED")


# 2. URL INTELLIGENCE TESTS
def test_url_safe_decomposition_and_ip_host():
    # Raw IP URL
    res_ip = asyncio.run(default_intelligence_service.get_url_intelligence("http://185.220.101.5:8080/auth/login.php?user=test"))
    assert res_ip.is_ip_host is True
    assert res_ip.host_ip == "185.220.101.5"
    assert res_ip.port == 8080
    assert res_ip.has_query is True
    assert res_ip.has_credential_keywords is True
    assert res_ip.attribution in ("LOCAL ANALYSIS", "OFFLINE FALLBACK", "CACHED")

    # Domain URL without IP host
    res_dom = asyncio.run(default_intelligence_service.get_url_intelligence("https://auth.paypa1-security.com/portal"))
    assert res_dom.is_ip_host is False
    assert res_dom.hostname == "auth.paypa1-security.com"
    assert res_dom.has_query is False


# 3. EMAIL ADDRESS INTELLIGENCE TESTS
def test_email_rfc5322_normalization():
    norm, local, dom, valid = parse_and_normalize_email("Security Desk <SUPPORT@paypa1-security.com>")
    assert norm == "support@paypa1-security.com"
    assert local == "support"
    assert dom == "paypa1-security.com"
    assert valid is True

    # Invalid email syntax
    _, _, _, valid_bad = parse_and_normalize_email("invalid-address-without-at")
    assert valid_bad is False


def test_email_disposable_and_free_provider():
    # Disposable email
    res_disp = asyncio.run(default_email_provider.lookup_email("attacker@mailinator.com", role=EmailRole.SENDER))
    assert res_disp.is_disposable is True
    assert res_disp.is_free_provider is False
    assert res_disp.reputation in (ReputationStatus.SUSPICIOUS, ReputationStatus.KNOWN_MALICIOUS)

    # Free consumer provider
    res_free = asyncio.run(default_email_provider.lookup_email("ceo.executive@gmail.com", role=EmailRole.SENDER))
    assert res_free.is_disposable is False
    assert res_free.is_free_provider is True

    # High-risk lookalike brand domain
    res_phish = asyncio.run(default_email_provider.lookup_email("billing@paypa1-security.com", role=EmailRole.SENDER))
    assert res_phish.is_lookalike_domain is True
    assert res_phish.reputation in (ReputationStatus.KNOWN_MALICIOUS, ReputationStatus.SUSPICIOUS)


# 4. CORRELATION ENGINE TESTS
def test_correlate_investigation_relationships_and_signals():
    # Create synthetic EML with sender/reply-to mismatch, direct IP URL, and lookalike domain
    raw_eml = (
        b"From: CEO John <john@legitimate-company.com>\r\n"
        b"Reply-To: Collector <payouts@mailinator.com>\r\n"
        b"To: finance@legitimate-company.com\r\n"
        b"Subject: Urgent Wire Transfer\r\n"
        b"Date: Mon, 19 Sep 2026 10:00:00 +0000\r\n"
        b"Received: from [185.220.101.5] (relay.attacker.net [185.220.101.5]) by mx.legitimate-company.com; Mon, 19 Sep 2026 10:01:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please review the pending invoice immediately: http://185.220.101.5/invoice.pdf\r\n"
    )
    forensic = analyze_email_bytes(raw_eml, original_filename="test_corr.eml")
    forensic.investigation_id = "INV-TEST-CORR-01"

    intel = asyncio.run(
        default_intelligence_service.enrich_investigation(
            investigation_id=forensic.investigation_id,
            ips=[hop.ip for hop in forensic.received_chain if hop.ip],
            domains=[d.domain for d in forensic.domains],
            urls=[u.normalized_url for u in forensic.urls],
            emails=[forensic.metadata.from_address, forensic.metadata.reply_to],
        )
    )

    corr = asyncio.run(
        correlate_investigation_indicators(
            investigation_id=forensic.investigation_id,
            forensic=forensic,
            intelligence=intel,
        )
    )

    assert isinstance(corr, IndicatorCorrelationResult)
    assert corr.summary.total_relationships > 0
    assert corr.summary.total_signals >= 2

    # Check relationships
    rel_types = {r.relationship for r in corr.relationships}
    assert "BELONGS_TO_DOMAIN" in rel_types
    assert "HOSTED_ON" in rel_types
    assert "RECEIVED_FROM" in rel_types

    # Check threat signals
    sig_ids = {s.signal_id for s in corr.signals}
    assert "CORR_SENDER_REPLYTO_MISMATCH" in sig_ids
    assert "CORR_URL_IP_HOSTNAME" in sig_ids
    assert "CORR_DISPOSABLE_EMAIL_SENDER" in sig_ids


# 5. THREAT ENGINE CORRELATION CATEGORY & CAPPING
def test_threat_assessment_correlation_weight_cap():
    raw_eml = (
        b"From: CEO John <john@legitimate-company.com>\r\n"
        b"Reply-To: Collector <payouts@mailinator.com>\r\n"
        b"To: finance@legitimate-company.com\r\n"
        b"Subject: Urgent Wire\r\n"
        b"Date: Mon, 19 Sep 2026 10:00:00 +0000\r\n"
        b"Received: from [185.220.101.5] by mx.test.com; Mon, 19 Sep 2026 10:01:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Urgent payment link: http://185.220.101.5/auth\r\n"
    )
    forensic = analyze_email_bytes(raw_eml, original_filename="test_cap.eml")
    forensic.investigation_id = "INV-TEST-CAP-01"

    intel = asyncio.run(
        default_intelligence_service.enrich_investigation(
            investigation_id=forensic.investigation_id,
            ips=[hop.ip for hop in forensic.received_chain if hop.ip],
            domains=[d.domain for d in forensic.domains],
            urls=[u.normalized_url for u in forensic.urls],
            emails=[forensic.metadata.from_address, forensic.metadata.reply_to],
        )
    )
    corr = asyncio.run(
        default_intelligence_service.correlate_investigation(
            forensic.investigation_id, forensic, intel
        )
    )

    assessment = asyncio.run(assess_email_threat(forensic, correlation=corr))

    # Check correlation category cap
    corr_breakdown = next(
        (b for b in assessment.category_breakdown if b.category == ThreatCategory.CORRELATION),
        None,
    )
    assert corr_breakdown is not None
    assert corr_breakdown.capped_points <= CATEGORY_WEIGHT_CAPS[ThreatCategory.CORRELATION]
    assert corr_breakdown.capped_points <= 15.0


# 6. ATTACK GRAPH EXTENDED EDGES
def test_attack_graph_extended_edges():
    raw_eml = (
        b"From: support@legitimate-company.com\r\n"
        b"Reply-To: hacker@external-destination.com\r\n"
        b"To: victim@legitimate-company.com\r\n"
        b"Subject: Reset your password\r\n"
        b"Date: Mon, 19 Sep 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Click here: https://external-destination.com/login\r\n"
    )
    forensic = analyze_email_bytes(raw_eml, original_filename="graph_ext.eml")
    forensic.investigation_id = "INV-TEST-GRAPH-01"

    intel = asyncio.run(
        default_intelligence_service.enrich_investigation(
            investigation_id=forensic.investigation_id,
            ips=[],
            domains=["external-destination.com"],
            urls=["https://external-destination.com/login"],
        )
    )
    corr = asyncio.run(
        default_intelligence_service.correlate_investigation(
            forensic.investigation_id, forensic, intel
        )
    )
    graph = build_attack_graph(forensic, intelligence=intel, correlation=corr)

    edge_types = {e.type for e in graph.edges}
    assert GraphEdgeType.REPLY_TO in edge_types
    assert GraphEdgeType.HOSTED_ON in edge_types


# 7. API ENDPOINTS
def test_api_email_intelligence_endpoint(client):
    headers = get_auth_headers(client)

    # 1. Valid lookup
    resp = client.post(
        "/api/v1/intelligence/email",
        headers=headers,
        json={"email": "attacker@mailinator.com", "role": "SENDER"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["normalized_address"] == "attacker@mailinator.com"
    assert data["domain"] == "mailinator.com"
    assert data["is_disposable"] is True
    assert data["role"] == "SENDER"

    # 2. Empty email rejected
    resp_bad = client.post("/api/v1/intelligence/email", headers=headers, json={"email": ""})
    assert resp_bad.status_code == 400


def test_api_correlation_endpoints(client):
    headers = get_auth_headers(client)

    # 1. Ad-hoc correlation endpoint
    resp_adhoc = client.post(
        "/api/v1/intelligence/correlate",
        headers=headers,
        json={
            "emails": ["ceo@company.com", "phisher@mailinator.com"],
            "urls": ["http://198.51.100.1/invoice"],
            "domains": ["company.com", "mailinator.com"],
            "ips": ["198.51.100.1"],
        },
    )
    assert resp_adhoc.status_code == 200
    adhoc_data = resp_adhoc.json()
    assert adhoc_data["summary"]["total_indicators"] > 0
    assert adhoc_data["summary"]["total_relationships"] > 0
    assert len(adhoc_data["signals"]) > 0

    # 2. Investigation correlation endpoint (for seeded INV-2026-00001)
    resp_inv = client.get(
        "/api/v1/intelligence/investigation/INV-2026-00001/correlation",
        headers=headers,
    )
    assert resp_inv.status_code == 200
    inv_data = resp_inv.json()
    assert inv_data["investigation_id"] == "INV-2026-00001"
    assert "summary" in inv_data
    assert "relationships" in inv_data

    # 3. 404 on non-existent investigation
    resp_404 = client.get(
        "/api/v1/intelligence/investigation/INV-DOES-NOT-EXIST/correlation",
        headers=headers,
    )
    assert resp_404.status_code == 404


def test_zero_api_key_leakage_in_intelligence():
    # Verify no raw API keys are present in models or responses
    res = asyncio.run(default_intelligence_service.get_ip_intelligence("8.8.8.8"))
    serialized = res.model_dump_json() if hasattr(res, "model_dump_json") else str(res)
    actual_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if actual_key and len(actual_key) > 5:
        assert actual_key not in serialized
