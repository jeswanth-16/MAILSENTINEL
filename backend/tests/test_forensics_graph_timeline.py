import asyncio
import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.email import analyze_email_bytes
from app.services.forensics.graph import build_attack_graph

from app.services.forensics.models import (
    GraphEdgeType,
    GraphNodeType,
    TimelineEventType,
    TimestampPrecision,
)
from app.services.forensics.timeline import build_forensic_timeline
from app.services.intelligence.service import default_intelligence_service
from app.services.risk import assess_email_threat


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(filename: str) -> bytes:
    filepath = os.path.join(FIXTURES_DIR, filename)
    with open(filepath, "rb") as f:
        return f.read()


def test_timeline_generation_phishing_eml():
    phish_bytes = read_fixture("sample_phishing.eml")
    forensic = analyze_email_bytes(phish_bytes, original_filename="sample_phishing.eml")
    threat = asyncio.run(assess_email_threat(forensic))
    intel = asyncio.run(
        default_intelligence_service.enrich_investigation(
            investigation_id=forensic.investigation_id,
            ips=[hop.ip for hop in forensic.received_chain if hop.ip],
            domains=[d.domain for d in forensic.domains],
            urls=[u.normalized_url for u in forensic.urls],
        )
    )

    events = build_forensic_timeline(forensic, threat, intel)
    assert len(events) >= 8

    # 1. First event is evidence hashing
    assert events[0].event_type == TimelineEventType.EVIDENCE_HASHED
    assert events[0].timestamp_precision == TimestampPrecision.SECOND

    # 2. Check Received Relay ordering
    relay_events = [e for e in events if e.event_type == TimelineEventType.SMTP_RELAY]
    assert len(relay_events) == 2
    assert relay_events[0].metadata["hop_number"] == 1
    assert "185.220.101.5" in relay_events[0].description
    assert relay_events[1].metadata["hop_number"] == 2

    # 3. Check Authentication evaluation
    auth_events = [e for e in events if e.event_type == TimelineEventType.AUTHENTICATION_CHECK]
    assert len(auth_events) == 1
    assert auth_events[0].severity in ("HIGH", "CRITICAL")

    # 4. Check Extracted URLs & Domains (no fake timestamps!)
    url_events = [e for e in events if e.event_type == TimelineEventType.URL_DISCOVERED]
    assert len(url_events) >= 1
    assert url_events[0].timestamp is None
    assert url_events[0].timestamp_precision == TimestampPrecision.UNKNOWN

    # 5. Check Threat Indicators & Risk Assessment
    ind_events = [e for e in events if e.event_type == TimelineEventType.THREAT_INDICATOR]
    assert len(ind_events) >= 3

    risk_events = [e for e in events if e.event_type == TimelineEventType.RISK_ASSESSMENT]
    assert len(risk_events) == 1
    assert risk_events[0].severity == "CRITICAL"


def test_timeline_clean_email():
    clean_bytes = read_fixture("valid_clean.eml")
    forensic = analyze_email_bytes(clean_bytes, original_filename="valid_clean.eml")
    threat = asyncio.run(assess_email_threat(forensic))

    events = build_forensic_timeline(forensic, threat, None)
    assert len(events) >= 4

    # Authentication passes
    auth_events = [e for e in events if e.event_type == TimelineEventType.AUTHENTICATION_CHECK]
    assert len(auth_events) == 1
    assert auth_events[0].severity == "CLEAN"

    # No critical threat indicators
    crit_ind_events = [
        e for e in events if e.event_type == TimelineEventType.THREAT_INDICATOR and e.severity == "CRITICAL"
    ]
    assert len(crit_ind_events) == 0


def test_attack_graph_construction_phishing():
    phish_bytes = read_fixture("sample_phishing.eml")
    forensic = analyze_email_bytes(phish_bytes, original_filename="sample_phishing.eml")
    threat = asyncio.run(assess_email_threat(forensic))
    intel = asyncio.run(
        default_intelligence_service.enrich_investigation(
            investigation_id=forensic.investigation_id,
            ips=[hop.ip for hop in forensic.received_chain if hop.ip],
            domains=[d.domain for d in forensic.domains],
            urls=[u.normalized_url for u in forensic.urls],
        )
    )

    graph = build_attack_graph(forensic, threat, intel)

    # 1. Node type coverage
    node_types = {n.type for n in graph.nodes}
    assert GraphNodeType.INVESTIGATION in node_types
    assert GraphNodeType.EMAIL in node_types
    assert GraphNodeType.IP in node_types
    assert GraphNodeType.DOMAIN in node_types
    assert GraphNodeType.URL in node_types
    assert GraphNodeType.ATTACHMENT in node_types
    assert GraphNodeType.THREAT_INDICATOR in node_types

    # 2. Node deduplication check
    node_ids = [n.id for n in graph.nodes]
    assert len(node_ids) == len(set(node_ids))

    # 3. Edge types & confidence
    edge_types = {e.type for e in graph.edges}
    assert GraphEdgeType.OBSERVED_IN in edge_types
    assert (GraphEdgeType.SENT_FROM in edge_types) or (GraphEdgeType.RELAYED_THROUGH in edge_types)
    assert GraphEdgeType.CONTAINS_URL in edge_types
    assert GraphEdgeType.CONTAINS_ATTACHMENT in edge_types
    assert GraphEdgeType.TRIGGERS in edge_types

    for edge in graph.edges:
        assert 0.0 <= edge.confidence <= 1.0


def test_api_timeline_endpoints(client):
    # 1. Get timeline for seeded INV-2026-00001
    resp = client.get("/api/v1/investigations/INV-2026-00001/timeline")
    assert resp.status_code == 200
    data = resp.json()
    assert data["investigation_id"] == "INV-2026-00001"
    assert data["total_events"] > 0
    assert len(data["events"]) == data["total_events"]

    # 2. Test sort=desc
    resp_desc = client.get("/api/v1/investigations/INV-2026-00001/timeline?sort=desc")
    assert resp_desc.status_code == 200

    # 3. Test filter by severity
    resp_crit = client.get("/api/v1/investigations/INV-2026-00001/timeline?severity=CRITICAL")
    assert resp_crit.status_code == 200
    crit_data = resp_crit.json()
    assert all(e["severity"] == "CRITICAL" for e in crit_data["events"])

    # 4. Non-existent investigation
    resp_404 = client.get("/api/v1/investigations/INV-NON-EXISTENT/timeline")
    assert resp_404.status_code == 404


def test_api_graph_endpoints(client):
    # 1. Get graph for seeded INV-2026-00001
    resp = client.get("/api/v1/investigations/INV-2026-00001/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert data["investigation_id"] == "INV-2026-00001"
    assert data["total_nodes"] > 0
    assert data["total_edges"] > 0

    # 2. Non-existent graph
    resp_404 = client.get("/api/v1/investigations/INV-NON-EXISTENT/graph")
    assert resp_404.status_code == 404
