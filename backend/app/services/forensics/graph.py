from typing import Any, Dict, List, Optional

from app.services.email.models import EmailForensicResult
from app.services.forensics.models import (
    AttackGraphResponse,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
)
from app.services.intelligence.models import (
    InvestigationIntelligenceResult,
    LookupStatus,
    ReputationStatus,
)
from app.services.risk.models import ThreatAssessmentResult


def build_attack_graph(
    forensic: EmailForensicResult,
    threat_assessment: Optional[ThreatAssessmentResult] = None,
    intelligence: Optional[InvestigationIntelligenceResult] = None,
    correlation: Optional[Any] = None,
) -> AttackGraphResponse:
    """
    Constructs a normalized, evidence-based relationship graph connecting
    observed email container, IP transit infrastructure, domains, URLs, attachments,
    intelligence metadata, and threat indicators.
    """
    nodes_map: Dict[str, GraphNode] = {}
    edges_list: List[GraphEdge] = []
    inv_id = forensic.investigation_id
    edge_seq = 1

    def add_node(node: GraphNode):
        if node.id not in nodes_map:
            nodes_map[node.id] = node

    def add_edge(
        source_id: str,
        target_id: str,
        edge_type: GraphEdgeType,
        confidence: float = 1.0,
        evidence: Optional[str] = None,
    ):
        nonlocal edge_seq
        # Ensure endpoints exist to prevent dangling edges
        if source_id not in nodes_map or target_id not in nodes_map:
            return
        # Deduplication: avoid duplicate edge of same type between same nodes
        if any(e.source == source_id and e.target == target_id and e.type == edge_type for e in edges_list):
            return

        edge_id = f"edge-{edge_seq:04d}"
        edge_seq += 1
        edges_list.append(
            GraphEdge(
                id=edge_id,
                source=source_id,
                target=target_id,
                type=edge_type,
                confidence=confidence,
                evidence_reference=evidence,
            )
        )

    # 1. Root Investigation Node
    overall_severity = threat_assessment.severity.value if threat_assessment else "INFO"
    inv_node_id = f"investigation:{inv_id}"
    add_node(
        GraphNode(
            id=inv_node_id,
            type=GraphNodeType.INVESTIGATION,
            label=f"Investigation: {inv_id}",
            severity=overall_severity,
            metadata={
                "investigation_id": inv_id,
                "risk_score": threat_assessment.risk_score if threat_assessment else 0,
                "classification": threat_assessment.classification.value if threat_assessment else "PENDING",
            },
        )
    )

    # 2. Email Container Node
    email_node_id = f"email:{inv_id}"
    email_label = f"Email: {forensic.metadata.subject[:32]}..." if forensic.metadata.subject else f"Email: {inv_id}"
    add_node(
        GraphNode(
            id=email_node_id,
            type=GraphNodeType.EMAIL,
            label=email_label,
            severity=overall_severity,
            metadata={
                "from": forensic.metadata.from_address,
                "to": forensic.metadata.to_addresses,
                "subject": forensic.metadata.subject,
                "sha256": forensic.sha256_digest,
                "file_name": forensic.file_name,
                "date": forensic.metadata.date,
            },
        )
    )
    add_edge(inv_node_id, email_node_id, GraphEdgeType.OBSERVED_IN, 1.0, "Forensic Case Ingestion")

    # 2b. Reply-To Address Node & Relationship
    if forensic.metadata.reply_to and forensic.metadata.reply_to != forensic.metadata.from_address:
        reply_addr = forensic.metadata.reply_to
        reply_node_id = f"email_address:{reply_addr}"
        add_node(
            GraphNode(
                id=reply_node_id,
                type=GraphNodeType.EMAIL,
                label=f"Reply-To: {reply_addr[:32]}",
                severity="HIGH",
                metadata={"address": reply_addr, "role": "REPLY_TO"},
            )
        )
        add_edge(email_node_id, reply_node_id, GraphEdgeType.REPLY_TO, 1.0, "Reply-To Header")

    # Map intelligence lookups by IP and domain for fast lookup
    ip_intel_map = {}
    if intelligence:
        for ip_res in intelligence.ips:
            ip_intel_map[ip_res.ip] = ip_res

    # 3. IP Infrastructure Nodes (From Received Chain & Extracted IPs)
    for hop in forensic.received_chain:
        if not hop.ip:
            continue
        ip = hop.ip
        ip_node_id = f"ip:{ip}"
        intel = ip_intel_map.get(ip)

        ip_severity = "INFO"
        if hop.hop == 1:
            ip_severity = "HIGH"
        if intel:
            if intel.reputation == ReputationStatus.KNOWN_MALICIOUS:
                ip_severity = "CRITICAL"
            elif intel.reputation == ReputationStatus.SUSPICIOUS:
                ip_severity = "HIGH"
            elif intel.reputation == ReputationStatus.CLEAN:
                ip_severity = "CLEAN"

        add_node(
            GraphNode(
                id=ip_node_id,
                type=GraphNodeType.IP,
                label=f"IP: {ip}",
                severity=ip_severity,
                metadata={
                    "ip": ip,
                    "hop": hop.hop,
                    "from_host": hop.from_host,
                    "by_host": hop.by_host,
                    "asn": intel.asn if intel else None,
                    "country": intel.country if intel else None,
                    "organization": intel.organization if intel else None,
                },
            )
        )

        edge_type = GraphEdgeType.SENT_FROM if hop.hop == 1 else GraphEdgeType.RELAYED_THROUGH
        add_edge(email_node_id, ip_node_id, edge_type, 1.0, f"Received Header (Hop {hop.hop})")

        # Connect ASN Node if available
        if intel and intel.asn:
            asn_node_id = f"asn:{intel.asn}"
            add_node(
                GraphNode(
                    id=asn_node_id,
                    type=GraphNodeType.ASN,
                    label=f"{intel.asn}",
                    severity="INFO",
                    metadata={"asn": intel.asn, "organization": intel.organization, "isp": intel.isp},
                )
            )
            add_edge(ip_node_id, asn_node_id, GraphEdgeType.BELONGS_TO_ASN, 0.95, "BGP Routing Record")

        # Connect Location Node if available
        if intel and intel.country and intel.latitude is not None:
            loc_node_id = f"location:{intel.country_code or intel.country}"
            add_node(
                GraphNode(
                    id=loc_node_id,
                    type=GraphNodeType.LOCATION,
                    label=f"Geo: {intel.city or ''} {intel.country}",
                    severity="INFO",
                    metadata={
                        "country": intel.country,
                        "country_code": intel.country_code,
                        "city": intel.city,
                        "latitude": intel.latitude,
                        "longitude": intel.longitude,
                    },
                )
            )
            add_edge(ip_node_id, loc_node_id, GraphEdgeType.GEOLOCATED_AT, 0.90, "Observed GeoIP Provider")

    # 4. Extracted Domain Nodes
    for dom in forensic.domains:
        dom_name = dom.domain
        dom_node_id = f"domain:{dom_name}"
        
        dom_severity = "INFO"
        if "paypa1" in dom_name or "xn--" in dom_name:
            dom_severity = "CRITICAL"

        add_node(
            GraphNode(
                id=dom_node_id,
                type=GraphNodeType.DOMAIN,
                label=f"Domain: {dom_name}",
                severity=dom_severity,
                metadata={"domain": dom_name, "occurrence_count": dom.occurrence_count},
            )
        )
        add_edge(email_node_id, dom_node_id, GraphEdgeType.ASSOCIATED_WITH, 1.0, "Extracted from message body/headers")

    # 5. Extracted URL Nodes & Domain Links
    for url_item in forensic.urls:
        url_node_id = f"url:{url_item.normalized_url}"
        url_label = f"URL: {url_item.path[:24] if url_item.path and url_item.path != '/' else url_item.domain}"
        
        url_severity = "INFO"
        if url_item.domain.replace(".", "").isdigit() or "login" in url_item.path or "verify" in url_item.path:
            url_severity = "HIGH"

        add_node(
            GraphNode(
                id=url_node_id,
                type=GraphNodeType.URL,
                label=url_label,
                severity=url_severity,
                metadata={
                    "url": url_item.url,
                    "normalized_url": url_item.normalized_url,
                    "scheme": url_item.scheme,
                    "domain": url_item.domain,
                    "path": url_item.path,
                },
            )
        )
        add_edge(email_node_id, url_node_id, GraphEdgeType.CONTAINS_URL, 1.0, f"Body Link ({url_item.source})")

        # Edge from URL to its Domain / Host
        dom_node_id = f"domain:{url_item.domain}"
        if dom_node_id in nodes_map:
            add_edge(url_node_id, dom_node_id, GraphEdgeType.HOSTED_ON, 1.0, "URL Host Infrastructure")

    # 6. Attachment Nodes
    for att in forensic.attachments:
        att_node_id = f"attachment:{att.filename}"
        att_severity = "HIGH" if att.extension.lower() in [".html", ".exe", ".vbs", ".zip", ".iso"] else "INFO"
        if ".pdf.html" in att.filename.lower():
            att_severity = "CRITICAL"

        add_node(
            GraphNode(
                id=att_node_id,
                type=GraphNodeType.ATTACHMENT,
                label=f"File: {att.filename}",
                severity=att_severity,
                metadata={
                    "filename": att.filename,
                    "extension": att.extension,
                    "mime_type": att.mime_type,
                    "size_bytes": att.size_bytes,
                    "sha256": att.sha256,
                },
            )
        )
        add_edge(email_node_id, att_node_id, GraphEdgeType.CONTAINS_ATTACHMENT, 1.0, f"MIME Attachment ({att.extension})")

    # 7. Threat Indicator Nodes (Step 6)
    if threat_assessment:
        for ind in threat_assessment.indicators:
            ind_node_id = f"indicator:{ind.id}"
            ind_severity = "CRITICAL" if ind.severity.value in ("CRITICAL", "HIGH") else "MEDIUM"
            add_node(
                GraphNode(
                    id=ind_node_id,
                    type=GraphNodeType.THREAT_INDICATOR,
                    label=f"Indicator: {ind.name}",
                    severity=ind_severity,
                    metadata={
                        "indicator_id": ind.id,
                        "category": ind.category.value,
                        "weight": ind.weight,
                        "rule_name": ind.id,
                        "evidence": ind.evidence,
                    },
                )
            )
            add_edge(email_node_id, ind_node_id, GraphEdgeType.TRIGGERS, 1.0, f"Detection Rule [{ind.id}]")

            # Try to connect indicator to specific domain or attachment if referenced in evidence
            for dom in forensic.domains:
                if dom.domain in ind.evidence:
                    dom_node_id = f"domain:{dom.domain}"
                    if dom_node_id in nodes_map:
                        add_edge(dom_node_id, ind_node_id, GraphEdgeType.TRIGGERS, 0.95, "Domain Heuristic Indicator")

            for att in forensic.attachments:
                if att.filename in ind.evidence or att.extension in ind.evidence:
                    att_node_id = f"attachment:{att.filename}"
                    if att_node_id in nodes_map:
                        add_edge(att_node_id, ind_node_id, GraphEdgeType.TRIGGERS, 0.95, "Attachment Heuristic Indicator")

    # 8. Ingest Correlation Relationships (if provided)
    if correlation and hasattr(correlation, "relationships"):
        for rel in correlation.relationships:
            try:
                edge_type = getattr(GraphEdgeType, rel.relationship, None)
                if edge_type and rel.source in nodes_map and rel.target in nodes_map:
                    if not any(e.source == rel.source and e.target == rel.target and e.type == edge_type for e in edges_list):
                        add_edge(rel.source, rel.target, edge_type, rel.confidence, rel.evidence)
            except Exception:
                pass

    nodes_list = list(nodes_map.values())
    return AttackGraphResponse(
        investigation_id=inv_id,
        nodes=nodes_list,
        edges=edges_list,
        total_nodes=len(nodes_list),
        total_edges=len(edges_list),
    )
