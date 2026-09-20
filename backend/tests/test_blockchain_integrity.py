import asyncio
import copy
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.blockchain.hashing import (
    canonicalize_evidence_package,
    compute_evidence_digest,
    compute_sha256,
)
from app.services.blockchain.models import (
    BlockchainStatus,
    EvidencePackage,
)
from app.services.blockchain.providers.mock_provider import DemoBlockchainProvider
from app.services.blockchain.service import BlockchainService


def test_deterministic_canonical_hashing():
    pkg1 = EvidencePackage(
        evidence_id="EVD-2026-TEST1",
        investigation_id="INV-2026-TEST1",
        file_name="invoice.eml",
        file_size_bytes=1024,
        raw_file_sha256="7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        metadata_summary={"subject": "Urgent", "from": "test@domain.com"},
        threat_summary={"risk_score": 85, "severity": "HIGH"},
        created_at="2026-03-01T12:00:00Z",
    )

    pkg2 = EvidencePackage(
        evidence_id="EVD-2026-TEST1",
        investigation_id="INV-2026-TEST1",
        file_name="invoice.eml",
        file_size_bytes=1024,
        raw_file_sha256="7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        metadata_summary={"from": "test@domain.com", "subject": "Urgent"},  # Reversed key order
        threat_summary={"severity": "HIGH", "risk_score": 85},  # Reversed key order
        created_at="2026-03-01T12:00:00Z",
    )

    # 1. Determinism: same content with different key order must yield exact same digest
    digest1 = compute_evidence_digest(pkg1)
    digest2 = compute_evidence_digest(pkg2)
    assert digest1 == digest2
    assert len(digest1) == 64

    # 2. Tamper sensitivity: modifying any property must change the digest
    pkg_tampered = copy.deepcopy(pkg1)
    pkg_tampered.threat_summary["risk_score"] = 10  # Altered risk score
    digest_tampered = compute_evidence_digest(pkg_tampered)
    assert digest1 != digest_tampered


def test_demo_blockchain_provider_anchoring_and_verification():
    provider = DemoBlockchainProvider(start_block=1000)
    pkg = EvidencePackage(
        evidence_id="EVD-2026-TEST_PROV",
        investigation_id="INV-2026-TEST_PROV",
        file_name="test.eml",
        file_size_bytes=2048,
        raw_file_sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    )
    digest = compute_evidence_digest(pkg)

    # 1. Anchor evidence
    record = asyncio.run(provider.anchor_evidence(pkg, digest))
    assert record.evidence_id == pkg.evidence_id
    assert record.block_number == 1001
    assert record.transaction_hash.startswith("0x")
    assert len(record.transaction_hash) == 66
    assert record.evidence_hash == digest

    # 2. Verify with matching digest
    verif_ok = asyncio.run(provider.verify_evidence(pkg.evidence_id, digest))
    assert verif_ok.match is True
    assert verif_ok.status == BlockchainStatus.VERIFIED

    # 3. Verify with mismatched / tampered digest
    fake_digest = "0000000000000000000000000000000000000000000000000000000000000000"
    verif_tampered = asyncio.run(provider.verify_evidence(pkg.evidence_id, fake_digest))
    assert verif_tampered.match is False
    assert verif_tampered.status == BlockchainStatus.TAMPERED

    # 4. Verify non-existent evidence
    verif_unknown = asyncio.run(provider.verify_evidence("EVD-NON-EXISTENT", digest))
    assert verif_unknown.status == BlockchainStatus.NOT_FOUND


def test_blockchain_service_end_to_end_tamper_cycle():
    service = BlockchainService()

    # 1. Create package from pre-seeded INV-2026-00001
    pkg = asyncio.run(service.create_evidence_package("INV-2026-00001"))
    assert pkg.evidence_id == "EVD-2026-00001"
    assert pkg.canonical_digest is not None

    # 2. Anchor
    record = asyncio.run(service.anchor_evidence(pkg.evidence_id))
    assert record.blockchain_status == BlockchainStatus.ANCHORED

    # 3. Verify initial state (VERIFIED)
    res1 = asyncio.run(service.verify_evidence(pkg.evidence_id))
    assert res1.status == BlockchainStatus.VERIFIED
    assert res1.match is True

    # 4. Simulate tamper in testbed (TAMPERED)
    tampered_pkg = asyncio.run(service.simulate_evidence_tamper(pkg.evidence_id))
    assert tampered_pkg.canonical_digest != pkg.canonical_digest

    res2 = asyncio.run(service.verify_evidence(pkg.evidence_id))
    assert res2.status == BlockchainStatus.TAMPERED
    assert res2.match is False

    # 5. Restore original evidence (VERIFIED)
    restored_pkg = asyncio.run(service.reset_evidence_tamper(pkg.evidence_id))
    assert restored_pkg.canonical_digest == pkg.canonical_digest

    res3 = asyncio.run(service.verify_evidence(pkg.evidence_id))
    assert res3.status == BlockchainStatus.VERIFIED
    assert res3.match is True


def test_api_blockchain_endpoints(client):
    # 1. Generate evidence package endpoint
    pkg_resp = client.post("/api/v1/evidence/package/INV-2026-00001")
    assert pkg_resp.status_code == 200
    pkg_data = pkg_resp.json()
    assert pkg_data["evidence_id"] == "EVD-2026-00001"

    # 2. Anchor endpoint
    anchor_resp = client.post("/api/v1/blockchain/anchor/EVD-2026-00001")
    assert anchor_resp.status_code == 200
    anchor_data = anchor_resp.json()
    assert anchor_data["blockchain_status"] == "ANCHORED"
    assert anchor_data["transaction_hash"].startswith("0x")

    # 3. Verify endpoint (VERIFIED)
    verif_resp = client.post("/api/v1/blockchain/verify/EVD-2026-00001")
    assert verif_resp.status_code == 200
    verif_data = verif_resp.json()
    assert verif_data["status"] == "VERIFIED"
    assert verif_data["match"] is True

    # 4. Simulate Tamper endpoint
    tamper_resp = client.post("/api/v1/blockchain/tamper-simulate/EVD-2026-00001")
    assert tamper_resp.status_code == 200

    # 5. Verify under tamper (TAMPERED)
    verif_tampered = client.post("/api/v1/blockchain/verify/EVD-2026-00001")
    assert verif_tampered.status_code == 200
    assert verif_tampered.json()["status"] == "TAMPERED"

    # 6. Reset tamper
    reset_resp = client.post("/api/v1/blockchain/tamper-reset/EVD-2026-00001")
    assert reset_resp.status_code == 200

    # 7. Get ledger and custody
    ledger_resp = client.get("/api/v1/blockchain/ledger")
    assert ledger_resp.status_code == 200
    assert len(ledger_resp.json()) > 0

    custody_resp = client.get("/api/v1/blockchain/custody/INV-2026-00001")
    assert custody_resp.status_code == 200
    assert len(custody_resp.json()) >= 2
