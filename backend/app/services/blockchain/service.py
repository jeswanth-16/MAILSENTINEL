import copy
import os
import threading
from typing import List, Optional

from app.core.logging import logger
from app.services.blockchain.hashing import compute_evidence_digest
from app.services.blockchain.interface import BaseBlockchainProvider
from app.services.blockchain.models import (
    BlockchainAnchorRecord,
    BlockchainProviderType,
    BlockchainStatus,
    CustodyEvent,
    EvidencePackage,
    VerificationResult,
)
from app.services.blockchain.providers.evm_provider import EVMTestnetProvider
from app.services.blockchain.providers.mock_provider import DemoBlockchainProvider
from app.services.blockchain.storage import BlockchainEvidenceStore, evidence_store
from app.services.forensics.service import investigation_registry


class BlockchainService:
    """
    Main coordinator for cryptographic evidence bundling, blockchain anchoring,
    tamper verification, and chain of custody management.
    """

    def __init__(
        self,
        provider: Optional[BaseBlockchainProvider] = None,
        store: Optional[BlockchainEvidenceStore] = None,
    ):
        configured_provider = os.getenv("BLOCKCHAIN_PROVIDER", "demo").lower()
        if configured_provider == "evm":
            self.provider = provider or EVMTestnetProvider()
        else:
            self.provider = provider or DemoBlockchainProvider()

        self.store = store or evidence_store
        self._seeded = False
        self._lock = threading.Lock()

    async def create_evidence_package(self, investigation_id: str) -> EvidencePackage:
        await investigation_registry.ensure_seeded()
        existing = self.store.get_package_by_investigation(investigation_id)
        if existing:
            return existing

        forensic = investigation_registry.get_forensic(investigation_id)
        if not forensic:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        threat = investigation_registry.get_threat(investigation_id)

        # Generate standard evidence ID
        num_part = investigation_id.split("-")[-1] if "-" in investigation_id else "00001"
        evidence_id = f"EVD-2026-{num_part}"

        package = EvidencePackage(
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            evidence_type="EMAIL_FORENSIC_BUNDLE",
            file_name=forensic.file_name,
            file_size_bytes=forensic.file_size_bytes,
            raw_file_sha256=forensic.sha256_digest,
            created_at=forensic.analyzed_at,

            metadata_summary={
                "from": forensic.metadata.from_address,
                "to": forensic.metadata.to_addresses,
                "subject": forensic.metadata.subject,
                "date": forensic.metadata.date,
                "message_id": forensic.metadata.message_id,
                "raw_headers_count": forensic.metadata.raw_headers_count,
            },
            auth_summary={
                "spf": forensic.authentication.spf.value,
                "dkim": forensic.authentication.dkim.value,
                "dmarc": forensic.authentication.dmarc.value,
            },
            threat_summary={
                "risk_score": threat.risk_score if threat else 0,
                "severity": threat.severity.value if threat else "INFO",
                "classification": threat.classification.value if threat else "PENDING",
                "indicator_count": len(threat.indicators) if threat else 0,
            },
            entity_counts={
                "ips": len(forensic.ip_addresses),
                "domains": len(forensic.domains),
                "urls": len(forensic.urls),
                "attachments": len(forensic.attachments),
                "received_hops": len(forensic.received_chain),
            },
            schema_version="1.0",
        )

        # Compute canonical hash
        digest = compute_evidence_digest(package)
        package.canonical_digest = digest

        self.store.store_package(package)
        return package

    async def anchor_evidence(self, evidence_id: str) -> BlockchainAnchorRecord:
        await self.ensure_seeded()
        pkg = self.store.get_package(evidence_id)
        if not pkg:
            raise ValueError(f"Evidence package '{evidence_id}' not found.")

        digest = pkg.canonical_digest or compute_evidence_digest(pkg)
        record = await self.provider.anchor_evidence(pkg, digest)

        self.store.add_custody_event(
            evidence_id=evidence_id,
            investigation_id=pkg.investigation_id,
            phase="ANCHOR",
            title=f"Evidence Digest Anchored to {record.network} (Block #{record.block_number})",
            actor="MAILSENTINEL-BLOCKCHAIN-RELAY",
            hash_reference=record.transaction_hash,
        )

        return record

    async def verify_evidence(self, evidence_id: str) -> VerificationResult:
        await self.ensure_seeded()
        pkg = self.store.get_effective_package(evidence_id)
        if not pkg:
            return VerificationResult(
                status=BlockchainStatus.NOT_FOUND,
                match=False,
                stored_hash="",
                current_hash="",
                message=f"Evidence package '{evidence_id}' not found in registry.",
                evidence_id=evidence_id,
                investigation_id="",
            )

        # Recompute canonical digest of the current state of evidence
        current_digest = compute_evidence_digest(pkg)
        res = await self.provider.verify_evidence(evidence_id, current_digest)

        phase = "VERIFICATION_SUCCESS" if res.match else "TAMPER_ALERT"
        self.store.add_custody_event(
            evidence_id=evidence_id,
            investigation_id=pkg.investigation_id,
            phase=phase,
            title=f"Integrity Check: {res.status.value}",
            actor="VERIFICATION-ENGINE",
            hash_reference=f"Computed: {current_digest[:16]}...",
        )

        return res

    async def simulate_evidence_tamper(self, evidence_id: str) -> EvidencePackage:
        """
        Creates a simulated modified copy of the evidence package in memory
        to safely demonstrate on-chain tamper detection without altering actual files.
        """
        await self.ensure_seeded()
        pkg = self.store.get_package(evidence_id)
        if not pkg:
            raise ValueError(f"Evidence package '{evidence_id}' not found.")

        # Create modified copy with altered metadata and subject
        tampered = copy.deepcopy(pkg)
        tampered.metadata_summary["subject"] = f"{pkg.metadata_summary.get('subject', '')} [TAMPERED_ATTACHMENT_REMOVED]"
        tampered.threat_summary["risk_score"] = 0
        tampered.threat_summary["severity"] = "CLEAN"

        # Recompute digest (will differ from on-chain anchor!)
        new_digest = compute_evidence_digest(tampered)
        tampered.canonical_digest = new_digest

        self.store.store_tampered_copy(evidence_id, tampered)
        return tampered

    async def reset_evidence_tamper(self, evidence_id: str) -> EvidencePackage:
        """Restores the original untampered evidence package copy."""
        pkg = self.store.clear_tamper_copy(evidence_id)
        if not pkg:
            raise ValueError(f"Evidence package '{evidence_id}' not found.")
        return pkg

    async def get_evidence_record(self, evidence_id: str) -> Optional[BlockchainAnchorRecord]:
        await self.ensure_seeded()
        return await self.provider.get_anchor(evidence_id)

    async def get_history(self, investigation_id: Optional[str] = None) -> List[BlockchainAnchorRecord]:
        await self.ensure_seeded()
        return await self.provider.get_history(investigation_id)

    async def get_ledger(self) -> List[BlockchainAnchorRecord]:
        await self.ensure_seeded()
        return await self.provider.get_ledger()

    async def get_custody_chain(self, investigation_id: str) -> List[CustodyEvent]:
        await self.ensure_seeded()
        return self.store.get_custody_chain(investigation_id)

    async def ensure_seeded(self):
        """Pre-seeds standard SIH demo evidence packages and anchors on startup."""
        if self._seeded:
            return

        with self._lock:
            if self._seeded:
                return
            self._seeded = True

        try:
            # 1. Seed INV-2026-00001 -> EVD-2026-00001
            pkg1 = await self.create_evidence_package("INV-2026-00001")
            await self.anchor_evidence(pkg1.evidence_id)
            
            # 2. Seed INV-2026-00004 -> EVD-2026-00004
            pkg4 = await self.create_evidence_package("INV-2026-00004")
            await self.anchor_evidence(pkg4.evidence_id)
        except Exception as e:
            logger.warning(f"Error during blockchain pre-seeding: {e}")


default_blockchain_service = BlockchainService()
