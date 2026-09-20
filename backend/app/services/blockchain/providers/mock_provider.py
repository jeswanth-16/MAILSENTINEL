from datetime import datetime, timezone
import hashlib
import threading
from typing import Dict, List, Optional

from app.services.blockchain.hashing import compute_sha256
from app.services.blockchain.interface import BaseBlockchainProvider
from app.services.blockchain.models import (
    BlockchainAnchorRecord,
    BlockchainProviderType,
    BlockchainStatus,
    EvidencePackage,
    VerificationResult,
)


class DemoBlockchainProvider(BaseBlockchainProvider):
    """
    Demo Blockchain Provider simulating an immutable cryptographic ledger locally.
    Maintains realistic block heights, previous block hash links, transaction IDs,
    and deterministic verification without requiring gas, wallets, or external network access.
    """

    def __init__(self, start_block: int = 1040):
        self._lock = threading.Lock()
        self._records: Dict[str, BlockchainAnchorRecord] = {}  # evidence_id -> record
        self._ledger: List[BlockchainAnchorRecord] = []
        self._current_block = start_block
        self._latest_block_hash = "0x0000000000000000000000000000000000000000000000000000000000000000"

    @property
    def name(self) -> str:
        return "Demo Local Blockchain"

    @property
    def provider_type(self) -> BlockchainProviderType:
        return BlockchainProviderType.DEMO

    @property
    def network_name(self) -> str:
        return "MAILSENTINEL-DEMO-CHAIN"

    def _generate_tx_hash(self, evidence_id: str, digest: str, block_num: int) -> str:
        payload = f"{evidence_id}:{digest}:{block_num}:{self._latest_block_hash}".encode("utf-8")
        raw_hash = hashlib.sha256(payload).hexdigest()
        return f"0x{raw_hash}"

    async def anchor_evidence(
        self, package: EvidencePackage, digest: str
    ) -> BlockchainAnchorRecord:
        with self._lock:
            # If already anchored, return existing record
            if package.evidence_id in self._records:
                return self._records[package.evidence_id]

            self._current_block += 1
            block_number = self._current_block
            prev_hash = self._latest_block_hash
            tx_hash = self._generate_tx_hash(package.evidence_id, digest, block_number)
            
            # Compute new block hash linking previous hash and transaction hash
            block_payload = f"{block_number}:{prev_hash}:{tx_hash}:{digest}".encode("utf-8")
            self._latest_block_hash = f"0x{hashlib.sha256(block_payload).hexdigest()}"

            record = BlockchainAnchorRecord(
                evidence_id=package.evidence_id,
                investigation_id=package.investigation_id,
                evidence_hash=digest,
                blockchain_status=BlockchainStatus.ANCHORED,
                provider=self.provider_type,
                network=self.network_name,
                transaction_hash=tx_hash,
                block_number=block_number,
                previous_block_hash=prev_hash,
                anchored_at=datetime.now(timezone.utc).isoformat(),
                contract_address=None,
                verification_status=BlockchainStatus.ANCHORED,
                anchored_by="MAILSENTINEL-ORACLE-01 (Demo Authority)",
            )

            self._records[package.evidence_id] = record
            self._ledger.insert(0, record)  # Newest first
            return record

    async def verify_evidence(
        self, evidence_id: str, current_digest: str
    ) -> VerificationResult:
        with self._lock:
            record = self._records.get(evidence_id)
            if not record:
                return VerificationResult(
                    status=BlockchainStatus.NOT_FOUND,
                    match=False,
                    stored_hash="",
                    current_hash=current_digest,
                    message=f"No blockchain anchor found for Evidence ID '{evidence_id}'.",
                    evidence_id=evidence_id,
                    investigation_id="",
                )

            is_match = (record.evidence_hash.lower() == current_digest.lower())
            status = BlockchainStatus.VERIFIED if is_match else BlockchainStatus.TAMPERED
            message = (
                "Evidence integrity cryptographically verified. Hash matches on-chain anchor exactly."
                if is_match
                else "CRITICAL ALERT: Evidence integrity check failed. Current fingerprint does not match on-chain anchor (Tampering detected)."
            )

            # Update verification status in record
            record.verification_status = status

            return VerificationResult(
                status=status,
                match=is_match,
                stored_hash=record.evidence_hash,
                current_hash=current_digest,
                message=message,
                evidence_id=record.evidence_id,
                investigation_id=record.investigation_id,
                block_number=record.block_number,
                transaction_hash=record.transaction_hash,
                network=record.network,
                anchored_at=record.anchored_at,
            )

    async def get_anchor(
        self, evidence_id: str
    ) -> Optional[BlockchainAnchorRecord]:
        with self._lock:
            return self._records.get(evidence_id)

    async def get_history(
        self, investigation_id: Optional[str] = None
    ) -> List[BlockchainAnchorRecord]:
        with self._lock:
            if investigation_id:
                return [r for r in self._ledger if r.investigation_id == investigation_id]
            return list(self._ledger)

    async def get_ledger(self) -> List[BlockchainAnchorRecord]:
        with self._lock:
            return list(self._ledger)
