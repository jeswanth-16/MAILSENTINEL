from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class BlockchainStatus(str, Enum):
    PENDING = "PENDING"
    ANCHORED = "ANCHORED"
    VERIFIED = "VERIFIED"
    TAMPERED = "TAMPERED"
    NOT_FOUND = "NOT_FOUND"
    FAILED = "FAILED"


class BlockchainProviderType(str, Enum):
    DEMO = "DEMO"
    EVM = "EVM"


class EvidencePackage(BaseModel):
    """
    Standardized, canonicalized forensic bundle containing normalized email evidence,
    authentication verdicts, risk metrics, and structural metadata.
    """
    evidence_id: str = Field(..., description="Unique evidence package identifier e.g. EVD-2026-00001")
    investigation_id: str = Field(..., description="Associated investigation identifier e.g. INV-2026-00001")
    evidence_type: str = Field(default="EMAIL_FORENSIC_BUNDLE")
    file_name: str = Field(...)
    file_size_bytes: int = Field(...)
    raw_file_sha256: str = Field(..., description="SHA-256 of raw unparsed .EML container")
    metadata_summary: Dict[str, Any] = Field(default_factory=dict)
    auth_summary: Dict[str, str] = Field(default_factory=dict)
    threat_summary: Dict[str, Any] = Field(default_factory=dict)
    entity_counts: Dict[str, int] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: str = Field(default="1.0")
    canonical_digest: Optional[str] = Field(default=None, description="SHA-256 digest of canonical JSON")


class BlockchainAnchorRecord(BaseModel):
    """
    Immutable ledger record recording on-chain anchor details.
    """
    evidence_id: str
    investigation_id: str
    evidence_hash: str = Field(..., description="Cryptographic SHA-256 anchored on-chain")
    blockchain_status: BlockchainStatus = Field(default=BlockchainStatus.ANCHORED)
    provider: BlockchainProviderType = Field(default=BlockchainProviderType.DEMO)
    network: str = Field(default="MAILSENTINEL-DEMO-CHAIN")
    transaction_hash: str = Field(..., description="Hex 0x... transaction identifier")
    block_number: int = Field(..., description="Block height where evidence was anchored")
    previous_block_hash: str = Field(...)
    anchored_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    contract_address: Optional[str] = Field(default=None)
    verification_status: BlockchainStatus = Field(default=BlockchainStatus.ANCHORED)
    anchored_by: str = Field(default="MAILSENTINEL-ORACLE-01")


class VerificationResult(BaseModel):
    """
    Result of comparing the recomputed canonical evidence hash against the immutable on-chain record.
    """
    status: BlockchainStatus
    match: bool
    stored_hash: str
    current_hash: str
    message: str
    evidence_id: str
    investigation_id: str
    block_number: Optional[int] = None
    transaction_hash: Optional[str] = None
    network: Optional[str] = None
    anchored_at: Optional[str] = None
    verified_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CustodyEvent(BaseModel):
    """
    Chain of custody milestone in digital forensic evidence lifecycle.
    """
    event_id: str
    evidence_id: str
    investigation_id: str
    timestamp: str
    phase: str
    title: str
    actor: str
    hash_reference: Optional[str] = None
    status: str = "CONFIRMED"
