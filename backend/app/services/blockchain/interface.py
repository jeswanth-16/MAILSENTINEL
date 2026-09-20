from abc import ABC, abstractmethod
from typing import List, Optional

from app.services.blockchain.models import (
    BlockchainAnchorRecord,
    BlockchainProviderType,
    EvidencePackage,
    VerificationResult,
)


class BaseBlockchainProvider(ABC):
    """
    Abstract interface for blockchain evidence anchoring and verification providers.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def provider_type(self) -> BlockchainProviderType:
        pass

    @property
    @abstractmethod
    def network_name(self) -> str:
        pass

    @abstractmethod
    async def anchor_evidence(
        self, package: EvidencePackage, digest: str
    ) -> BlockchainAnchorRecord:
        """Anchors an evidence package digest on-chain."""
        pass

    @abstractmethod
    async def verify_evidence(
        self, evidence_id: str, current_digest: str
    ) -> VerificationResult:
        """Verifies current evidence package digest against on-chain anchor."""
        pass

    @abstractmethod
    async def get_anchor(
        self, evidence_id: str
    ) -> Optional[BlockchainAnchorRecord]:
        """Retrieves an existing anchor record by evidence ID."""
        pass

    @abstractmethod
    async def get_history(
        self, investigation_id: Optional[str] = None
    ) -> List[BlockchainAnchorRecord]:
        """Retrieves anchor history filtered optionally by investigation ID."""
        pass

    @abstractmethod
    async def get_ledger(self) -> List[BlockchainAnchorRecord]:
        """Retrieves complete immutable ledger records."""
        pass
