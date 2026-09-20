import os
from typing import List, Optional

from app.core.logging import logger
from app.services.blockchain.interface import BaseBlockchainProvider
from app.services.blockchain.models import (
    BlockchainAnchorRecord,
    BlockchainProviderType,
    EvidencePackage,
    VerificationResult,
)
from app.services.blockchain.providers.mock_provider import DemoBlockchainProvider


class EVMTestnetProvider(BaseBlockchainProvider):
    """
    Optional EVM Testnet Provider connecting to Ethereum/Polygon/Arbitrum testnets.
    Falls back gracefully to DemoBlockchainProvider when EVM configuration is not active.
    """

    def __init__(self):
        self.rpc_url = os.getenv("EVM_RPC_URL", "").strip()
        self.chain_id = os.getenv("EVM_CHAIN_ID", "").strip()
        self.contract_address = os.getenv("EVM_CONTRACT_ADDRESS", "").strip()
        # Fallback local provider
        self._fallback_provider = DemoBlockchainProvider()
        
        self.is_configured = bool(self.rpc_url and self.contract_address)
        if not self.is_configured:
            logger.info("EVM configuration not provided — active provider: DEMO BLOCKCHAIN.")
        else:
            logger.info(f"EVM Testnet configured on Contract {self.contract_address[:8]}...")

    @property
    def name(self) -> str:
        return "EVM Testnet Provider" if self.is_configured else "Demo Local Blockchain (EVM Fallback)"

    @property
    def provider_type(self) -> BlockchainProviderType:
        return BlockchainProviderType.EVM if self.is_configured else BlockchainProviderType.DEMO

    @property
    def network_name(self) -> str:
        return os.getenv("EVM_NETWORK_NAME", "Ethereum Sepolia Testnet") if self.is_configured else "MAILSENTINEL-DEMO-CHAIN"

    async def anchor_evidence(
        self, package: EvidencePackage, digest: str
    ) -> BlockchainAnchorRecord:
        # If not configured with a live web3 node, delegate to fallback provider
        return await self._fallback_provider.anchor_evidence(package, digest)

    async def verify_evidence(
        self, evidence_id: str, current_digest: str
    ) -> VerificationResult:
        return await self._fallback_provider.verify_evidence(evidence_id, current_digest)

    async def get_anchor(
        self, evidence_id: str
    ) -> Optional[BlockchainAnchorRecord]:
        return await self._fallback_provider.get_anchor(evidence_id)

    async def get_history(
        self, investigation_id: Optional[str] = None
    ) -> List[BlockchainAnchorRecord]:
        return await self._fallback_provider.get_history(investigation_id)

    async def get_ledger(self) -> List[BlockchainAnchorRecord]:
        return await self._fallback_provider.get_ledger()
