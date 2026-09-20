from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from app.services.ai.models import AIAnalystAssessment


class BaseAIAnalystProvider(ABC):
    """
    Abstract interface for AI SOC Analyst assessment providers.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def model(self) -> str:
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        pass

    @abstractmethod
    async def generate_assessment(
        self,
        investigation_id: str,
        evidence_id: str,
        evidence_hash: str,
        evidence_context: Dict[str, Any],
    ) -> AIAnalystAssessment:
        pass
