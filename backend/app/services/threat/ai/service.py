import os
from app.services.threat.ai.models import AIInputPayload, AIOutputPayload
from app.services.threat.ai.provider import (
    DeterministicFallbackAIProvider,
    GeminiAIProvider,
    ThreatAIProvider,
)


class AIService:
    """
    Manages AI enrichment execution with fallback guards.
    """

    def __init__(self, provider: ThreatAIProvider | None = None):
        if provider:
            self.provider = provider
        else:
            provider_type = os.getenv("AI_PROVIDER", "none").lower()
            if provider_type in ("gemini", "google") and (
                os.getenv("AI_API_KEY") or os.getenv("GEMINI_API_KEY")
            ):
                self.provider = GeminiAIProvider()
            else:
                self.provider = DeterministicFallbackAIProvider()

    async def get_enrichment(self, payload: AIInputPayload) -> AIOutputPayload:
        try:
            return await self.provider.analyze(payload)
        except Exception as e:
            return AIOutputPayload(
                available=False,
                provider_name=self.provider.name,
                status_message=f"AI enrichment error ({str(e)}) — deterministic analysis used.",
            )


default_ai_service = AIService()
