import json
import os
from datetime import datetime
from typing import Any, Dict, Optional

from app.core.logging import logger
from app.services.ai.fallback_provider import DeterministicFallbackAIAnalystProvider
from app.services.ai.models import (
    AIAnalystAssessment,
    AttackNarrativeStep,
    CorrelatedEntityFinding,
    InvestigationLead,
    MITRETechnique,
    RecommendedAction,
    ThreatPattern,
)
from app.services.ai.prompts import construct_ai_analyst_prompt
from app.services.ai.provider import BaseAIAnalystProvider


class GeminiAIAnalystProvider(BaseAIAnalystProvider):
    """
    Google Gemini AI Analyst provider.
    Uses Gemini Flash model to produce structured SOC analysis from sanitized evidence context.
    Gracefully falls back to DeterministicFallbackAIAnalystProvider if unconfigured or unreachable.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-1.5-flash"):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("AI_API_KEY")
        self._model_name = model or os.getenv("AI_MODEL", "gemini-1.5-flash")
        self._fallback = DeterministicFallbackAIAnalystProvider()

    @property
    def name(self) -> str:
        return "Google Gemini"

    @property
    def model(self) -> str:
        return self._model_name

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key.strip()) > 5)

    async def generate_assessment(
        self,
        investigation_id: str,
        evidence_id: str,
        evidence_hash: str,
        evidence_context: Dict[str, Any],
    ) -> AIAnalystAssessment:
        if not self.is_configured():
            logger.info("Gemini API key not found. Using deterministic SOC fallback provider.")
            return await self._fallback.generate_assessment(
                investigation_id, evidence_id, evidence_hash, evidence_context
            )

        try:
            # Construct prompt with strict prompt-injection boundaries
            prompt_text = construct_ai_analyst_prompt(evidence_context)

            # In runtime with configured key: attempt call via official SDK or REST
            # For demonstration safety and mock resilience, we execute deterministic analysis augmented by model metadata
            import urllib.request
            import urllib.error

            api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{self._model_name}:generateContent?key={self.api_key}"
            req_data = {
                "contents": [{"parts": [{"text": prompt_text}]}],
                "generationConfig": {
                    "temperature": 0.1,
                    "responseMimeType": "application/json",
                },
            }

            req = urllib.request.Request(
                api_url,
                data=json.dumps(req_data).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )

            with urllib.request.urlopen(req, timeout=5) as response:
                res_body = response.read().decode("utf-8")
                res_json = json.loads(res_body)
                content_text = res_json["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(content_text)

                num_part = investigation_id.split("-")[-1] if "-" in investigation_id else "00001"
                assessment_id = f"AIA-2026-{num_part}"

                return AIAnalystAssessment(
                    assessment_id=assessment_id,
                    investigation_id=investigation_id,
                    evidence_id=evidence_id,
                    input_evidence_hash=evidence_hash,
                    created_at=datetime.utcnow(),
                    provider=self.name,
                    model=self._model_name,
                    fallback_used=False,
                    executive_summary=parsed.get("executive_summary", ""),
                    threat_pattern=ThreatPattern(**parsed["threat_pattern"]),
                    ai_confidence_score=parsed.get("ai_confidence_score", 0.92),
                    ai_confidence_percentage=parsed.get("ai_confidence_percentage", 92),
                    attack_narrative=[AttackNarrativeStep(**s) for s in parsed.get("attack_narrative", [])],
                    correlated_findings=[CorrelatedEntityFinding(**f) for f in parsed.get("correlated_findings", [])],
                    mitre_techniques=[MITRETechnique(**t) for t in parsed.get("mitre_techniques", [])],
                    investigation_leads=[InvestigationLead(**l) for l in parsed.get("investigation_leads", [])],
                    recommended_actions=[RecommendedAction(**a) for a in parsed.get("recommended_actions", [])],
                    related_cases=evidence_context.get("correlation").related_cases if evidence_context.get("correlation") else [],
                    output_version="1.0",
                    prompt_tokens=len(prompt_text.split()),
                )

        except Exception as e:
            logger.warning(f"Gemini API request failed ({e}). Falling back to deterministic SOC analysis.")
            res = await self._fallback.generate_assessment(
                investigation_id, evidence_id, evidence_hash, evidence_context
            )
            res.fallback_reason = f"Gemini API call failed: {str(e)[:60]}... using deterministic fallback."
            return res
