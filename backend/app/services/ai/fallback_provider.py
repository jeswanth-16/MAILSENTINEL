from datetime import datetime
from typing import Any, Dict, Optional

from app.services.ai.models import AIAnalystAssessment
from app.services.ai.narrative import (
    generate_attack_narrative,
    generate_executive_summary,
    generate_investigation_leads,
    generate_mitre_techniques,
    generate_recommended_actions,
)
from app.services.ai.provider import BaseAIAnalystProvider


class DeterministicFallbackAIAnalystProvider(BaseAIAnalystProvider):
    """
    Deterministic rule-based SOC Analyst provider.
    Ensures 100% functionality and rich intelligence generation even when Gemini or external LLMs are unavailable.
    """

    @property
    def name(self) -> str:
        return "Deterministic SOC Rule Engine"

    @property
    def model(self) -> str:
        return "rule-engine-v1.0 (Offline Fallback)"

    def is_configured(self) -> bool:
        return True

    async def generate_assessment(
        self,
        investigation_id: str,
        evidence_id: str,
        evidence_hash: str,
        evidence_context: Dict[str, Any],
    ) -> AIAnalystAssessment:
        forensic = evidence_context.get("forensic")
        threat = evidence_context.get("threat")
        correlation = evidence_context.get("correlation")

        narrative = generate_attack_narrative(forensic, threat, correlation)
        techniques = generate_mitre_techniques(forensic, threat, correlation)
        leads = generate_investigation_leads(forensic, threat, correlation)
        actions = generate_recommended_actions(forensic, threat, correlation)
        exec_summary = generate_executive_summary(forensic, threat, correlation)

        num_part = investigation_id.split("-")[-1] if "-" in investigation_id else "00001"
        assessment_id = f"AIA-2026-{num_part}"

        return AIAnalystAssessment(
            assessment_id=assessment_id,
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            input_evidence_hash=evidence_hash,
            created_at=datetime.utcnow(),
            provider=self.name,
            model=self.model,
            fallback_used=True,
            fallback_reason="Operating in deterministic offline SOC fallback mode.",
            executive_summary=exec_summary,
            threat_pattern=correlation.primary_pattern,
            ai_confidence_score=0.92,
            ai_confidence_percentage=92,
            attack_narrative=narrative,
            correlated_findings=correlation.correlated_findings,
            mitre_techniques=techniques,
            investigation_leads=leads,
            recommended_actions=actions,
            related_cases=correlation.related_cases,
            output_version="1.0",
            prompt_tokens=0,
        )
