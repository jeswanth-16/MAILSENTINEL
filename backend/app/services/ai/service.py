import os
import threading
from typing import Dict, List, Optional, Any

from app.core.logging import logger
from app.services.ai.correlation import correlate_investigation_evidence
from app.services.ai.fallback_provider import DeterministicFallbackAIAnalystProvider
from app.services.ai.gemini_provider import GeminiAIAnalystProvider
from app.services.ai.models import (
    AIAnalystAssessment,
    CorrelationResult,
    InvestigationAssessment,
    RelatedCase,
)
from app.services.ai.provider import BaseAIAnalystProvider
from app.services.blockchain.service import default_blockchain_service
from app.services.decision import default_decision_engine
from app.services.forensics.service import investigation_registry


class AIAnalystService:
    """
    Central coordinator for Automated Forensic Decision Engine assessments,
    multi-entity threat correlation, and SQLite-backed audit trails.
    """

    def __init__(self, provider: Optional[BaseAIAnalystProvider] = None):
        self._lock = threading.Lock()
        self._cache: Dict[str, InvestigationAssessment] = {}  # Keyed by input_evidence_hash
        self._inv_to_hash: Dict[str, str] = {}  # Maps investigation_id -> latest evidence hash
        self._repository = None

        # Optional secondary LLM provider for stylistic summaries
        configured = os.getenv("AI_PROVIDER", "fallback").lower()
        if configured == "gemini":
            self.provider = provider or GeminiAIAnalystProvider()
        else:
            self.provider = provider or DeterministicFallbackAIAnalystProvider()

    @property
    def repository(self):
        if self._repository is None:
            from app.services.persistence.assessment_repository import (
                default_assessment_sqlite_repository,
            )
            self._repository = default_assessment_sqlite_repository
        return self._repository

    async def analyze_investigation(
        self,
        investigation_id: str,
        force_refresh: bool = False,
    ) -> InvestigationAssessment:
        """
        Executes automated forensic evaluation on the investigation evidence package.
        Reuses cached or persisted assessment if evidence hash has not changed.
        """
        await investigation_registry.ensure_seeded()
        await default_blockchain_service.ensure_seeded()

        forensic = investigation_registry.get_forensic(investigation_id)
        threat = investigation_registry.get_threat(investigation_id)
        intel = investigation_registry.get_intelligence(investigation_id)
        correlation_phase3 = investigation_registry.get_correlation(investigation_id)

        # Get evidence package / hash
        pkg = default_blockchain_service.store.get_package_by_investigation(investigation_id)
        if not pkg:
            try:
                pkg = await default_blockchain_service.create_evidence_package(investigation_id)
            except Exception:
                pkg = None

        evidence_id = pkg.evidence_id if pkg else "EVD-2026-00001"
        evidence_hash = pkg.canonical_digest if pkg else (forensic.sha256_digest if forensic else "UNKNOWN_HASH")

        # 1. In-memory Cache check
        if not force_refresh:
            with self._lock:
                if evidence_hash in self._cache:
                    return self._cache[evidence_hash]

            # 2. SQLite Persistent check
            persisted = self.repository.get_assessment(investigation_id)
            if persisted and persisted.input_evidence_hash == evidence_hash:
                with self._lock:
                    self._cache[evidence_hash] = persisted
                    self._inv_to_hash[investigation_id] = evidence_hash
                return persisted

        # 3. Deterministic Phase 4 Forensic Decision Engine evaluation
        from app.services.investigations.service import default_case_service
        all_cases = await default_case_service.list_investigations()

        assessment = default_decision_engine.evaluate_investigation(
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            forensic=forensic,
            threat=threat,
            intel=intel,
            correlation=correlation_phase3,
            other_cases=all_cases,
        )

        # 4. Persist to SQLite
        try:
            self.repository.save_assessment(assessment)
        except Exception as e:
            logger.warning(f"Could not persist assessment {assessment.assessment_id} to SQLite: {e}")

        # 5. Audit log in case notes
        try:
            from app.services.investigations.models import NoteType
            action_type = "recalculated" if force_refresh else "generated"
            await default_case_service.add_note(
                investigation_id=investigation_id,
                content=(
                    f"Automated forensic assessment {action_type}: verdict={assessment.verdict.value}, "
                    f"confidence={assessment.confidence.value}, risk_score={assessment.risk_score}/100, "
                    f"engine=v{assessment.engine_version}."
                ),
                author="Forensic Decision Engine",
                note_type=NoteType.SYSTEM,
            )
        except Exception as e:
            logger.debug(f"Audit trail note skipped for {investigation_id}: {e}")

        # 6. Update memory cache
        with self._lock:
            self._cache[evidence_hash] = assessment
            self._inv_to_hash[investigation_id] = evidence_hash

        return assessment

    async def get_assessment(self, investigation_id: str) -> Optional[InvestigationAssessment]:
        with self._lock:
            ev_hash = self._inv_to_hash.get(investigation_id)
            if ev_hash and ev_hash in self._cache:
                return self._cache[ev_hash]

        # Check SQLite persistence
        persisted = self.repository.get_assessment(investigation_id)
        if persisted:
            with self._lock:
                self._cache[persisted.input_evidence_hash] = persisted
                self._inv_to_hash[investigation_id] = persisted.input_evidence_hash
            return persisted

        return await self.analyze_investigation(investigation_id)

    async def get_correlation(self, investigation_id: str) -> Optional[CorrelationResult]:
        await investigation_registry.ensure_seeded()
        forensic = investigation_registry.get_forensic(investigation_id)
        threat = investigation_registry.get_threat(investigation_id)
        intel = investigation_registry.get_intelligence(investigation_id)
        pkg = default_blockchain_service.store.get_package_by_investigation(investigation_id)
        evidence_id = pkg.evidence_id if pkg else "EVD-2026-00001"

        from app.services.investigations.service import default_case_service
        all_cases = await default_case_service.list_investigations()

        return correlate_investigation_evidence(
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            forensic=forensic,
            threat=threat,
            intel=intel,
            other_cases=all_cases,
        )

    async def get_related_cases(self, investigation_id: str) -> List[RelatedCase]:
        correlation = await self.get_correlation(investigation_id)
        return correlation.related_cases if correlation else []

    async def refresh_assessment(self, investigation_id: str) -> InvestigationAssessment:
        return await self.analyze_investigation(investigation_id, force_refresh=True)


default_ai_service = AIAnalystService()
