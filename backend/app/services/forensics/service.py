import os
import threading
from typing import Any, Dict, List, Optional

from app.core.logging import logger
from app.services.email import EmailForensicResult, analyze_email_bytes
from app.services.forensics.graph import build_attack_graph

from app.services.forensics.models import (
    AttackGraphResponse,
    TimelineEvent,
    TimelineEventType,
    TimelineResponse,
)
from app.services.forensics.timeline import build_forensic_timeline
from app.services.intelligence.models import InvestigationIntelligenceResult
from app.services.intelligence.service import default_intelligence_service
from app.services.risk import ThreatAssessmentResult, assess_email_threat



class InvestigationRegistry:
    """
    Thread-safe in-memory registry maintaining the forensic state,
    threat assessments, and intelligence enrichments for investigations.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._forensics: Dict[str, EmailForensicResult] = {}
        self._threats: Dict[str, ThreatAssessmentResult] = {}
        self._intelligence: Dict[str, InvestigationIntelligenceResult] = {}
        self._correlations: Dict[str, Any] = {}
        self._initialized = False

    def store(
        self,
        investigation_id: str,
        forensic: EmailForensicResult,
        threat: Optional[ThreatAssessmentResult] = None,
        intel: Optional[InvestigationIntelligenceResult] = None,
        correlation: Optional[Any] = None,
    ):
        with self._lock:
            self._forensics[investigation_id] = forensic
            if threat:
                self._threats[investigation_id] = threat
            if intel:
                self._intelligence[investigation_id] = intel
            if correlation:
                self._correlations[investigation_id] = correlation

    def get_forensic(self, investigation_id: str) -> Optional[EmailForensicResult]:
        with self._lock:
            return self._forensics.get(investigation_id)

    def get_threat(self, investigation_id: str) -> Optional[ThreatAssessmentResult]:
        with self._lock:
            return self._threats.get(investigation_id)

    def get_intelligence(self, investigation_id: str) -> Optional[InvestigationIntelligenceResult]:
        with self._lock:
            return self._intelligence.get(investigation_id)

    def get_correlation(self, investigation_id: str) -> Optional[Any]:
        with self._lock:
            return self._correlations.get(investigation_id)

    async def ensure_seeded(self):
        """Pre-seeds standard SIH demo investigation fixtures if not already loaded."""
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return
            self._initialized = True

        fixtures_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "tests", "fixtures")
        phishing_path = os.path.join(fixtures_dir, "sample_phishing.eml")
        clean_path = os.path.join(fixtures_dir, "valid_clean.eml")
        contra_path = os.path.join(fixtures_dir, "demo_contradictory.eml")
        incomplete_path = os.path.join(fixtures_dir, "demo_incomplete.eml")

        # Seed INV-2026-00001 (Demo 1: Phishing)
        if os.path.exists(phishing_path):
            try:
                with open(phishing_path, "rb") as f:
                    phish_bytes = f.read()
                forensic_1 = analyze_email_bytes(phish_bytes, original_filename="sample_phishing.eml")
                forensic_1.investigation_id = "INV-2026-00001"
                threat_1 = await assess_email_threat(forensic_1)
                threat_1.investigation_id = "INV-2026-00001"
                intel_1 = await default_intelligence_service.enrich_investigation(
                    investigation_id="INV-2026-00001",
                    ips=[hop.ip for hop in forensic_1.received_chain if hop.ip],
                    domains=[d.domain for d in forensic_1.domains],
                    urls=[u.normalized_url for u in forensic_1.urls],
                )
                corr_1 = await default_intelligence_service.correlate_investigation("INV-2026-00001", forensic_1, intel_1)
                self.store("INV-2026-00001", forensic_1, threat_1, intel_1, correlation=corr_1)
            except Exception as e:
                logger.warning(f"Failed to seed demo fixture INV-2026-00001: {e}")

        # Seed INV-2026-00003 (Demo 3: Contradictory Evidence)
        if os.path.exists(contra_path):
            try:
                with open(contra_path, "rb") as f:
                    contra_bytes = f.read()
                forensic_3 = analyze_email_bytes(contra_bytes, original_filename="demo_contradictory.eml")
                forensic_3.investigation_id = "INV-2026-00003"
                threat_3 = await assess_email_threat(forensic_3)
                threat_3.investigation_id = "INV-2026-00003"
                intel_3 = await default_intelligence_service.enrich_investigation(
                    investigation_id="INV-2026-00003",
                    ips=[hop.ip for hop in forensic_3.received_chain if hop.ip],
                    domains=[d.domain for d in forensic_3.domains],
                    urls=[u.normalized_url for u in forensic_3.urls],
                )
                corr_3 = await default_intelligence_service.correlate_investigation("INV-2026-00003", forensic_3, intel_3)
                self.store("INV-2026-00003", forensic_3, threat_3, intel_3, correlation=corr_3)
            except Exception as e:
                logger.warning(f"Failed to seed demo fixture INV-2026-00003: {e}")

        # Seed INV-2026-00004 (Demo 2: Clean)
        if os.path.exists(clean_path):
            try:
                with open(clean_path, "rb") as f:
                    clean_bytes = f.read()
                forensic_4 = analyze_email_bytes(clean_bytes, original_filename="valid_clean.eml")
                forensic_4.investigation_id = "INV-2026-00004"
                threat_4 = await assess_email_threat(forensic_4)
                threat_4.investigation_id = "INV-2026-00004"
                intel_4 = await default_intelligence_service.enrich_investigation(
                    investigation_id="INV-2026-00004",
                    ips=[hop.ip for hop in forensic_4.received_chain if hop.ip],
                    domains=[d.domain for d in forensic_4.domains],
                    urls=[u.normalized_url for u in forensic_4.urls],
                )
                corr_4 = await default_intelligence_service.correlate_investigation("INV-2026-00004", forensic_4, intel_4)
                self.store("INV-2026-00004", forensic_4, threat_4, intel_4, correlation=corr_4)
            except Exception as e:
                logger.warning(f"Failed to seed demo fixture INV-2026-00004: {e}")

        # Seed INV-2026-00005 (Demo 4: Incomplete Intelligence / Gaps)
        if os.path.exists(incomplete_path):
            try:
                with open(incomplete_path, "rb") as f:
                    inc_bytes = f.read()
                forensic_5 = analyze_email_bytes(inc_bytes, original_filename="demo_incomplete.eml")
                forensic_5.investigation_id = "INV-2026-00005"
                threat_5 = await assess_email_threat(forensic_5)
                threat_5.investigation_id = "INV-2026-00005"
                intel_5 = await default_intelligence_service.enrich_investigation(
                    investigation_id="INV-2026-00005",
                    ips=[hop.ip for hop in forensic_5.received_chain if hop.ip],
                    domains=[d.domain for d in forensic_5.domains],
                    urls=[u.normalized_url for u in forensic_5.urls],
                )
                corr_5 = await default_intelligence_service.correlate_investigation("INV-2026-00005", forensic_5, intel_5)
                self.store("INV-2026-00005", forensic_5, threat_5, intel_5, correlation=corr_5)
            except Exception as e:
                logger.warning(f"Failed to seed demo fixture INV-2026-00005: {e}")


investigation_registry = InvestigationRegistry()


class ForensicsService:
    """
    Coordinates forensic timeline generation and interactive attack graph construction.
    """

    def __init__(self, registry: Optional[InvestigationRegistry] = None):
        self.registry = registry or investigation_registry

    async def get_investigation_timeline(
        self,
        investigation_id: str,
        sort: str = "asc",
        severity_filter: Optional[str] = None,
        event_type_filter: Optional[str] = None,
    ) -> Optional[TimelineResponse]:
        await self.registry.ensure_seeded()
        forensic = self.registry.get_forensic(investigation_id)
        if not forensic:
            return None

        threat = self.registry.get_threat(investigation_id)
        intel = self.registry.get_intelligence(investigation_id)

        raw_events = build_forensic_timeline(forensic, threat, intel)

        # Apply filters
        filtered_events = raw_events
        if severity_filter:
            sev_upper = severity_filter.upper()
            filtered_events = [e for e in filtered_events if e.severity and e.severity.upper() == sev_upper]

        if event_type_filter:
            type_upper = event_type_filter.upper()
            filtered_events = [e for e in filtered_events if e.event_type.value == type_upper]

        # Apply sorting
        # Events with timestamps are sorted chronologically; events without are placed stably after
        def sort_key(e: TimelineEvent):
            return (0 if e.timestamp else 1, e.timestamp or "", e.event_id)

        is_reverse = sort.lower() == "desc"
        sorted_events = sorted(filtered_events, key=sort_key, reverse=is_reverse)

        return TimelineResponse(
            investigation_id=investigation_id,
            events=sorted_events,
            total_events=len(sorted_events),
        )

    async def get_investigation_graph(self, investigation_id: str) -> Optional[AttackGraphResponse]:
        await self.registry.ensure_seeded()
        forensic = self.registry.get_forensic(investigation_id)
        if not forensic:
            return None

        threat = self.registry.get_threat(investigation_id)
        intel = self.registry.get_intelligence(investigation_id)

        return build_attack_graph(forensic, threat, intel)


default_forensics_service = ForensicsService()
