from datetime import datetime, timezone
import threading
from typing import Dict, List, Optional

from app.services.blockchain.models import CustodyEvent, EvidencePackage


class BlockchainEvidenceStore:
    """
    Thread-safe storage manager for forensic evidence packages,
    tamper simulation copies, and chain of custody audit logs.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._packages: Dict[str, EvidencePackage] = {}  # evidence_id -> package
        self._inv_to_evd: Dict[str, str] = {}  # investigation_id -> evidence_id
        self._tampered_copies: Dict[str, EvidencePackage] = {}  # evidence_id -> tampered package copy
        self._custody_logs: Dict[str, List[CustodyEvent]] = {}  # investigation_id -> list of events

    def store_package(self, package: EvidencePackage):
        with self._lock:
            self._packages[package.evidence_id] = package
            self._inv_to_evd[package.investigation_id] = package.evidence_id
            
            # Record initial custody event if not already present
            if package.investigation_id not in self._custody_logs:
                self._custody_logs[package.investigation_id] = []
                self._add_custody_event_locked(
                    evidence_id=package.evidence_id,
                    investigation_id=package.investigation_id,
                    phase="INGESTION",
                    title="Evidence Package Created & Canonicalized",
                    actor="MAILSENTINEL-FORENSIC-ENGINE",
                    hash_reference=package.canonical_digest,
                )

    def get_package(self, evidence_id: str) -> Optional[EvidencePackage]:
        with self._lock:
            return self._packages.get(evidence_id)

    def get_package_by_investigation(self, investigation_id: str) -> Optional[EvidencePackage]:
        with self._lock:
            evd_id = self._inv_to_evd.get(investigation_id)
            if evd_id:
                return self._packages.get(evd_id)
            return None

    def store_tampered_copy(self, evidence_id: str, tampered: EvidencePackage):
        with self._lock:
            self._tampered_copies[evidence_id] = tampered
            self._add_custody_event_locked(
                evidence_id=evidence_id,
                investigation_id=tampered.investigation_id,
                phase="SIMULATION",
                title="Simulated Evidence Modification (Demo Testbed)",
                actor="SECURITY-ANALYST-DEMO",
                hash_reference=tampered.canonical_digest,
            )

    def get_effective_package(self, evidence_id: str) -> Optional[EvidencePackage]:
        """Returns the tampered copy if active simulation is running, else official package."""
        with self._lock:
            if evidence_id in self._tampered_copies:
                return self._tampered_copies[evidence_id]
            return self._packages.get(evidence_id)

    def clear_tamper_copy(self, evidence_id: str) -> Optional[EvidencePackage]:
        with self._lock:
            if evidence_id in self._tampered_copies:
                del self._tampered_copies[evidence_id]
            pkg = self._packages.get(evidence_id)
            if pkg:
                self._add_custody_event_locked(
                    evidence_id=evidence_id,
                    investigation_id=pkg.investigation_id,
                    phase="RESTORATION",
                    title="Evidence Restored to Original Authentic State",
                    actor="SECURITY-ANALYST-DEMO",
                    hash_reference=pkg.canonical_digest,
                )
            return pkg

    def is_tampered_active(self, evidence_id: str) -> bool:
        with self._lock:
            return evidence_id in self._tampered_copies

    def add_custody_event(
        self,
        evidence_id: str,
        investigation_id: str,
        phase: str,
        title: str,
        actor: str,
        hash_reference: Optional[str] = None,
    ):
        with self._lock:
            self._add_custody_event_locked(
                evidence_id, investigation_id, phase, title, actor, hash_reference
            )

    def _add_custody_event_locked(
        self,
        evidence_id: str,
        investigation_id: str,
        phase: str,
        title: str,
        actor: str,
        hash_reference: Optional[str] = None,
    ):
        if investigation_id not in self._custody_logs:
            self._custody_logs[investigation_id] = []

        event_seq = len(self._custody_logs[investigation_id]) + 1
        event = CustodyEvent(
            event_id=f"custody-{event_seq:03d}",
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=phase,
            title=title,
            actor=actor,
            hash_reference=hash_reference,
            status="RECORDED",
        )
        self._custody_logs[investigation_id].append(event)

    def get_custody_chain(self, investigation_id: str) -> List[CustodyEvent]:
        with self._lock:
            return list(self._custody_logs.get(investigation_id, []))


evidence_store = BlockchainEvidenceStore()
