import copy
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from app.core.logging import logger
from app.services.case_management.audit import AuditEventType, CaseAuditEvent
from app.services.case_management.models import (
    ActionStatus,
    ActionType,
    ArtifactType,
    CaseAction,
    CaseArtifact,
    CaseNote,
    CasePriority,
    CaseStatus,
    CaseTimelineEvent,
    IncidentCase,
    IncidentVerdict,
    NoteCategory,
)


class CaseRepository:
    """
    Thread-safe repository for IncidentCase records and immutable audit logs.
    Integrates with SQLite for durable persistence across restarts.
    """

    def __init__(self, persistence: Optional[Any] = None):
        self._lock = threading.Lock()
        self._cases: Dict[str, IncidentCase] = {}
        self._audit_logs: Dict[str, List[CaseAuditEvent]] = {}
        self._case_counter = 10
        self._note_counter = 100
        self._action_counter = 100
        self._artifact_counter = 100
        self._audit_counter = 100
        self._timeline_counter = 100
        self._initialized = False

        self._persistence = persistence

    @property
    def persistence(self):
        if self._persistence is None:
            from app.services.persistence.case_repository import default_case_sqlite_repository
            self._persistence = default_case_sqlite_repository
        return self._persistence

    def _extract_counter(self, text: Optional[str]) -> int:
        if not text:
            return 0
        digits = "".join(ch for ch in text.split("-")[-1] if ch.isdigit())
        return int(digits) if digits else 0

    def _update_counters_for_case(self, case: IncidentCase, audit_logs: Optional[List[CaseAuditEvent]] = None):
        self._case_counter = max(self._case_counter, self._extract_counter(case.case_id))
        for note in case.notes:
            self._note_counter = max(self._note_counter, self._extract_counter(note.note_id))
        for act in case.actions:
            self._action_counter = max(self._action_counter, self._extract_counter(act.action_id))
        for art in case.artifacts:
            self._artifact_counter = max(self._artifact_counter, self._extract_counter(art.artifact_id))
        for evt in case.timeline:
            self._timeline_counter = max(self._timeline_counter, self._extract_counter(evt.event_id))
        if audit_logs:
            for aud in audit_logs:
                self._audit_counter = max(self._audit_counter, self._extract_counter(aud.audit_id))

    def next_case_id(self) -> str:
        with self._lock:
            self._case_counter += 1
            return f"CASE-2026-{self._case_counter:05d}"

    def next_note_id(self) -> str:
        with self._lock:
            self._note_counter += 1
            return f"NOTE-{self._note_counter}"

    def next_action_id(self) -> str:
        with self._lock:
            self._action_counter += 1
            return f"ACT-{self._action_counter}"

    def next_artifact_id(self) -> str:
        with self._lock:
            self._artifact_counter += 1
            return f"ART-{self._artifact_counter}"

    def next_audit_id(self) -> str:
        with self._lock:
            self._audit_counter += 1
            return f"AUD-{self._audit_counter}"

    def next_timeline_id(self) -> str:
        with self._lock:
            self._timeline_counter += 1
            return f"EVT-{self._timeline_counter}"

    def save_case(self, case: IncidentCase) -> IncidentCase:
        with self._lock:
            case.updated_at = datetime.utcnow()
            self._cases[case.case_id] = copy.deepcopy(case)
            if case.case_id not in self._audit_logs:
                self._audit_logs[case.case_id] = []
            if self.persistence:
                try:
                    self.persistence.save_case(case, self._audit_logs[case.case_id])
                except Exception as e:
                    logger.error(f"Error persisting case {case.case_id} to SQLite: {e}")
            return copy.deepcopy(case)

    def get_case(self, case_id: str) -> Optional[IncidentCase]:
        with self._lock:
            case = self._cases.get(case_id)
            return copy.deepcopy(case) if case else None

    def get_case_by_investigation(self, investigation_id: str) -> Optional[IncidentCase]:
        with self._lock:
            for case in self._cases.values():
                if case.investigation_id == investigation_id:
                    return copy.deepcopy(case)
            return None

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        priority: Optional[CasePriority] = None,
        verdict: Optional[IncidentVerdict] = None,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        descending: bool = True,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[IncidentCase], int]:
        with self._lock:
            cases = list(self._cases.values())

        # Filtering
        if status:
            cases = [c for c in cases if c.status == status]
        if priority:
            cases = [c for c in cases if c.priority == priority]
        if verdict:
            cases = [c for c in cases if c.verdict == verdict]
        if search:
            q = search.lower()
            cases = [
                c
                for c in cases
                if q in c.case_id.lower()
                or q in c.investigation_id.lower()
                or q in c.title.lower()
                or q in (c.sender or "").lower()
                or q in (c.subject or "").lower()
                or any(q in t.lower() for t in c.tags)
            ]

        # Sorting
        if hasattr(IncidentCase, sort_by):
            cases.sort(key=lambda c: getattr(c, sort_by) or "", reverse=descending)
        else:
            cases.sort(key=lambda c: c.created_at, reverse=descending)

        total = len(cases)
        start = (page - 1) * page_size
        end = start + page_size
        paginated = [copy.deepcopy(c) for c in cases[start:end]]
        return paginated, total

    def delete_case(self, case_id: str) -> bool:
        with self._lock:
            if case_id in self._cases:
                del self._cases[case_id]
                self._audit_logs.pop(case_id, None)
                if self.persistence:
                    try:
                        self.persistence.delete_case(case_id)
                    except Exception as e:
                        logger.error(f"Error deleting case {case_id} from SQLite: {e}")
                return True
            return False

    def append_audit_event(self, event: CaseAuditEvent):
        with self._lock:
            if event.case_id not in self._audit_logs:
                self._audit_logs[event.case_id] = []
            self._audit_logs[event.case_id].append(copy.deepcopy(event))
            if self.persistence:
                try:
                    self.persistence.append_audit_event(event)
                except Exception as e:
                    logger.error(f"Error persisting audit event {event.audit_id} to SQLite: {e}")

    def get_audit_trail(self, case_id: str) -> List[CaseAuditEvent]:
        with self._lock:
            logs = self._audit_logs.get(case_id, [])
            return copy.deepcopy(logs)

    def ensure_seeded(self):
        """Initializes default SIH demonstration incident cases."""
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return
            self._initialized = True

            # Rehydrate from SQLite if records exist
            if self.persistence:
                try:
                    persisted = self.persistence.list_all_cases()
                    if persisted:
                        for case, audit_logs in persisted:
                            self._cases[case.case_id] = case
                            self._audit_logs[case.case_id] = audit_logs
                            self._update_counters_for_case(case, audit_logs)
                        logger.info(f"Rehydrated {len(persisted)} incident cases from SQLite.")
                        return
                except Exception as e:
                    logger.warning(f"Failed to load persisted cases from SQLite: {e}")

            now = datetime.utcnow()

            # Case 1: High-Risk BEC Phishing (from INV-2026-00001)
            c1_id = "CASE-2026-00001"
            c1 = IncidentCase(
                case_id=c1_id,
                investigation_id="INV-2026-00001",
                title="Executive Wire Fraud Impersonation via Lookalike Domain",
                description="Targeted executive wire transfer request originating from homoglyph domain paypa1-security.com with SPF/DMARC failure and urgent payment instructions.",
                status=CaseStatus.INVESTIGATING,
                priority=CasePriority.P1_CRITICAL,
                verdict=IncidentVerdict.MALICIOUS,
                created_at=now - timedelta(hours=2),
                updated_at=now - timedelta(minutes=15),
                assigned_analyst="SOC-L2-ANALYST",
                tags=["BEC", "WireFraud", "LookalikeDomain", "UrgentPayment", "C-SuiteTarget"],
                risk_score=94,
                severity="CRITICAL",
                classification="BUSINESS_EMAIL_COMPROMISE",
                confidence=95,
                evidence_hash="7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
                evidence_id="EVD-2026-00001",
                blockchain_verified=True,
                blockchain_block=1042,
                blockchain_tx="0x83f9a2b1c4e720d58f310492e8ca55172b9a4c3f81e095da124376fb40192e47",
                sender="executive-desk@paypa1-security.com",
                subject="URGENT: Outstanding Acquisition Wire Authorization Required",
                artifacts=[
                    CaseArtifact(
                        artifact_id="ART-001",
                        artifact_type=ArtifactType.EMAIL,
                        name="Raw EML Container",
                        reference_id="sample_phishing.eml",
                        sha256="7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
                        description="Ingested RFC 5322 MIME container from perimeter email gateway.",
                    ),
                    CaseArtifact(
                        artifact_id="ART-002",
                        artifact_type=ArtifactType.DOMAIN,
                        name="Lookalike Sender Domain",
                        reference_id="paypa1-security.com",
                        description="Homoglyph impersonation domain with Levenshtein distance 1 to paypal.com.",
                    ),
                    CaseArtifact(
                        artifact_id="ART-003",
                        artifact_type=ArtifactType.IP,
                        name="Observed SMTP Relay Node",
                        reference_id="185.220.101.5",
                        description="Amsterdam hosting node, ASN 60781, flagged for bulletproof hosting.",
                    ),
                    CaseArtifact(
                        artifact_id="ART-004",
                        artifact_type=ArtifactType.ATTACHMENT,
                        name="Double Extension File",
                        reference_id="Urgent_Invoice_Doc.pdf.html",
                        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        description="HTML disguised with double extension attempting credential harvesting.",
                    ),
                    CaseArtifact(
                        artifact_id="ART-005",
                        artifact_type=ArtifactType.BLOCKCHAIN_ANCHOR,
                        name="Cryptographic Evidence Proof",
                        reference_id="0x83f9a2b1c4e720d58f310492e8ca55172b9a4c3f81e095da124376fb40192e47",
                        description="Anchored on MAILSENTINEL-DEMO-CHAIN at Block #1042.",
                    ),
                ],
                actions=[
                    CaseAction(
                        action_id="ACT-001",
                        case_id=c1_id,
                        type=ActionType.PRESERVE_EVIDENCE,
                        title="Preserve Immutable Evidence Digest",
                        description="Compute SHA-256 evidence fingerprint and anchor on-chain for forensic integrity.",
                        priority=CasePriority.P1_CRITICAL,
                        status=ActionStatus.COMPLETED,
                        created_at=now - timedelta(hours=2),
                        completed_at=now - timedelta(hours=2),
                        actor="SYSTEM_AUTO_TRIAGE",
                    ),
                    CaseAction(
                        action_id="ACT-002",
                        case_id=c1_id,
                        type=ActionType.BLOCK_DOMAIN,
                        title="Block Sender Domain 'paypa1-security.com'",
                        description="Add homoglyph domain to perimeter mail gateway and DNS sinkhole.",
                        priority=CasePriority.P1_CRITICAL,
                        status=ActionStatus.APPROVED,
                        created_at=now - timedelta(hours=1, minutes=45),
                        actor="SOC-L2-ANALYST",
                    ),
                    CaseAction(
                        action_id="ACT-003",
                        case_id=c1_id,
                        type=ActionType.BLOCK_IP,
                        title="Sinkhole Suspect IP 185.220.101.5",
                        description="Block originating VPS node at perimeter firewall boundaries.",
                        priority=CasePriority.P2_HIGH,
                        status=ActionStatus.IN_PROGRESS,
                        created_at=now - timedelta(hours=1, minutes=30),
                        actor="SOC-L2-ANALYST",
                    ),
                    CaseAction(
                        action_id="ACT-004",
                        case_id=c1_id,
                        type=ActionType.NOTIFY_USER,
                        title="Alert Targeted Finance Personnel",
                        description="Notify recipient of fraudulent wire transfer attempt and confirm no funds were disbursed.",
                        priority=CasePriority.P1_CRITICAL,
                        status=ActionStatus.COMPLETED,
                        created_at=now - timedelta(hours=1),
                        completed_at=now - timedelta(minutes=45),
                        actor="SOC-L2-ANALYST",
                    ),
                ],
                notes=[
                    CaseNote(
                        note_id="NOTE-001",
                        case_id=c1_id,
                        timestamp=now - timedelta(hours=2),
                        author="SOC_INGEST_GATEWAY",
                        content="Case created automatically from high-risk investigation INV-2026-00001.",
                        category=NoteCategory.OBSERVATION,
                    ),
                    CaseNote(
                        note_id="NOTE-002",
                        case_id=c1_id,
                        timestamp=now - timedelta(hours=1, minutes=30),
                        author="SOC-L2-ANALYST",
                        content="Lookalike domain paypa1-security.com verified as unregistered to PayPal Inc. Reply-To points to suspicious external mailbox.",
                        category=NoteCategory.ANALYSIS,
                    ),
                ],
                timeline=[
                    CaseTimelineEvent(
                        event_id="EVT-001",
                        timestamp=now - timedelta(hours=2),
                        event_type="CASE_CREATED",
                        title="Incident Case Opened",
                        description="Incident case initialized from automated triage pipeline.",
                        actor="SYSTEM_AUTO_TRIAGE",
                    ),
                    CaseTimelineEvent(
                        event_id="EVT-002",
                        timestamp=now - timedelta(hours=1, minutes=45),
                        event_type="ACTION_PROPOSED",
                        title="Containment Action Proposed",
                        description="Proposed gateway block on paypa1-security.com.",
                        actor="SOC-L2-ANALYST",
                    ),
                ],
            )
            self._cases[c1_id] = c1
            self._audit_logs[c1_id] = [
                CaseAuditEvent(
                    audit_id="AUD-001",
                    timestamp=now - timedelta(hours=2),
                    case_id=c1_id,
                    event_type=AuditEventType.CASE_CREATED,
                    actor="SYSTEM_AUTO_TRIAGE",
                    description="Incident Case CASE-2026-00001 created from investigation INV-2026-00001.",
                ),
                CaseAuditEvent(
                    audit_id="AUD-002",
                    timestamp=now - timedelta(hours=1, minutes=45),
                    case_id=c1_id,
                    event_type=AuditEventType.STATUS_CHANGED,
                    actor="SOC-L2-ANALYST",
                    description="Status transitioned from NEW to INVESTIGATING.",
                    previous_value="NEW",
                    new_value="INVESTIGATING",
                ),
            ]

            # Case 2: Credential Phishing Campaign (from INV-2026-00002)
            c2_id = "CASE-2026-00002"
            c2 = IncidentCase(
                case_id=c2_id,
                investigation_id="INV-2026-00002",
                title="M365 Password Expiry Fake Portal Harvesting Campaign",
                description="Mass employee credential harvesting campaign leveraging spoofed Microsoft login portal.",
                status=CaseStatus.CONTAINMENT,
                priority=CasePriority.P2_HIGH,
                verdict=IncidentVerdict.MALICIOUS,
                created_at=now - timedelta(hours=4),
                updated_at=now - timedelta(hours=1),
                assigned_analyst="SOC-IR-TIER2",
                tags=["CredentialTheft", "PhishingURL", "M365Spoof"],
                risk_score=86,
                severity="HIGH",
                classification="CREDENTIAL_HARVESTING",
                confidence=92,
                evidence_hash="3b9a1c8f4d2e7a0b5c8e1f3a6d9b2c4e7f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c",
                evidence_id="EVD-2026-00002",
                blockchain_verified=True,
                blockchain_block=1043,
                blockchain_tx="0x94a2b1c8f3e720d58f310492e8ca55172b9a4c3f81e095da124376fb40192e48",
                sender="admin-alerts@secure-m365-verify.com",
                subject="Action Required: Microsoft 365 Password Expiration in 24 Hours",
            )
            self._cases[c2_id] = c2
            self._audit_logs[c2_id] = [
                CaseAuditEvent(
                    audit_id="AUD-003",
                    timestamp=now - timedelta(hours=4),
                    case_id=c2_id,
                    event_type=AuditEventType.CASE_CREATED,
                    actor="SYSTEM_AUTO_TRIAGE",
                    description="Incident Case CASE-2026-00002 created from investigation INV-2026-00002.",
                ),
            ]

            # Case 3: Clean Corporate Newsletter (from INV-2026-00004)
            c3_id = "CASE-2026-00004"
            c3 = IncidentCase(
                case_id=c3_id,
                investigation_id="INV-2026-00004",
                title="Monthly Partner Performance Service Update",
                description="Routine verified benign partner status update email with passing SPF/DKIM/DMARC.",
                status=CaseStatus.CLOSED,
                priority=CasePriority.P4_LOW,
                verdict=IncidentVerdict.BENIGN,
                created_at=now - timedelta(days=1),
                updated_at=now - timedelta(hours=20),
                closed_at=now - timedelta(hours=20),
                assigned_analyst="SOC-L1-ANALYST",
                tags=["Benign", "Newsletter", "DKIM_Pass"],
                risk_score=4,
                severity="CLEAN",
                classification="BENIGN",
                confidence=99,
                evidence_hash="8d9a1c8f4d2e7a0b5c8e1f3a6d9b2c4e7f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4d",
                evidence_id="EVD-2026-00004",
                blockchain_verified=True,
                blockchain_block=1045,
                blockchain_tx="0x72a2b1c8f3e720d58f310492e8ca55172b9a4c3f81e095da124376fb40192e49",
                sender="notifications@partner-service.com",
                subject="Monthly Service Performance Metrics Summary",
                closure_reason="Verified clean email with passing cryptographic authentication and zero IOCs.",
                lessons_learned="Standard legitimate traffic pattern.",
            )
            self._cases[c3_id] = c3
            self._audit_logs[c3_id] = [
                CaseAuditEvent(
                    audit_id="AUD-004",
                    timestamp=now - timedelta(days=1),
                    case_id=c3_id,
                    event_type=AuditEventType.CASE_CREATED,
                    actor="SYSTEM_AUTO_TRIAGE",
                    description="Case CASE-2026-00004 opened.",
                ),
                CaseAuditEvent(
                    audit_id="AUD-005",
                    timestamp=now - timedelta(hours=20),
                    case_id=c3_id,
                    event_type=AuditEventType.CASE_CLOSED,
                    actor="SOC-L1-ANALYST",
                    description="Case closed with verdict BENIGN. Reason: Verified clean email.",
                ),
            ]

            # Persist seeded demo cases to SQLite
            if self.persistence:
                try:
                    for cid, case_obj in self._cases.items():
                        self.persistence.save_case(case_obj, self._audit_logs.get(cid, []))
                except Exception as e:
                    logger.warning(f"Failed to persist initial seed cases to SQLite: {e}")


# Singleton repository instance
default_case_repository = CaseRepository()
