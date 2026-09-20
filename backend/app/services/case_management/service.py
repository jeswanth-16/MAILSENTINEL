from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

from app.core.logging import logger
from app.services.ai.service import default_ai_service
from app.services.blockchain.service import default_blockchain_service
from app.services.case_management.audit import AuditEventType, CaseAuditEvent
from app.services.case_management.models import (
    ActionStatus,
    ActionType,
    ArtifactType,
    CaseAction,
    CaseArtifact,
    CaseMetrics,
    CaseNote,
    CasePriority,
    CaseStatus,
    CaseTimelineEvent,
    IncidentCase,
    IncidentVerdict,
    NoteCategory,
)
from app.services.case_management.repository import CaseRepository, default_case_repository
from app.services.case_management.workflow import (
    InvalidCaseStateTransitionError,
    validate_status_transition,
)
from app.services.forensics.service import investigation_registry
from app.services.investigations.service import default_case_service as investigation_service


class IncidentCaseManagementService:
    """
    Central orchestration service for SOC Incident Response & Case Management.
    """

    def __init__(self, repository: Optional[CaseRepository] = None):
        self.repo = repository or default_case_repository

    async def ensure_seeded(self):
        """Ensures all prerequisite registries and demo cases are initialized."""
        await investigation_registry.ensure_seeded()
        await default_blockchain_service.ensure_seeded()
        await investigation_service.ensure_seeded()
        self.repo.ensure_seeded()

    async def create_case_from_investigation(
        self,
        investigation_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        priority: Optional[CasePriority] = None,
        assigned_analyst: str = "SOC-L2-ANALYST",
        tags: Optional[List[str]] = None,
        actor: str = "SOC Analyst",
    ) -> IncidentCase:
        """
        Creates an IncidentCase from an existing Investigation without duplicating large evidence.
        Inherits references to forensic artifacts, threat indicators, timeline, graph, blockchain proof, and AI assessment.
        """
        await self.ensure_seeded()

        # Check if a case already exists for this investigation
        existing = self.repo.get_case_by_investigation(investigation_id)
        if existing:
            return existing

        # Fetch investigation details
        inv = await investigation_service.get_investigation(investigation_id)
        forensic = investigation_registry.get_forensic(investigation_id)
        threat = investigation_registry.get_threat(investigation_id)
        intel = investigation_registry.get_intelligence(investigation_id)

        case_id = self.repo.next_case_id()
        now = datetime.utcnow()

        # Determine default priority & verdict from threat score
        risk_score = threat.risk_score if threat else (inv.risk_score if inv else 0)
        severity = threat.severity.value if threat and hasattr(threat.severity, "value") else (inv.severity.value if inv and hasattr(inv.severity, "value") else "MEDIUM")
        classification = threat.classification.value if threat and hasattr(threat.classification, "value") else (inv.classification.value if inv and hasattr(inv.classification, "value") else "SUSPICIOUS")
        confidence = threat.confidence_percentage if threat else (inv.confidence if inv else 85)
        evidence_hash = inv.evidence_hash if inv else (forensic.sha256_digest if forensic else "")
        evidence_id = inv.evidence_id if inv else f"EVD-{investigation_id}"
        sender = forensic.metadata.from_address if forensic and forensic.metadata else (inv.sender if inv else "")
        subject = forensic.metadata.subject if forensic and forensic.metadata else (inv.subject if inv else "")

        if not priority:
            if risk_score >= 80:
                priority = CasePriority.P1_CRITICAL
            elif risk_score >= 50:
                priority = CasePriority.P2_HIGH
            elif risk_score >= 20:
                priority = CasePriority.P3_MEDIUM
            else:
                priority = CasePriority.P4_LOW

        verdict = None
        if not verdict:
            try:
                from app.services.ai.service import default_ai_service
                assessment = await default_ai_service.get_assessment(investigation_id)
                if assessment and assessment.verdict:
                    v_name = assessment.verdict.value if hasattr(assessment.verdict, "value") else str(assessment.verdict)
                    verdict = getattr(IncidentVerdict, v_name, None)
            except Exception:
                verdict = None

        if not verdict:
            if risk_score >= 80:
                verdict = IncidentVerdict.MALICIOUS
            elif risk_score >= 60:
                verdict = IncidentVerdict.HIGH_RISK
            elif risk_score >= 30:
                verdict = IncidentVerdict.SUSPICIOUS
            elif risk_score >= 15:
                verdict = IncidentVerdict.LOW_RISK
            else:
                verdict = IncidentVerdict.BENIGN

        case_title = title or (inv.title if inv else f"Incident Case for {investigation_id}")
        case_desc = description or (inv.description if inv else f"Automated SOC incident case created from {investigation_id}.")

        case_tags = list(set((tags or []) + (inv.tags if inv else []) + [classification, severity]))

        # Construct referenced artifacts
        artifacts: List[CaseArtifact] = []

        if forensic:
            fname = getattr(forensic, "file_name", None) or getattr(forensic, "filename", None) or "email.eml"
            ev_id = getattr(forensic, "evidence_id", None) or evidence_id
            f_size = getattr(forensic, "file_size_bytes", getattr(forensic, "size_bytes", 0))
            f_mime = getattr(getattr(forensic, "metadata", None), "content_type", "message/rfc822")
            artifacts.append(
                CaseArtifact(
                    artifact_id=self.repo.next_artifact_id(),
                    artifact_type=ArtifactType.EMAIL,
                    name=f"RFC 5322 MIME Container ({fname})",
                    reference_id=ev_id,
                    sha256=forensic.sha256_digest,
                    description=f"Raw email from {sender} with subject '{subject}'",
                    metadata={"size_bytes": f_size, "mime_type": f_mime},
                )
            )
            # Add Domain artifacts
            for d in forensic.domains[:3]:
                artifacts.append(
                    CaseArtifact(
                        artifact_id=self.repo.next_artifact_id(),
                        artifact_type=ArtifactType.DOMAIN,
                        name=f"Observed Domain: {d.domain}",
                        reference_id=d.domain,
                        description=f"Domain observed with {getattr(d, 'occurrence_count', 1)} occurrences.",
                        metadata={"is_lookalike": getattr(d, "is_lookalike", False), "impersonated": getattr(d, "target_brand", None)},
                    )
                )
            # Add IP artifacts
            extracted_ips = getattr(forensic, "ip_addresses", None) or getattr(forensic, "ips", [])
            for ip in extracted_ips[:3]:
                ip_val = getattr(ip, "ip", str(ip))
                ip_type_desc = getattr(ip, "ip_type", getattr(ip, "source", "SMTP_RELAY"))
                artifacts.append(
                    CaseArtifact(
                        artifact_id=self.repo.next_artifact_id(),
                        artifact_type=ArtifactType.IP,
                        name=f"Observed IP: {ip_val}",
                        reference_id=ip_val,
                        description=f"Hop relay IP extracted from Received headers (Type: {ip_type_desc}).",
                    )
                )
            # Add Attachments
            for att in forensic.attachments:
                artifacts.append(
                    CaseArtifact(
                        artifact_id=self.repo.next_artifact_id(),
                        artifact_type=ArtifactType.ATTACHMENT,
                        name=f"Attachment: {att.filename}",
                        reference_id=att.filename,
                        sha256=att.sha256,
                        description=f"File extension: {att.extension}, size: {att.size_bytes} bytes.",
                        metadata={"mime_type": att.mime_type, "double_extension": getattr(att, "has_double_extension", False)},
                    )
                )

        if inv and inv.blockchain_tx:
            artifacts.append(
                CaseArtifact(
                    artifact_id=self.repo.next_artifact_id(),
                    artifact_type=ArtifactType.BLOCKCHAIN_ANCHOR,
                    name=f"Blockchain Cryptographic Anchor (Block #{inv.blockchain_block})",
                    reference_id=inv.blockchain_tx,
                    description=f"Anchored on {inv.blockchain_network} with evidence hash {inv.evidence_hash}.",
                    metadata={"block": inv.blockchain_block, "network": inv.blockchain_network},
                )
            )

        # Standard Proposed Response Actions
        actions: List[CaseAction] = [
            CaseAction(
                action_id=self.repo.next_action_id(),
                case_id=case_id,
                type=ActionType.PRESERVE_EVIDENCE,
                title="Preserve Immutable Evidence Digest",
                description="Verify canonical SHA-256 fingerprint against the blockchain ledger.",
                priority=CasePriority.P1_CRITICAL,
                status=ActionStatus.COMPLETED if (inv and inv.blockchain_verified) else ActionStatus.PROPOSED,
                created_at=now,
                completed_at=now if (inv and inv.blockchain_verified) else None,
                actor=actor,
                evidence_reference=evidence_hash,
            )
        ]

        if risk_score >= 50:
            actions.append(
                CaseAction(
                    action_id=self.repo.next_action_id(),
                    case_id=case_id,
                    type=ActionType.BLOCK_DOMAIN,
                    title=f"Block Sender Domain at Mail Gateway",
                    description=f"Add sender domain or lookalike target to perimeter gateway filter rules.",
                    priority=CasePriority.P1_CRITICAL if risk_score >= 80 else CasePriority.P2_HIGH,
                    status=ActionStatus.PROPOSED,
                    created_at=now,
                    actor=actor,
                )
            )
            actions.append(
                CaseAction(
                    action_id=self.repo.next_action_id(),
                    case_id=case_id,
                    type=ActionType.QUARANTINE_EMAIL,
                    title="Quarantine Message in User Mailboxes",
                    description="Issue mailbox quarantine rule for matching Message-ID and sender address.",
                    priority=CasePriority.P1_CRITICAL if risk_score >= 80 else CasePriority.P2_HIGH,
                    status=ActionStatus.PROPOSED,
                    created_at=now,
                    actor=actor,
                )
            )

        if risk_score >= 80:
            actions.append(
                CaseAction(
                    action_id=self.repo.next_action_id(),
                    case_id=case_id,
                    type=ActionType.NOTIFY_SOC,
                    title="Notify Tier-3 Incident Response Team",
                    description="Escalate high-severity incident to senior incident commanders for coordinated containment.",
                    priority=CasePriority.P1_CRITICAL,
                    status=ActionStatus.PROPOSED,
                    created_at=now,
                    actor=actor,
                )
            )

        # Timeline
        timeline: List[CaseTimelineEvent] = [
            CaseTimelineEvent(
                event_id=self.repo.next_timeline_id(),
                timestamp=now,
                event_type="CASE_CREATED",
                title="Incident Case Opened",
                description=f"Incident Case {case_id} initialized from investigation {investigation_id}.",
                actor=actor,
            )
        ]

        # Initial Note
        notes: List[CaseNote] = [
            CaseNote(
                note_id=self.repo.next_note_id(),
                case_id=case_id,
                timestamp=now,
                author=actor,
                content=f"Case created from investigation {investigation_id}. Risk Score: {risk_score}/100, Verdict: {verdict.value}.",
                category=NoteCategory.OBSERVATION,
            )
        ]

        case = IncidentCase(
            case_id=case_id,
            investigation_id=investigation_id,
            title=case_title,
            description=case_desc,
            status=CaseStatus.INVESTIGATING if risk_score >= 50 else CaseStatus.TRIAGING,
            priority=priority,
            verdict=verdict,
            created_at=now,
            updated_at=now,
            assigned_analyst=assigned_analyst,
            tags=case_tags,
            notes=notes,
            artifacts=artifacts,
            actions=actions,
            timeline=timeline,
            risk_score=risk_score,
            severity=severity,
            classification=classification,
            confidence=confidence,
            evidence_hash=evidence_hash,
            evidence_id=evidence_id,
            blockchain_verified=inv.blockchain_verified if inv else False,
            blockchain_block=inv.blockchain_block if inv else None,
            blockchain_tx=inv.blockchain_tx if inv else None,
            sender=sender,
            subject=subject,
        )

        saved = self.repo.save_case(case)

        # Record audit event
        self.repo.append_audit_event(
            CaseAuditEvent(
                audit_id=self.repo.next_audit_id(),
                timestamp=now,
                case_id=case_id,
                event_type=AuditEventType.CASE_CREATED,
                actor=actor,
                description=f"Incident Case {case_id} created from investigation {investigation_id}.",
                new_value=saved.status.value,
                related_evidence=evidence_hash,
            )
        )

        return saved

    async def get_case(self, case_id: str) -> Optional[IncidentCase]:
        await self.ensure_seeded()
        return self.repo.get_case(case_id)

    async def list_cases(
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
        await self.ensure_seeded()
        return self.repo.list_cases(
            status=status,
            priority=priority,
            verdict=verdict,
            search=search,
            sort_by=sort_by,
            descending=descending,
            page=page,
            page_size=page_size,
        )

    async def update_case(
        self,
        case_id: str,
        updates: Dict[str, Any],
        actor: str = "SOC Analyst",
    ) -> Optional[IncidentCase]:
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            return None

        now = datetime.utcnow()

        if "title" in updates and updates["title"]:
            case.title = updates["title"]
        if "description" in updates and updates["description"] is not None:
            case.description = updates["description"]
        if "priority" in updates and updates["priority"]:
            old_prio = case.priority
            case.priority = updates["priority"]
            self.repo.append_audit_event(
                CaseAuditEvent(
                    audit_id=self.repo.next_audit_id(),
                    timestamp=now,
                    case_id=case_id,
                    event_type=AuditEventType.STATUS_CHANGED,
                    actor=actor,
                    description=f"Priority changed from {old_prio.value} to {case.priority.value}.",
                    previous_value=old_prio.value,
                    new_value=case.priority.value,
                )
            )
        if "assigned_analyst" in updates and updates["assigned_analyst"]:
            old_analyst = case.assigned_analyst
            case.assigned_analyst = updates["assigned_analyst"]
            self.repo.append_audit_event(
                CaseAuditEvent(
                    audit_id=self.repo.next_audit_id(),
                    timestamp=now,
                    case_id=case_id,
                    event_type=AuditEventType.ASSIGNMENT_CHANGED,
                    actor=actor,
                    description=f"Assigned analyst changed from {old_analyst} to {case.assigned_analyst}.",
                    previous_value=old_analyst,
                    new_value=case.assigned_analyst,
                )
            )
        if "tags" in updates and updates["tags"] is not None:
            case.tags = updates["tags"]
        if "verdict" in updates and updates["verdict"]:
            case.verdict = updates["verdict"]

        case.updated_at = now
        return self.repo.save_case(case)

    async def transition_status(
        self,
        case_id: str,
        new_status: CaseStatus,
        reason: str,
        actor: str = "SOC Analyst",
    ) -> IncidentCase:
        """
        Transitions case status through controlled state validation and appends an audit event.
        """
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        is_valid, msg = validate_status_transition(case.status, new_status)
        if not is_valid:
            raise InvalidCaseStateTransitionError(msg)

        old_status = case.status
        case.status = new_status
        now = datetime.utcnow()
        case.updated_at = now

        if new_status == CaseStatus.CLOSED and not case.closed_at:
            case.closed_at = now
            if reason:
                case.closure_reason = reason

        # Append audit event
        self.repo.append_audit_event(
            CaseAuditEvent(
                audit_id=self.repo.next_audit_id(),
                timestamp=now,
                case_id=case_id,
                event_type=AuditEventType.STATUS_CHANGED if new_status != CaseStatus.CLOSED else AuditEventType.CASE_CLOSED,
                actor=actor,
                description=f"Status transitioned from {old_status.value} to {new_status.value}. Reason: {reason}",
                previous_value=old_status.value,
                new_value=new_status.value,
            )
        )

        # Timeline event
        case.timeline.append(
            CaseTimelineEvent(
                event_id=self.repo.next_timeline_id(),
                timestamp=now,
                event_type="STATUS_CHANGED",
                title=f"Status: {new_status.value}",
                description=f"Transitioned by {actor}. Reason: {reason}",
                actor=actor,
            )
        )

        return self.repo.save_case(case)

    async def assign_analyst(
        self,
        case_id: str,
        analyst: str,
        actor: str = "SOC Lead",
    ) -> IncidentCase:
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        old_analyst = case.assigned_analyst
        case.assigned_analyst = analyst
        now = datetime.utcnow()
        case.updated_at = now

        if case.status == CaseStatus.NEW:
            case.status = CaseStatus.TRIAGING

        self.repo.append_audit_event(
            CaseAuditEvent(
                audit_id=self.repo.next_audit_id(),
                timestamp=now,
                case_id=case_id,
                event_type=AuditEventType.ASSIGNMENT_CHANGED,
                actor=actor,
                description=f"Case assigned to {analyst} (Previous: {old_analyst}).",
                previous_value=old_analyst,
                new_value=analyst,
            )
        )

        case.notes.append(
            CaseNote(
                note_id=self.repo.next_note_id(),
                case_id=case_id,
                timestamp=now,
                author=actor,
                content=f"Case assigned to {analyst}.",
                category=NoteCategory.HANDOFF,
            )
        )

        return self.repo.save_case(case)

    async def add_note(
        self,
        case_id: str,
        content: str,
        author: str = "SOC Analyst",
        category: NoteCategory = NoteCategory.OBSERVATION,
    ) -> CaseNote:
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        now = datetime.utcnow()
        note = CaseNote(
            note_id=self.repo.next_note_id(),
            case_id=case_id,
            timestamp=now,
            author=author,
            content=content,
            category=category,
        )
        case.notes.append(note)
        case.updated_at = now
        self.repo.save_case(case)

        self.repo.append_audit_event(
            CaseAuditEvent(
                audit_id=self.repo.next_audit_id(),
                timestamp=now,
                case_id=case_id,
                event_type=AuditEventType.NOTE_ADDED,
                actor=author,
                description=f"Note added ({category.value}): {content[:60]}...",
                metadata={"note_id": note.note_id, "category": category.value},
            )
        )

        return note

    async def delete_note(
        self,
        case_id: str,
        note_id: str,
        actor: str = "SOC Analyst",
    ) -> bool:
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            return False

        init_len = len(case.notes)
        case.notes = [n for n in case.notes if n.note_id != note_id]
        if len(case.notes) < init_len:
            case.updated_at = datetime.utcnow()
            self.repo.save_case(case)
            self.repo.append_audit_event(
                CaseAuditEvent(
                    audit_id=self.repo.next_audit_id(),
                    timestamp=datetime.utcnow(),
                    case_id=case_id,
                    event_type=AuditEventType.NOTE_DELETED,
                    actor=actor,
                    description=f"Note {note_id} deleted.",
                    metadata={"note_id": note_id},
                )
            )
            return True
        return False

    async def add_tag(
        self,
        case_id: str,
        tag: str,
        actor: str = "SOC Analyst",
    ) -> IncidentCase:
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        if tag not in case.tags:
            case.tags.append(tag)
            case.updated_at = datetime.utcnow()
            self.repo.save_case(case)
            self.repo.append_audit_event(
                CaseAuditEvent(
                    audit_id=self.repo.next_audit_id(),
                    timestamp=datetime.utcnow(),
                    case_id=case_id,
                    event_type=AuditEventType.TAG_ADDED,
                    actor=actor,
                    description=f"Tag '{tag}' added to case.",
                    new_value=tag,
                )
            )
        return case

    async def remove_tag(
        self,
        case_id: str,
        tag: str,
        actor: str = "SOC Analyst",
    ) -> IncidentCase:
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        if tag in case.tags:
            case.tags = [t for t in case.tags if t != tag]
            case.updated_at = datetime.utcnow()
            self.repo.save_case(case)
            self.repo.append_audit_event(
                CaseAuditEvent(
                    audit_id=self.repo.next_audit_id(),
                    timestamp=datetime.utcnow(),
                    case_id=case_id,
                    event_type=AuditEventType.TAG_REMOVED,
                    actor=actor,
                    description=f"Tag '{tag}' removed from case.",
                    previous_value=tag,
                )
            )
        return case

    async def create_action(
        self,
        case_id: str,
        action_type: ActionType,
        title: str,
        description: str,
        priority: CasePriority = CasePriority.P2_HIGH,
        actor: str = "SOC Analyst",
        evidence_reference: Optional[str] = None,
    ) -> CaseAction:
        """Creates a standardized analyst workflow action record."""
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        now = datetime.utcnow()
        action = CaseAction(
            action_id=self.repo.next_action_id(),
            case_id=case_id,
            type=action_type,
            title=title,
            description=description,
            priority=priority,
            status=ActionStatus.PROPOSED,
            created_at=now,
            actor=actor,
            evidence_reference=evidence_reference,
        )

        case.actions.append(action)
        case.updated_at = now
        self.repo.save_case(case)

        self.repo.append_audit_event(
            CaseAuditEvent(
                audit_id=self.repo.next_audit_id(),
                timestamp=now,
                case_id=case_id,
                event_type=AuditEventType.ACTION_CREATED,
                actor=actor,
                description=f"Action proposed ({action_type.value}): {title}",
                metadata={"action_id": action.action_id, "type": action_type.value},
            )
        )

        return action

    async def update_action_status(
        self,
        case_id: str,
        action_id: str,
        status: ActionStatus,
        actor: str = "SOC Lead",
        notes: Optional[str] = None,
    ) -> CaseAction:
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        target_action = None
        for act in case.actions:
            if act.action_id == action_id:
                target_action = act
                break

        if not target_action:
            raise KeyError(f"Action '{action_id}' not found in case '{case_id}'.")

        old_status = target_action.status
        target_action.status = status
        now = datetime.utcnow()
        if status == ActionStatus.COMPLETED:
            target_action.completed_at = now
        if notes:
            target_action.notes = notes

        case.updated_at = now
        self.repo.save_case(case)

        event_type = AuditEventType.ACTION_APPROVED if status == ActionStatus.APPROVED else (
            AuditEventType.ACTION_COMPLETED if status == ActionStatus.COMPLETED else (
                AuditEventType.ACTION_REJECTED if status == ActionStatus.REJECTED else AuditEventType.STATUS_CHANGED
            )
        )

        self.repo.append_audit_event(
            CaseAuditEvent(
                audit_id=self.repo.next_audit_id(),
                timestamp=now,
                case_id=case_id,
                event_type=event_type,
                actor=actor,
                description=f"Action '{target_action.title}' status updated to {status.value}.",
                previous_value=old_status.value,
                new_value=status.value,
                metadata={"action_id": action_id},
            )
        )

        return target_action

    async def close_case(
        self,
        case_id: str,
        verdict: IncidentVerdict,
        closure_reason: str,
        lessons_learned: Optional[str] = None,
        actor: str = "SOC Incident Commander",
    ) -> IncidentCase:
        """Closes a case with mandatory justification reason and verdict assignment."""
        await self.ensure_seeded()
        if not closure_reason or len(closure_reason.strip()) < 5:
            raise ValueError("A valid closure reason of at least 5 characters is mandatory.")

        case = self.repo.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        old_status = case.status
        case.status = CaseStatus.CLOSED
        case.verdict = verdict
        case.closure_reason = closure_reason.strip()
        if lessons_learned:
            case.lessons_learned = lessons_learned.strip()

        now = datetime.utcnow()
        case.closed_at = now
        case.updated_at = now

        self.repo.append_audit_event(
            CaseAuditEvent(
                audit_id=self.repo.next_audit_id(),
                timestamp=now,
                case_id=case_id,
                event_type=AuditEventType.CASE_CLOSED,
                actor=actor,
                description=f"Case closed with verdict {verdict.value}. Reason: {closure_reason}",
                previous_value=old_status.value,
                new_value=CaseStatus.CLOSED.value,
                metadata={"verdict": verdict.value},
            )
        )

        case.timeline.append(
            CaseTimelineEvent(
                event_id=self.repo.next_timeline_id(),
                timestamp=now,
                event_type="CASE_CLOSED",
                title=f"Case Closed: Verdict {verdict.value}",
                description=f"Closed by {actor}. Reason: {closure_reason}",
                actor=actor,
            )
        )

        return self.repo.save_case(case)

    async def get_audit_trail(self, case_id: str) -> List[CaseAuditEvent]:
        await self.ensure_seeded()
        return self.repo.get_audit_trail(case_id)

    async def get_case_metrics(self) -> CaseMetrics:
        """Calculates live SOC Incident Response metrics."""
        await self.ensure_seeded()
        cases, _ = self.repo.list_cases(page_size=1000)

        total = len(cases)
        open_cases = sum(1 for c in cases if c.status != CaseStatus.CLOSED)
        crit = sum(1 for c in cases if c.priority == CasePriority.P1_CRITICAL and c.status != CaseStatus.CLOSED)
        investigating = sum(1 for c in cases if c.status == CaseStatus.INVESTIGATING)
        containment = sum(1 for c in cases if c.status == CaseStatus.CONTAINMENT)
        resolved = sum(1 for c in cases if c.status == CaseStatus.RESOLVED)
        closed = sum(1 for c in cases if c.status == CaseStatus.CLOSED)
        verified = sum(1 for c in cases if c.blockchain_verified)

        # Average resolution time
        durations = []
        for c in cases:
            if c.closed_at and c.created_at:
                diff = (c.closed_at - c.created_at).total_seconds() / 60.0
                if diff >= 0:
                    durations.append(diff)
        avg_res = round(sum(durations) / len(durations), 1) if durations else 45.0

        return CaseMetrics(
            total_cases=total,
            open_cases=open_cases,
            critical_cases=crit,
            cases_in_investigation=investigating,
            cases_in_containment=containment,
            resolved_cases=resolved,
            closed_cases=closed,
            evidence_integrity_verified=verified,
            tamper_events=0,
            average_resolution_time_minutes=avg_res,
        )

    async def verify_case_blockchain(
        self,
        case_id: str,
        actor: str = "SOC Analyst",
    ) -> Dict[str, Any]:
        """Integrates with Step 9 blockchain verification for case evidence."""
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        evidence_id = case.evidence_id or f"EVD-{case.investigation_id}"
        verify_res = await default_blockchain_service.verify_evidence(evidence_id)

        now = datetime.utcnow()
        case.blockchain_verified = verify_res.match
        case.updated_at = now
        self.repo.save_case(case)

        event_type = AuditEventType.EVIDENCE_VERIFIED if verify_res.match else AuditEventType.EVIDENCE_TAMPER_DETECTED
        self.repo.append_audit_event(
            CaseAuditEvent(
                audit_id=self.repo.next_audit_id(),
                timestamp=now,
                case_id=case_id,
                event_type=event_type,
                actor=actor,
                description=f"Evidence verification result: {verify_res.status.value}. Match: {verify_res.match}",
                related_evidence=case.evidence_hash,
                metadata={"status": verify_res.status.value, "match": verify_res.match},
            )
        )

        return {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "match": verify_res.match,
            "status": verify_res.status.value,
            "message": verify_res.message,
            "evidence_hash": case.evidence_hash,
            "anchored_block": case.blockchain_block or 1042,
        }

    async def refresh_case_ai(
        self,
        case_id: str,
        actor: str = "SOC Analyst",
    ) -> Dict[str, Any]:
        """Triggers fresh AI assessment for the underlying investigation."""
        await self.ensure_seeded()
        case = self.repo.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        ai_assessment = await default_ai_service.analyze_investigation(case.investigation_id, force_refresh=True)

        self.repo.append_audit_event(
            CaseAuditEvent(
                audit_id=self.repo.next_audit_id(),
                timestamp=datetime.utcnow(),
                case_id=case_id,
                event_type=AuditEventType.AI_ANALYSIS_REQUESTED,
                actor=actor,
                description="AI SOC Analyst assessment refreshed.",
                metadata={"provider": ai_assessment.provider, "model": ai_assessment.model},
            )
        )

        return ai_assessment.dict()


# Singleton service instance
default_incident_case_service = IncidentCaseManagementService()
