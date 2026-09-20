import json
import sqlite3
import pytest
from datetime import datetime

from app.core.database import get_db_connection, init_db
from app.services.case_management.audit import AuditEventType, CaseAuditEvent
from app.services.case_management.models import (
    ActionStatus,
    ActionType,
    CaseAction,
    CaseNote,
    CasePriority,
    CaseStatus,
    IncidentCase,
    IncidentVerdict,
    NoteCategory,
)
from app.services.case_management.repository import CaseRepository
from app.services.investigations.models import (
    AnalystNote,
    Investigation,
    InvestigationClassification,
    InvestigationPriority,
    InvestigationSeverity,
    InvestigationStatus,
    NoteType,
)
from app.services.investigations.service import CaseManagementService
from app.services.persistence.case_repository import CaseSqliteRepository
from app.services.persistence.investigation_repository import InvestigationSqliteRepository


def test_database_initialization(tmp_path):
    """Verifies that an uninitialized database is created with all required tables and indexes."""
    db_file = str(tmp_path / "init_test.db")
    
    # Run init_db
    init_db(db_file)

    # Verify tables and indexes exist
    with get_db_connection(db_file) as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        table_names = {t["name"] for t in tables}
        assert "investigations" in table_names
        assert "cases" in table_names

        indexes = conn.execute("SELECT name FROM sqlite_master WHERE type='index';").fetchall()
        index_names = {i["name"] for i in indexes}
        assert "idx_investigations_status" in index_names
        assert "idx_investigations_created_at" in index_names
        assert "idx_cases_investigation_id" in index_names
        assert "idx_cases_status" in index_names
        assert "idx_cases_created_at" in index_names

    # Verify idempotence (calling init_db again causes no error)
    init_db(db_file)


def test_investigation_save_and_retrieve(tmp_path):
    """Verifies save and retrieval of an investigation model with 100% data fidelity."""
    db_file = str(tmp_path / "inv_test.db")
    init_db(db_file)
    repo = InvestigationSqliteRepository(db_path=db_file)

    now = datetime(2026, 9, 19, 10, 0, 0)
    inv = Investigation(
        id="INV-2026-99001",
        case_number="CASE-2026-901",
        title="Test Phishing Investigation for SQLite",
        description="Detailed test description for SQLite persistence.",
        source="EMAIL_GATEWAY",
        created_at=now,
        updated_at=now,
        status=InvestigationStatus.INVESTIGATING,
        severity=InvestigationSeverity.HIGH,
        classification=InvestigationClassification.PHISHING,
        risk_score=88,
        confidence=92,
        assigned_analyst="SOC-TESTER",
        tags=["Phishing", "CredentialTheft", "SQLiteTest"],
        priority=InvestigationPriority.P2_HIGH,
        sender="attacker@spoofed-target.com",
        subject="Password Reset Urgency",
        evidence_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        notes=[
            AnalystNote(
                note_id="NOTE-901",
                investigation_id="INV-2026-99001",
                author="SOC-TESTER",
                timestamp=now,
                content="Initial automated parsing complete.",
                note_type=NoteType.SYSTEM,
            )
        ],
    )

    repo.save_investigation(inv)

    retrieved = repo.get_investigation("INV-2026-99001")
    assert retrieved is not None
    retrieved_inv = retrieved["investigation"]
    assert retrieved_inv.id == "INV-2026-99001"
    assert retrieved_inv.title == "Test Phishing Investigation for SQLite"
    assert retrieved_inv.status == InvestigationStatus.INVESTIGATING
    assert retrieved_inv.severity == InvestigationSeverity.HIGH
    assert retrieved_inv.risk_score == 88
    assert retrieved_inv.sender == "attacker@spoofed-target.com"
    assert len(retrieved_inv.notes) == 1
    assert retrieved_inv.notes[0].content == "Initial automated parsing complete."


def test_investigation_persistence_across_instances(tmp_path):
    """Simulates backend restart: Instance A saves data, is destroyed, Instance B retrieves it."""
    db_file = str(tmp_path / "restart_inv.db")
    init_db(db_file)

    # 1. Instance A saves investigation
    repo_a = InvestigationSqliteRepository(db_path=db_file)
    inv = Investigation(
        id="INV-2026-99002",
        case_number="CASE-2026-902",
        title="Cross-Instance Persistence Verification",
        description="Must survive process shutdown.",
        source="SOC_MANUAL",
        status=InvestigationStatus.NEW,
        severity=InvestigationSeverity.CRITICAL,
        classification=InvestigationClassification.BUSINESS_EMAIL_COMPROMISE,
        risk_score=95,
        assigned_analyst="LEAD-ANALYST",
    )
    repo_a.save_investigation(inv)

    # 2. Destroy Instance A
    del repo_a

    # 3. Instance B retrieves investigation from same SQLite database
    repo_b = InvestigationSqliteRepository(db_path=db_file)
    res = repo_b.get_investigation("INV-2026-99002")
    assert res is not None
    loaded_inv = res["investigation"]
    assert loaded_inv.id == "INV-2026-99002"
    assert loaded_inv.risk_score == 95
    assert loaded_inv.severity == InvestigationSeverity.CRITICAL
    assert loaded_inv.assigned_analyst == "LEAD-ANALYST"


def test_case_persistence_and_audit_trail(tmp_path):
    """Verifies that an IncidentCase, its artifacts, actions, notes, and audit logs persist."""
    db_file = str(tmp_path / "case_test.db")
    init_db(db_file)
    repo = CaseSqliteRepository(db_path=db_file)

    now = datetime(2026, 9, 19, 11, 0, 0)
    case = IncidentCase(
        case_id="CASE-2026-90001",
        investigation_id="INV-2026-99001",
        title="CEO Fraud Incident Case",
        description="Executive wire transfer fraud investigation.",
        status=CaseStatus.INVESTIGATING,
        priority=CasePriority.P1_CRITICAL,
        verdict=IncidentVerdict.MALICIOUS,
        created_at=now,
        updated_at=now,
        assigned_analyst="SOC-IR-LEAD",
        tags=["BEC", "WireFraud"],
        risk_score=94,
        severity="CRITICAL",
        notes=[
            CaseNote(
                note_id="NOTE-001",
                case_id="CASE-2026-90001",
                timestamp=now,
                author="SOC-IR-LEAD",
                content="Identified lookalike domain in envelope sender.",
                category=NoteCategory.ANALYSIS,
            )
        ],
        actions=[
            CaseAction(
                action_id="ACT-001",
                case_id="CASE-2026-90001",
                type=ActionType.BLOCK_DOMAIN,
                title="Block lookalike domain at mail gateway",
                description="Perimeter mail filter rule.",
                priority=CasePriority.P1_CRITICAL,
                status=ActionStatus.PROPOSED,
                created_at=now,
            )
        ],
    )

    audit_logs = [
        CaseAuditEvent(
            audit_id="AUD-001",
            timestamp=now,
            case_id="CASE-2026-90001",
            event_type=AuditEventType.CASE_CREATED,
            actor="SOC-IR-LEAD",
            description="Incident Case CASE-2026-90001 opened.",
        )
    ]

    # Save to SQLite
    repo.save_case(case, audit_logs)

    # Re-read from a fresh repository instance
    fresh_repo = CaseSqliteRepository(db_path=db_file)
    result = fresh_repo.get_case("CASE-2026-90001")
    assert result is not None
    loaded_case, loaded_audit = result

    assert loaded_case.case_id == "CASE-2026-90001"
    assert loaded_case.priority == CasePriority.P1_CRITICAL
    assert loaded_case.verdict == IncidentVerdict.MALICIOUS
    assert len(loaded_case.notes) == 1
    assert loaded_case.notes[0].content == "Identified lookalike domain in envelope sender."
    assert len(loaded_case.actions) == 1
    assert loaded_case.actions[0].title == "Block lookalike domain at mail gateway"
    assert len(loaded_audit) == 1
    assert loaded_audit[0].event_type == AuditEventType.CASE_CREATED


def test_case_update_persistence_across_instances(tmp_path):
    """Verifies that modifications, status transitions, and audit events persist across instances."""
    db_file = str(tmp_path / "update_test.db")
    init_db(db_file)

    repo_a = CaseSqliteRepository(db_path=db_file)
    case = IncidentCase(
        case_id="CASE-2026-90002",
        investigation_id="INV-2026-99002",
        title="Initial Title",
        status=CaseStatus.NEW,
        priority=CasePriority.P3_MEDIUM,
    )
    repo_a.save_case(case, [])

    # Update title and status
    case.title = "Updated Urgent Title"
    case.status = CaseStatus.CONTAINMENT
    case.priority = CasePriority.P1_CRITICAL
    audit_evt = CaseAuditEvent(
        audit_id="AUD-002",
        timestamp=datetime.utcnow(),
        case_id="CASE-2026-90002",
        event_type=AuditEventType.STATUS_CHANGED,
        actor="SOC-ANALYST",
        description="Transitioned from NEW to CONTAINMENT.",
    )
    repo_a.save_case(case, [audit_evt])

    del repo_a

    # Read from Instance B
    repo_b = CaseSqliteRepository(db_path=db_file)
    result = repo_b.get_case("CASE-2026-90002")
    assert result is not None
    loaded_case, loaded_audit = result
    assert loaded_case.title == "Updated Urgent Title"
    assert loaded_case.status == CaseStatus.CONTAINMENT
    assert loaded_case.priority == CasePriority.P1_CRITICAL
    assert len(loaded_audit) == 1
    assert loaded_audit[0].description == "Transitioned from NEW to CONTAINMENT."


def test_missing_record_handling(tmp_path):
    """Verifies that querying nonexistent records behaves consistently and returns None."""
    db_file = str(tmp_path / "missing_test.db")
    init_db(db_file)

    inv_repo = InvestigationSqliteRepository(db_path=db_file)
    assert inv_repo.get_investigation("INV-DOES-NOT-EXIST") is None
    assert inv_repo.delete_investigation("INV-DOES-NOT-EXIST") is False

    case_repo = CaseSqliteRepository(db_path=db_file)
    assert case_repo.get_case("CASE-DOES-NOT-EXIST") is None
    assert case_repo.get_case_by_investigation("INV-DOES-NOT-EXIST") is None
    assert case_repo.delete_case("CASE-DOES-NOT-EXIST") is False


def test_corrupt_database_json_resilience(tmp_path):
    """Verifies that corrupted JSON in SQLite does not crash the backend and is safely handled."""
    db_file = str(tmp_path / "corrupt_test.db")
    init_db(db_file)

    with get_db_connection(db_file) as conn:
        # Corrupt investigation row
        conn.execute(
            """INSERT INTO investigations (id, data, created_at)
               VALUES ('INV-CORRUPT', '{not valid json!!!', '2026-09-19T10:00:00');"""
        )
        # Corrupt case row
        conn.execute(
            """INSERT INTO cases (case_id, data, created_at)
               VALUES ('CASE-CORRUPT', '{not valid json!!!', '2026-09-19T10:00:00');"""
        )

    inv_repo = InvestigationSqliteRepository(db_path=db_file)
    # Must not raise an unhandled exception
    res_inv = inv_repo.get_investigation("INV-CORRUPT")
    assert res_inv is None

    case_repo = CaseSqliteRepository(db_path=db_file)
    res_case = case_repo.get_case("CASE-CORRUPT")
    assert res_case is None


def test_sql_injection_safety(tmp_path):
    """Verifies that parameterized SQL prevents SQL injection attacks."""
    db_file = str(tmp_path / "sqli_test.db")
    init_db(db_file)

    repo = InvestigationSqliteRepository(db_path=db_file)

    # Malicious injection payloads
    malicious_ids = [
        "INV-001' OR '1'='1",
        "'; DROP TABLE investigations; --",
        "INV-001' UNION SELECT * FROM cases --",
    ]

    for sqli_id in malicious_ids:
        # Must return None safely without syntax error or table drop
        res = repo.get_investigation(sqli_id)
        assert res is None

    # Verify tables still exist
    with get_db_connection(db_file) as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        table_names = {t["name"] for t in tables}
        assert "investigations" in table_names
        assert "cases" in table_names


@pytest.mark.anyio
async def test_case_management_service_restart_rehydration(tmp_path):
    """Verifies that CaseManagementService completely survives a simulated process restart."""
    db_file = str(tmp_path / "service_restart.db")
    init_db(db_file)

    inv_repo = InvestigationSqliteRepository(db_path=db_file)

    # 1. First run: Start Service A and seed
    service_a = CaseManagementService(persistence=inv_repo)
    await service_a.ensure_seeded()

    # 2. Create new investigation in Service A
    new_inv = await service_a.create_investigation(
        title="Pre-Restart Investigation",
        description="Created before service restart.",
        source="SOC_MANUAL",
        severity=InvestigationSeverity.HIGH,
        classification=InvestigationClassification.PHISHING,
        risk_score=79,
        assigned_analyst="SOC-ANALYST-ALPHA",
    )
    inv_id = new_inv.id

    # 3. Add note and update status
    await service_a.add_note(inv_id, content="Important analyst observation before restart.")
    await service_a.update_status(inv_id, InvestigationStatus.INVESTIGATING, reason="Triage complete.")

    # 4. Simulate process restart: destroy service_a
    del service_a

    # 5. Service B starts up on the same SQLite database
    service_b = CaseManagementService(persistence=inv_repo)
    await service_b.ensure_seeded()

    # 6. Retrieve investigation in Service B
    rehydrated = await service_b.get_investigation(inv_id)
    assert rehydrated is not None
    assert rehydrated.id == inv_id
    assert rehydrated.title == "Pre-Restart Investigation"
    assert rehydrated.status == InvestigationStatus.INVESTIGATING
    assert rehydrated.assigned_analyst == "SOC-ANALYST-ALPHA"
    assert any("Important analyst observation" in n.content for n in rehydrated.notes)

    # 7. Verify counter continuity (creating next investigation does not collide)
    next_inv = await service_b.create_investigation(title="Post-Restart Investigation")
    assert next_inv.id != inv_id


def test_case_repository_restart_rehydration(tmp_path):
    """Verifies that CaseRepository completely survives a simulated process restart."""
    db_file = str(tmp_path / "repo_restart.db")
    init_db(db_file)

    case_repo = CaseSqliteRepository(db_path=db_file)

    # 1. First run: Start CaseRepository A and seed
    repo_a = CaseRepository(persistence=case_repo)
    repo_a.ensure_seeded()

    # 2. Create and save a new incident case
    c = IncidentCase(
        case_id="CASE-2026-88888",
        investigation_id="INV-2026-88888",
        title="Ransomware Incident Case",
        status=CaseStatus.INVESTIGATING,
        priority=CasePriority.P1_CRITICAL,
    )
    repo_a.save_case(c)
    repo_a.append_audit_event(
        CaseAuditEvent(
            audit_id="AUD-888",
            timestamp=datetime.utcnow(),
            case_id="CASE-2026-88888",
            event_type=AuditEventType.CASE_CREATED,
            actor="SOC-COMMANDER",
            description="High severity incident opened.",
        )
    )

    # 3. Simulate process restart: destroy repo_a
    del repo_a

    # 4. Start CaseRepository B
    repo_b = CaseRepository(persistence=case_repo)
    repo_b.ensure_seeded()

    # 5. Retrieve case in repo_b
    loaded = repo_b.get_case("CASE-2026-88888")
    assert loaded is not None
    assert loaded.case_id == "CASE-2026-88888"
    assert loaded.title == "Ransomware Incident Case"
    assert loaded.status == CaseStatus.INVESTIGATING

    audit_trail = repo_b.get_audit_trail("CASE-2026-88888")
    assert len(audit_trail) >= 1
    assert audit_trail[0].audit_id == "AUD-888"
