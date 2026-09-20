import json
from typing import Any, Dict, List, Optional, Tuple

from app.core.database import get_db_connection
from app.core.logging import logger
from app.services.case_management.audit import CaseAuditEvent
from app.services.case_management.models import IncidentCase


class CaseSqliteRepository:
    """
    Handles SQLite persistence for IncidentCase records and immutable CaseAuditEvent audit logs.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def save_case(self, case: IncidentCase, audit_logs: Optional[List[CaseAuditEvent]] = None) -> None:
        """Persists or updates an incident case in SQLite using parameterized SQL."""
        try:
            case_json = case.model_dump_json()
            audit_json = json.dumps([a.model_dump(mode="json") for a in audit_logs]) if audit_logs is not None else None

            created_at_str = case.created_at.isoformat() if hasattr(case.created_at, "isoformat") else str(case.created_at)
            updated_at_str = case.updated_at.isoformat() if hasattr(case.updated_at, "isoformat") else str(case.updated_at)
            status_str = case.status.value if hasattr(case.status, "value") else str(case.status)
            priority_str = case.priority.value if hasattr(case.priority, "value") else str(case.priority)
            verdict_str = case.verdict.value if hasattr(case.verdict, "value") else str(case.verdict)

            query = """
                INSERT INTO cases (
                    case_id, investigation_id, title, status, priority, verdict,
                    assigned_analyst, risk_score, data, audit_logs, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    investigation_id = excluded.investigation_id,
                    title = excluded.title,
                    status = excluded.status,
                    priority = excluded.priority,
                    verdict = excluded.verdict,
                    assigned_analyst = excluded.assigned_analyst,
                    risk_score = excluded.risk_score,
                    data = excluded.data,
                    audit_logs = COALESCE(excluded.audit_logs, cases.audit_logs),
                    updated_at = excluded.updated_at;
            """
            params = (
                case.case_id,
                case.investigation_id,
                case.title,
                status_str,
                priority_str,
                verdict_str,
                case.assigned_analyst,
                case.risk_score,
                case_json,
                audit_json,
                created_at_str,
                updated_at_str,
            )

            with get_db_connection(self.db_path) as conn:
                conn.execute(query, params)

        except Exception as e:
            logger.error(f"Failed to persist incident case {case.case_id} in SQLite: {e}")
            raise

    def get_case(self, case_id: str) -> Optional[Tuple[IncidentCase, List[CaseAuditEvent]]]:
        """
        Retrieves a case and its audit logs by case_id.
        Handles corrupt JSON safely by logging and returning None.
        """
        query = "SELECT * FROM cases WHERE case_id = ?;"
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(query, (case_id,)).fetchone()

        if not row:
            return None

        return self._row_to_case_and_logs(row)

    def get_case_by_investigation(self, investigation_id: str) -> Optional[Tuple[IncidentCase, List[CaseAuditEvent]]]:
        """Retrieves an incident case by associated investigation_id."""
        query = "SELECT * FROM cases WHERE investigation_id = ? LIMIT 1;"
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(query, (investigation_id,)).fetchone()

        if not row:
            return None

        return self._row_to_case_and_logs(row)

    def list_all_cases(self) -> List[Tuple[IncidentCase, List[CaseAuditEvent]]]:
        """Retrieves all persisted incident cases and their audit logs."""
        query = "SELECT * FROM cases ORDER BY created_at DESC;"
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(query).fetchall()

        results = []
        for r in rows:
            parsed = self._row_to_case_and_logs(r)
            if parsed:
                results.append(parsed)
        return results

    def delete_case(self, case_id: str) -> bool:
        """Deletes a case from SQLite."""
        query = "DELETE FROM cases WHERE case_id = ?;"
        with get_db_connection(self.db_path) as conn:
            cur = conn.execute(query, (case_id,))
            return cur.rowcount > 0

    def append_audit_event(self, event: CaseAuditEvent) -> None:
        """Appends an audit event to a case's audit log list in SQLite."""
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT audit_logs FROM cases WHERE case_id = ?;", (event.case_id,)).fetchone()
            if not row:
                return

            logs: List[Dict[str, Any]] = []
            if row["audit_logs"]:
                try:
                    logs = json.loads(row["audit_logs"])
                except Exception:
                    logs = []

            logs.append(event.model_dump(mode="json"))
            conn.execute(
                "UPDATE cases SET audit_logs = ? WHERE case_id = ?;",
                (json.dumps(logs), event.case_id),
            )

    def count_cases(self) -> int:
        """Returns total count of incident cases in SQLite."""
        query = "SELECT COUNT(*) FROM cases;"
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(query).fetchone()
            return row[0] if row else 0

    def _row_to_case_and_logs(self, row: Any) -> Optional[Tuple[IncidentCase, List[CaseAuditEvent]]]:
        """Safely deserializes a SQLite row into IncidentCase and CaseAuditEvent list."""
        try:
            case = IncidentCase.model_validate_json(row["data"])
        except Exception as e:
            logger.error(f"Corrupt case data in SQLite for row {row['case_id']}: {e}")
            return None

        audit_logs: List[CaseAuditEvent] = []
        if row["audit_logs"]:
            try:
                raw_logs = json.loads(row["audit_logs"])
                audit_logs = [CaseAuditEvent.model_validate(log) for log in raw_logs]
            except Exception as e:
                logger.warning(f"Corrupt audit logs in SQLite for case {row['case_id']}: {e}")

        return case, audit_logs


default_case_sqlite_repository = CaseSqliteRepository()
