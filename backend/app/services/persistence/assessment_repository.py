import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.database import get_db_connection
from app.core.logging import logger
from app.services.ai.models import InvestigationAssessment


class AssessmentSqliteRepository:
    """
    Handles SQLite persistence for InvestigationAssessment entities, ensuring
    assessments survive application restarts and maintain audit history.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def save_assessment(self, assessment: InvestigationAssessment) -> None:
        """Persists or updates an assessment record in SQLite using parameterized SQL."""
        try:
            data_json = assessment.model_dump_json()
            created_at_str = (
                assessment.created_at.isoformat()
                if hasattr(assessment.created_at, "isoformat")
                else str(assessment.created_at)
            )
            updated_at_str = datetime.utcnow().isoformat()
            verdict_str = (
                assessment.verdict.value
                if hasattr(assessment.verdict, "value")
                else str(assessment.verdict)
            )
            confidence_str = (
                assessment.confidence.value
                if hasattr(assessment.confidence, "value")
                else str(assessment.confidence)
            )

            query = """
                INSERT INTO assessments (
                    assessment_id, investigation_id, evidence_hash, engine_version,
                    verdict, confidence, severity, risk_score, data, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(assessment_id) DO UPDATE SET
                    investigation_id = excluded.investigation_id,
                    evidence_hash = excluded.evidence_hash,
                    engine_version = excluded.engine_version,
                    verdict = excluded.verdict,
                    confidence = excluded.confidence,
                    severity = excluded.severity,
                    risk_score = excluded.risk_score,
                    data = excluded.data,
                    updated_at = excluded.updated_at;
            """
            params = (
                assessment.assessment_id,
                assessment.investigation_id,
                assessment.input_evidence_hash,
                assessment.engine_version,
                verdict_str,
                confidence_str,
                assessment.severity,
                assessment.risk_score,
                data_json,
                created_at_str,
                updated_at_str,
            )

            with get_db_connection(self.db_path) as conn:
                conn.execute(query, params)

        except Exception as e:
            logger.error(f"Failed to persist assessment {assessment.assessment_id} in SQLite: {e}")
            raise

    def get_assessment(self, investigation_id: str) -> Optional[InvestigationAssessment]:
        """Retrieves the latest assessment for an investigation ID from SQLite."""
        query = "SELECT * FROM assessments WHERE investigation_id = ? ORDER BY updated_at DESC LIMIT 1;"
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(query, (investigation_id,)).fetchone()

        if not row:
            return None

        return self._row_to_assessment(row)

    def get_assessment_by_id(self, assessment_id: str) -> Optional[InvestigationAssessment]:
        """Retrieves an assessment by its unique assessment ID."""
        query = "SELECT * FROM assessments WHERE assessment_id = ?;"
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(query, (assessment_id,)).fetchone()

        if not row:
            return None

        return self._row_to_assessment(row)

    def list_assessments(self) -> List[InvestigationAssessment]:
        """Retrieves all persisted assessments."""
        query = "SELECT * FROM assessments ORDER BY updated_at DESC;"
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(query).fetchall()

        results = []
        for r in rows:
            parsed = self._row_to_assessment(r)
            if parsed:
                results.append(parsed)
        return results

    def delete_assessment(self, investigation_id: str) -> bool:
        """Deletes assessments associated with an investigation ID."""
        query = "DELETE FROM assessments WHERE investigation_id = ?;"
        with get_db_connection(self.db_path) as conn:
            cur = conn.execute(query, (investigation_id,))
            return cur.rowcount > 0

    def count_assessments(self) -> int:
        """Returns total count of assessments in SQLite."""
        query = "SELECT COUNT(*) FROM assessments;"
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(query).fetchone()
            return row[0] if row else 0

    def _row_to_assessment(self, row: Any) -> Optional[InvestigationAssessment]:
        """Safely deserializes a SQLite row into an InvestigationAssessment."""
        try:
            return InvestigationAssessment.model_validate_json(row["data"])
        except Exception as e:
            logger.error(f"Corrupt assessment data in SQLite for row {row['assessment_id']}: {e}")
            return None


default_assessment_sqlite_repository = AssessmentSqliteRepository()
