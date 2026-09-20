import json
import logging
from typing import Any, Dict, List, Optional

from app.core.database import get_db_connection
from app.core.logging import logger
from app.services.blockchain.models import CustodyEvent, EvidencePackage
from app.services.email.models import EmailForensicResult
from app.services.intelligence.models import InvestigationIntelligenceResult
from app.services.investigations.models import Investigation
from app.services.risk.models import ThreatAssessmentResult


class InvestigationSqliteRepository:
    """
    Handles SQLite persistence for Investigation entities, including
    associated forensic analysis, threat scores, intelligence enrichments,
    and blockchain evidence packages.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def save_investigation(
        self,
        investigation: Investigation,
        forensic: Optional[EmailForensicResult] = None,
        threat: Optional[ThreatAssessmentResult] = None,
        intel: Optional[InvestigationIntelligenceResult] = None,
        evidence_package: Optional[EvidencePackage] = None,
        custody: Optional[List[CustodyEvent]] = None,
    ) -> None:
        """Persists or updates an investigation record in SQLite using parameterized SQL."""
        try:
            inv_json = investigation.model_dump_json()
            forensic_json = forensic.model_dump_json() if forensic else None
            threat_json = threat.model_dump_json() if threat else None
            intel_json = intel.model_dump_json() if intel else None
            evidence_json = evidence_package.model_dump_json() if evidence_package else None
            custody_json = json.dumps([c.model_dump(mode="json") for c in custody]) if custody is not None else None

            created_at_str = investigation.created_at.isoformat() if hasattr(investigation.created_at, "isoformat") else str(investigation.created_at)
            updated_at_str = investigation.updated_at.isoformat() if hasattr(investigation.updated_at, "isoformat") else str(investigation.updated_at)
            status_str = investigation.status.value if hasattr(investigation.status, "value") else str(investigation.status)
            severity_str = investigation.severity.value if hasattr(investigation.severity, "value") else str(investigation.severity)
            classification_str = investigation.classification.value if hasattr(investigation.classification, "value") else str(investigation.classification)

            query = """
                INSERT INTO investigations (
                    id, case_number, title, status, severity, classification, risk_score,
                    data, forensic_data, threat_data, intel_data, evidence_package_data,
                    custody_data, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    case_number = excluded.case_number,
                    title = excluded.title,
                    status = excluded.status,
                    severity = excluded.severity,
                    classification = excluded.classification,
                    risk_score = excluded.risk_score,
                    data = excluded.data,
                    forensic_data = COALESCE(excluded.forensic_data, investigations.forensic_data),
                    threat_data = COALESCE(excluded.threat_data, investigations.threat_data),
                    intel_data = COALESCE(excluded.intel_data, investigations.intel_data),
                    evidence_package_data = COALESCE(excluded.evidence_package_data, investigations.evidence_package_data),
                    custody_data = COALESCE(excluded.custody_data, investigations.custody_data),
                    updated_at = excluded.updated_at;
            """
            params = (
                investigation.id,
                investigation.case_number,
                investigation.title,
                status_str,
                severity_str,
                classification_str,
                investigation.risk_score,
                inv_json,
                forensic_json,
                threat_json,
                intel_json,
                evidence_json,
                custody_json,
                created_at_str,
                updated_at_str,
            )

            with get_db_connection(self.db_path) as conn:
                conn.execute(query, params)

        except Exception as e:
            logger.error(f"Failed to persist investigation {investigation.id} in SQLite: {e}")
            raise

    def get_investigation(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves an investigation and all associated forensic/threat/intel/blockchain
        artifacts by ID. Safely catches and logs any corruption in serialized JSON.
        """
        query = "SELECT * FROM investigations WHERE id = ?;"
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(query, (investigation_id,)).fetchone()

        if not row:
            return None

        return self._row_to_dict(row)

    def list_all_investigations(self) -> List[Dict[str, Any]]:
        """Retrieves all persisted investigations."""
        query = "SELECT * FROM investigations ORDER BY updated_at DESC;"
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(query).fetchall()

        results = []
        for r in rows:
            parsed = self._row_to_dict(r)
            if parsed:
                results.append(parsed)
        return results

    def delete_investigation(self, investigation_id: str) -> bool:
        """Deletes an investigation from SQLite."""
        query = "DELETE FROM investigations WHERE id = ?;"
        with get_db_connection(self.db_path) as conn:
            cur = conn.execute(query, (investigation_id,))
            return cur.rowcount > 0

    def count_investigations(self) -> int:
        """Returns total count of investigations in SQLite."""
        query = "SELECT COUNT(*) FROM investigations;"
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(query).fetchone()
            return row[0] if row else 0

    def _row_to_dict(self, row: Any) -> Optional[Dict[str, Any]]:
        """Safely deserializes a SQLite row into models, handling corruption gracefully."""
        try:
            inv = Investigation.model_validate_json(row["data"])
        except Exception as e:
            logger.error(f"Corrupt investigation data in SQLite for row {row['id']}: {e}")
            return None

        forensic = None
        if row["forensic_data"]:
            try:
                forensic = EmailForensicResult.model_validate_json(row["forensic_data"])
            except Exception as e:
                logger.warning(f"Corrupt forensic data in SQLite for row {row['id']}: {e}")

        threat = None
        if row["threat_data"]:
            try:
                threat = ThreatAssessmentResult.model_validate_json(row["threat_data"])
            except Exception as e:
                logger.warning(f"Corrupt threat data in SQLite for row {row['id']}: {e}")

        intel = None
        if row["intel_data"]:
            try:
                intel = InvestigationIntelligenceResult.model_validate_json(row["intel_data"])
            except Exception as e:
                logger.warning(f"Corrupt intelligence data in SQLite for row {row['id']}: {e}")

        evidence_pkg = None
        if row["evidence_package_data"]:
            try:
                evidence_pkg = EvidencePackage.model_validate_json(row["evidence_package_data"])
            except Exception as e:
                logger.warning(f"Corrupt evidence package data in SQLite for row {row['id']}: {e}")

        custody = []
        if row["custody_data"]:
            try:
                raw_custody = json.loads(row["custody_data"])
                custody = [CustodyEvent.model_validate(c) for c in raw_custody]
            except Exception as e:
                logger.warning(f"Corrupt custody data in SQLite for row {row['id']}: {e}")

        return {
            "investigation": inv,
            "forensic": forensic,
            "threat": threat,
            "intel": intel,
            "evidence_package": evidence_pkg,
            "custody": custody,
        }


default_investigation_sqlite_repository = InvestigationSqliteRepository()
