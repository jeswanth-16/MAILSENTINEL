import hashlib
import json
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

from app.services.reporting.models import (
    ForensicReport,
    ReportManifest,
    ReportType,
    ReportStatus,
    VerifyReportResponse,
)
from app.services.reporting.generator import ReportGenerator
from app.services.reporting.exporter import ReportExporter
from app.services.case_management.repository import CaseRepository, default_case_repository


class ForensicReportingService:
    """Core service for managing Forensic Report generation, exports, and integrity verification."""

    def __init__(self, case_repository: Optional[CaseRepository] = None):
        self.case_repo = case_repository or default_case_repository
        if hasattr(self.case_repo, "ensure_seeded"):
            self.case_repo.ensure_seeded()
        self.generator = ReportGenerator(self.case_repo)
        self.exporter = ReportExporter()
        self._lock = threading.RLock()
        self._reports_by_case: Dict[str, List[ForensicReport]] = {}
        self._reports_by_id: Dict[str, ForensicReport] = {}
        self._manifests_by_case: Dict[str, ReportManifest] = {}

    def generate_report(
        self,
        case_id: str,
        report_type: ReportType = ReportType.FULL_INVESTIGATION,
        generated_by: str = "SOC Security Analyst",
        include_ai_assessment: bool = True,
    ) -> ForensicReport:
        with self._lock:
            # Check versioning
            existing = self._reports_by_case.get(case_id, [])
            version = "1.0"
            if existing:
                latest_v = existing[-1].metadata.version
                try:
                    parts = latest_v.split(".")
                    version = f"{parts[0]}.{int(parts[1]) + 1}"
                except Exception:
                    version = f"1.{len(existing)}"

            report = self.generator.generate_report(
                case_id=case_id,
                report_type=report_type,
                generated_by=generated_by,
                version=version,
                include_ai_assessment=include_ai_assessment,
            )

            # Store in repository
            if case_id not in self._reports_by_case:
                self._reports_by_case[case_id] = []
            self._reports_by_case[case_id].append(report)
            self._reports_by_id[report.metadata.report_id] = report

            # Pre-generate manifest
            _, manifest = self.exporter.export_package_zip(report)
            self._manifests_by_case[case_id] = manifest

            return report

    def get_report(self, case_id: str) -> Optional[ForensicReport]:
        with self._lock:
            reports = self._reports_by_case.get(case_id)
            if reports:
                return reports[-1]
        try:
            return self.generate_report(case_id)
        except Exception:
            return None

    def get_report_by_id(self, report_id: str) -> Optional[ForensicReport]:
        with self._lock:
            return self._reports_by_id.get(report_id)

    def get_report_json(self, case_id: str) -> str:
        report = self.get_report(case_id)
        if not report:
            raise ValueError(f"Report not found for case: {case_id}")
        return self.exporter.export_json(report)

    def get_report_pdf(self, case_id: str) -> bytes:
        report = self.get_report(case_id)
        if not report:
            raise ValueError(f"Report not found for case: {case_id}")
        return self.exporter.export_pdf(report)

    def get_iocs_csv(self, case_id: str) -> str:
        report = self.get_report(case_id)
        if not report:
            raise ValueError(f"Report not found for case: {case_id}")
        return self.exporter.export_iocs_csv(report)

    def get_timeline_csv(self, case_id: str) -> str:
        report = self.get_report(case_id)
        if not report:
            raise ValueError(f"Report not found for case: {case_id}")
        return self.exporter.export_timeline_csv(report)

    def get_findings_csv(self, case_id: str) -> str:
        report = self.get_report(case_id)
        if not report:
            raise ValueError(f"Report not found for case: {case_id}")
        return self.exporter.export_findings_csv(report)

    def build_evidence_package(self, case_id: str) -> Tuple[bytes, ReportManifest]:
        report = self.get_report(case_id)
        if not report:
            raise ValueError(f"Report not found for case: {case_id}")
        zip_bytes, manifest = self.exporter.export_package_zip(report)
        with self._lock:
            self._manifests_by_case[case_id] = manifest
        return zip_bytes, manifest

    def get_manifest(self, case_id: str) -> Optional[ReportManifest]:
        with self._lock:
            manifest = self._manifests_by_case.get(case_id)
            if manifest:
                return manifest
        # If not cached, trigger package generation
        report = self.get_report(case_id)
        if report:
            _, manifest = self.exporter.export_package_zip(report)
            with self._lock:
                self._manifests_by_case[case_id] = manifest
            return manifest
        return None

    def verify_report_integrity(
        self,
        report_id: str,
        report_content: Optional[str] = None,
        expected_hash: Optional[str] = None,
    ) -> VerifyReportResponse:
        with self._lock:
            report = self._reports_by_id.get(report_id)

        if not report:
            # Check if report_id matches case_id
            report = self.get_report(report_id)
            if not report:
                raise ValueError(f"Report ID not found in registry: {report_id}")

        stored_hash = report.metadata.report_sha256 or ""

        if report_content:
            try:
                # Calculate hash of provided content
                calc_hash = hashlib.sha256(report_content.encode("utf-8")).hexdigest()
            except Exception:
                calc_hash = "INVALID_PAYLOAD"
        elif expected_hash:
            calc_hash = expected_hash
        else:
            # Recompute from canonical structure
            report_dict = report.model_dump()
            report_dict["metadata"]["report_sha256"] = None
            canonical_str = json.dumps(report_dict, sort_keys=True, default=str)
            calc_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        verified = (stored_hash == calc_hash) and bool(stored_hash)
        tamper_detected = not verified

        status = ReportStatus.VERIFIED if verified else ReportStatus.TAMPER_DETECTED
        message = (
            "Cryptographic verification succeeded: Report checksum matches immutable ledger record."
            if verified
            else "TAMPER_DETECTED: Computed report digest does not match stored cryptographic hash."
        )

        return VerifyReportResponse(
            report_id=report.metadata.report_id,
            status=status,
            stored_hash=stored_hash,
            calculated_hash=calc_hash,
            verified=verified,
            tamper_detected=tamper_detected,
            message=message,
            verification_timestamp=datetime.utcnow(),
        )


# Global default instance
default_reporting_service = ForensicReportingService(default_case_repository)
