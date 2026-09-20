from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from app.core.security import sanitize_filename, sanitize_identifier
from app.services.auth import (
    User,
    UserRole,
    default_security_audit_logger,
    get_current_user,
    require_role,
)
from app.services.reporting import (
    ForensicReport,
    GenerateReportRequest,
    ReportManifest,
    VerifyReportRequest,
    VerifyReportResponse,
    default_reporting_service,
)

router = APIRouter(prefix="/reports", tags=["Reporting & Evidence Export"])


@router.post("/generate/{case_id}", response_model=ForensicReport, status_code=status.HTTP_201_CREATED)
def generate_report(
    case_id: str,
    payload: GenerateReportRequest,
    request: Request,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
            UserRole.AUDITOR,
        )
    ),
):
    """Generates a structured forensic report for the specified incident case."""
    clean_id = sanitize_identifier(case_id)
    try:
        report = default_reporting_service.generate_report(
            case_id=clean_id,
            report_type=payload.report_type,
            generated_by=payload.generated_by or current_user.full_name,
            include_ai_assessment=payload.include_ai_assessment,
        )

        default_security_audit_logger.log(
            action="REPORT_GENERATED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="REPORT",
            resource_id=report.metadata.report_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
            metadata={"case_id": clean_id, "report_type": payload.report_type.value},
        )
        return report
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")


@router.get("/{case_id}", response_model=ForensicReport)
def get_report(
    case_id: str,
    current_user: User = Depends(get_current_user),
):
    """Retrieves the latest forensic report for an incident case."""
    clean_id = sanitize_identifier(case_id)
    report = default_reporting_service.get_report(clean_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found for case: {clean_id}")
    return report


@router.get("/{case_id}/json")
def get_report_json(
    case_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Returns the canonical machine-readable JSON export for a report."""
    clean_id = sanitize_identifier(case_id)
    try:
        json_str = default_reporting_service.get_report_json(clean_id)
        default_security_audit_logger.log(
            action="REPORT_DOWNLOADED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="REPORT_JSON",
            resource_id=clean_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
        )
        return Response(content=json_str, media_type="application/json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{case_id}/pdf")
def get_report_pdf(
    case_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Generates and downloads a professional SOC PDF report."""
    clean_id = sanitize_identifier(case_id)
    try:
        pdf_bytes = default_reporting_service.get_report_pdf(clean_id)
        safe_filename = sanitize_filename(f"forensic_report_{clean_id}.pdf")
        headers = {
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "X-Content-Type-Options": "nosniff",
        }

        default_security_audit_logger.log(
            action="REPORT_DOWNLOADED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="REPORT_PDF",
            resource_id=clean_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
        )
        return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{case_id}/iocs.csv")
def get_iocs_csv(
    case_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Exports extracted Indicators of Compromise (IOCs) as CSV."""
    clean_id = sanitize_identifier(case_id)
    try:
        csv_str = default_reporting_service.get_iocs_csv(clean_id)
        safe_filename = sanitize_filename(f"iocs_{clean_id}.csv")
        headers = {
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "X-Content-Type-Options": "nosniff",
        }
        return Response(content=csv_str, media_type="text/csv", headers=headers)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{case_id}/timeline.csv")
def get_timeline_csv(
    case_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Exports incident timeline events as CSV."""
    clean_id = sanitize_identifier(case_id)
    try:
        csv_str = default_reporting_service.get_timeline_csv(clean_id)
        safe_filename = sanitize_filename(f"timeline_{clean_id}.csv")
        headers = {
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "X-Content-Type-Options": "nosniff",
        }
        return Response(content=csv_str, media_type="text/csv", headers=headers)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{case_id}/findings.csv")
def get_findings_csv(
    case_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Exports structured security findings as CSV."""
    clean_id = sanitize_identifier(case_id)
    try:
        csv_str = default_reporting_service.get_findings_csv(clean_id)
        safe_filename = sanitize_filename(f"findings_{clean_id}.csv")
        headers = {
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "X-Content-Type-Options": "nosniff",
        }
        return Response(content=csv_str, media_type="text/csv", headers=headers)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{case_id}/package")
def build_evidence_package(
    case_id: str,
    request: Request,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
            UserRole.AUDITOR,
        )
    ),
):
    """Builds and returns a complete, tamper-evident Evidence Package ZIP archive."""
    clean_id = sanitize_identifier(case_id)
    try:
        zip_bytes, _ = default_reporting_service.build_evidence_package(clean_id)
        safe_filename = sanitize_filename(f"evidence_package_{clean_id}.zip")
        headers = {
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "X-Content-Type-Options": "nosniff",
        }

        default_security_audit_logger.log(
            action="EVIDENCE_PACKAGE_EXPORTED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="EVIDENCE_PACKAGE",
            resource_id=clean_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
        )
        return Response(content=zip_bytes, media_type="application/zip", headers=headers)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{case_id}/manifest", response_model=ReportManifest)
def get_manifest(
    case_id: str,
    current_user: User = Depends(get_current_user),
):
    """Retrieves the cryptographic evidence manifest with SHA-256 digests."""
    clean_id = sanitize_identifier(case_id)
    manifest = default_reporting_service.get_manifest(clean_id)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Evidence manifest not found for case: {clean_id}")
    return manifest


@router.post("/{report_id}/verify", response_model=VerifyReportResponse)
def verify_report(
    report_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Verifies the integrity of a stored forensic report against its SHA-256 hash."""
    clean_id = sanitize_identifier(report_id)
    res = default_reporting_service.verify_report_integrity(clean_id)

    default_security_audit_logger.log(
        action="REPORT_VERIFIED",
        actor_user_id=current_user.id,
        actor_role=current_user.role.value,
        resource_type="REPORT",
        resource_id=clean_id,
        result="SUCCESS" if res.verified else "TAMPER_DETECTED",
        source_ip=request.client.host if request.client else "127.0.0.1",
    )
    return res
