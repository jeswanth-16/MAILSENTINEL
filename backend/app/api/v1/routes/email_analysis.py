import os
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from app.core.logging import logger
from app.core.security import sanitize_filename
from app.services.auth import (
    User,
    UserRole,
    default_security_audit_logger,
    get_current_user,
    require_role,
)
from app.services.email import (
    EmailForensicResult,
    MalformedEmailError,
    OversizedFileError,
    analyze_email_bytes,
)

router = APIRouter()

ALLOWED_EXTENSIONS = {".eml", ".msg", ".txt"}
MAX_UPLOAD_SIZE = 25 * 1024 * 1024  # 25MB


@router.post(
    "/analysis/email",
    response_model=EmailForensicResult,
    status_code=status.HTTP_200_OK,
    summary="Ingest and parse raw .EML container into forensic evidence",
    tags=["Email Forensics"],
)
async def analyze_email_endpoint(
    request: Request,
    file: UploadFile = File(..., description="Raw .EML or .MSG email container file"),
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    """
    Parses and extracts structured forensic indicators from an uploaded .EML file.
    - Extracts RFC 5322 metadata & normalized headers
    - Traces Received hop transit chain and timestamps
    - Evaluates SPF, DKIM, and DMARC authentication verdicts
    - Safely extracts URLs, domains, and IP entities (zero network execution)
    - Inspects attachment payloads and calculates cryptographic SHA-256 hashes
    - Generates body statistical analysis and normalized plaintext excerpt
    """
    raw_filename = file.filename or "uploaded_evidence.eml"
    safe_filename_clean = sanitize_filename(raw_filename)
    _, ext = os.path.splitext(raw_filename)

    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported file format '{ext}'. Only raw RFC 5322 email files (.eml, .msg) are supported.",
        )

    try:
        content = await file.read()
    except Exception as e:
        logger.error(f"Failed to read uploaded file payload: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to read uploaded file stream.",
        )

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty (0 bytes).",
        )

    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed upload size of 25MB (Received {len(content) / 1024 / 1024:.2f} MB).",
        )

    try:
        logger.info(f"Initiating forensic triage for file '{safe_filename_clean}' ({len(content)} bytes)")
        result = analyze_email_bytes(file_bytes=content, original_filename=safe_filename_clean)
        from app.services.forensics.service import investigation_registry
        investigation_registry.store(result.investigation_id, result)

        default_security_audit_logger.log(
            action="EMAIL_INGESTED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="INVESTIGATION",
            resource_id=result.investigation_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
            metadata={"filename": safe_filename_clean, "size_bytes": len(content)},
        )

        logger.info(f"Completed forensic extraction for Investigation {result.investigation_id}")
        return result

    except OversizedFileError as e:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(e),
        )
    except MalformedEmailError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email Parsing Error: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Unexpected error during email forensics: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal forensic engine processing failure. The file could not be analyzed.",
        )
