import email
import hashlib
import random
import time
from email import policy
from typing import List, Tuple
from app.core.security import generate_sha256
from app.services.email.attachments import extract_attachment_metadata
from app.services.email.authentication import parse_authentication_results
from app.services.email.headers import extract_metadata, parse_received_headers
from app.services.email.models import EmailForensicResult
from app.services.email.parser import analyze_body, extract_body_contents
from app.services.email.urls import extract_urls_and_domains

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB


class EmailForensicError(Exception):
    """Base exception for email forensic processing failures."""
    pass


class OversizedFileError(EmailForensicError):
    """Raised when uploaded file exceeds size limits."""
    pass


class MalformedEmailError(EmailForensicError):
    """Raised when input file cannot be parsed as a valid MIME email."""
    pass


def generate_case_id() -> str:
    """
    Generates a standardized Investigation ID, e.g. INV-2026-08492
    """
    year = 2026
    seq = random.randint(10000, 99999)
    return f"INV-{year}-{seq}"


def analyze_email_bytes(file_bytes: bytes, original_filename: str = "evidence.eml") -> EmailForensicResult:
    """
    Core forensic pipeline turning raw .EML bytes into structured, safe forensic evidence.
    Strictly isolated: zero external network calls, zero script execution, zero disk execution.
    """
    if not file_bytes:
        raise MalformedEmailError("Uploaded email payload is empty.")

    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        raise OversizedFileError(
            f"File size ({len(file_bytes) / 1024 / 1024:.2f} MB) exceeds maximum allowed limit of 25MB."
        )

    # 1. Compute cryptographic SHA-256 evidence digest of raw payload
    evidence_sha256 = generate_sha256(file_bytes)

    # 2. Parse MIME structure
    try:
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
    except Exception as exc:
        raise MalformedEmailError(f"Unable to parse file as RFC 5322 MIME email container: {str(exc)}")

    if not msg.keys() and not msg.get_payload():
        raise MalformedEmailError("Input file contains no valid email headers or payload structure.")

    # 3. Extract high-level metadata
    metadata = extract_metadata(msg)

    # 4. Parse Received hop chain & Header IPs
    received_chain, ip_addresses = parse_received_headers(msg)

    # 5. Parse Authentication verdicts (SPF, DKIM, DMARC)
    authentication = parse_authentication_results(msg)

    # 6. Extract Body contents safely
    plain_text, html_body = extract_body_contents(msg)

    # 7. Extract URLs and Domains safely (no HTTP requests)
    urls, domains = extract_urls_and_domains(plain_text, html_body)

    # 8. Extract Attachment metadata and SHA-256 hashes safely (no disk writes)
    attachments = extract_attachment_metadata(msg)

    # 9. Statistical body analysis & text normalization
    body_analysis = analyze_body(
        plain_text=plain_text,
        html_text=html_body,
        link_count=len(urls),
        attachment_count=len(attachments),
    )

    # 10. Generate forensic consistency warnings
    warnings: List[str] = []

    if metadata.from_address and metadata.return_path:
        from_dom = metadata.from_address.split("@")[-1].strip(">").strip().lower()
        return_dom = metadata.return_path.split("@")[-1].strip(">").strip().lower()
        if from_dom and return_dom and from_dom != return_dom:
            warnings.append(
                f"Sender domain mismatch: 'From' header domain ({from_dom}) differs from 'Return-Path' envelope domain ({return_dom})."
            )

    if metadata.reply_to and metadata.from_address:
        if metadata.reply_to.strip().lower() not in metadata.from_address.strip().lower():
            warnings.append(
                f"Reply-To mismatch: Replies are directed to '{metadata.reply_to}' instead of '{metadata.from_address}'."
            )

    if not received_chain:
        warnings.append("No 'Received' transport headers detected. Mail hop routing cannot be determined.")

    if authentication.spf.value in ("FAIL", "SOFTFAIL", "PERMERROR"):
        warnings.append(f"SPF Authentication returned status: {authentication.spf.value}.")

    if authentication.dmarc.value in ("FAIL", "PERMERROR"):
        warnings.append(f"DMARC policy check returned status: {authentication.dmarc.value}.")

    # 11. Compile structured forensic result
    investigation_id = generate_case_id()

    return EmailForensicResult(
        investigation_id=investigation_id,
        sha256_digest=evidence_sha256,
        file_name=original_filename,
        file_size_bytes=len(file_bytes),
        metadata=metadata,
        authentication=authentication,
        received_chain=received_chain,
        ip_addresses=ip_addresses,
        urls=urls,
        domains=domains,
        attachments=attachments,
        body_analysis=body_analysis,
        warnings=warnings,
    )
