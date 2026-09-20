from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class AuthenticationVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    TEMPERROR = "TEMPERROR"
    PERMERROR = "PERMERROR"
    UNKNOWN = "UNKNOWN"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class AuthenticationResult(BaseModel):
    spf: AuthenticationVerdict = Field(default=AuthenticationVerdict.NOT_AVAILABLE)
    spf_detail: Optional[str] = Field(default=None, description="Detailed SPF diagnostic or client IP")
    dkim: AuthenticationVerdict = Field(default=AuthenticationVerdict.NOT_AVAILABLE)
    dkim_detail: Optional[str] = Field(default=None, description="DKIM domain or signature header detail")
    dmarc: AuthenticationVerdict = Field(default=AuthenticationVerdict.NOT_AVAILABLE)
    dmarc_detail: Optional[str] = Field(default=None, description="DMARC policy action (e.g. reject, quarantine, p=none)")
    raw_header: Optional[str] = Field(default=None, description="Raw Authentication-Results or Received-SPF header string")


class ReceivedHop(BaseModel):
    hop: int = Field(..., description="1-indexed sequence of transit hop (1 is origin/first recorded relay)")
    source: str = Field(default="Received header")
    from_host: Optional[str] = Field(default=None, description="Reported sending hostname or HELO/EHLO identity")
    by_host: Optional[str] = Field(default=None, description="Receiving mail server hostname")
    ip: Optional[str] = Field(default=None, description="IPv4/IPv6 extracted from hop context")
    protocol: Optional[str] = Field(default=None, description="Transfer protocol e.g. ESMTP, SMTP, HTTPS")
    timestamp: Optional[str] = Field(default=None, description="Timestamp recorded in the hop header")
    raw: str = Field(..., description="Raw sanitized Received header string")


class ExtractedIP(BaseModel):
    ip: str = Field(..., description="Extracted IP address")
    source: str = Field(..., description="Header or context source, e.g. Received, X-Originating-IP")
    header_index: Optional[int] = Field(default=None, description="Index of header if applicable")
    context: str = Field(..., description="Description of the context in which the IP was found")


class ExtractedURL(BaseModel):
    url: str = Field(..., description="Original raw URL extracted from body")
    normalized_url: str = Field(..., description="Normalized URL representation")
    scheme: str = Field(..., description="URL scheme, e.g. https, http")
    domain: str = Field(..., description="Extracted host/domain name")
    port: Optional[int] = Field(default=None, description="Port number if non-standard")
    path: str = Field(default="", description="URL path component")
    query: str = Field(default="", description="URL query parameters")
    source: str = Field(..., description="Source location: 'plain_text' or 'html_anchor' or 'html_attribute'")


class ExtractedDomain(BaseModel):
    domain: str = Field(..., description="Domain name extracted from URLs or mail addresses")
    source_urls: List[str] = Field(default_factory=list, description="Associated extracted URLs")
    occurrence_count: int = Field(default=1, description="Number of times seen in message")


class AttachmentMetadata(BaseModel):
    filename: str = Field(..., description="Extracted sanitized filename")
    extension: str = Field(..., description="File extension with leading dot")
    mime_type: str = Field(..., description="Content-Type MIME identifier")
    size_bytes: int = Field(..., description="Attachment payload size in bytes")
    sha256: str = Field(..., description="Cryptographic SHA-256 hash of attachment payload")
    content_disposition: Optional[str] = Field(default=None, description="Content-Disposition type, e.g. attachment, inline")


class BodyAnalysis(BaseModel):
    has_html: bool = Field(default=False)
    has_plain_text: bool = Field(default=False)
    character_count: int = Field(default=0)
    word_count: int = Field(default=0)
    line_count: int = Field(default=0)
    link_count: int = Field(default=0)
    attachment_count: int = Field(default=0)
    normalized_text_preview: str = Field(default="", description="Sanitized plain text excerpt for preview and analysis")


class EmailMetadata(BaseModel):
    from_address: str = Field(default="", description="From header value")
    to_addresses: List[str] = Field(default_factory=list, description="To header recipient list")
    cc_addresses: List[str] = Field(default_factory=list, description="CC header recipient list")
    bcc_addresses: List[str] = Field(default_factory=list, description="BCC header recipient list")
    reply_to: Optional[str] = Field(default=None, description="Reply-To address")
    return_path: Optional[str] = Field(default=None, description="Return-Path envelope sender")
    subject: str = Field(default="", description="Decoded email subject")
    date: Optional[str] = Field(default=None, description="Sent date header")
    message_id: Optional[str] = Field(default=None, description="RFC 5322 Message-ID")
    mime_version: Optional[str] = Field(default=None, description="MIME-Version header")
    content_type: Optional[str] = Field(default=None, description="Top-level Content-Type header")
    raw_headers_count: int = Field(default=0, description="Total number of raw headers parsed")


class EmailForensicResult(BaseModel):
    investigation_id: str = Field(..., description="Assigned Investigation ID, e.g. INV-2026-XXXXX")
    sha256_digest: str = Field(..., description="SHA-256 hash of the full raw .EML evidence payload")
    file_name: str = Field(..., description="Original or sanitized input file name")
    file_size_bytes: int = Field(..., description="Size of uploaded .EML file in bytes")
    metadata: EmailMetadata
    authentication: AuthenticationResult
    received_chain: List[ReceivedHop] = Field(default_factory=list)
    ip_addresses: List[ExtractedIP] = Field(default_factory=list)
    urls: List[ExtractedURL] = Field(default_factory=list)
    domains: List[ExtractedDomain] = Field(default_factory=list)
    attachments: List[AttachmentMetadata] = Field(default_factory=list)
    body_analysis: BodyAnalysis
    warnings: List[str] = Field(default_factory=list, description="Forensic warnings encountered during ingestion")
    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
