import hashlib
import os
import re
from email.message import Message
from typing import List
from app.services.email.headers import safe_decode_header
from app.services.email.models import AttachmentMetadata


def sanitize_filename(name: str) -> str:
    """
    Sanitizes attachment filename to prevent directory traversal and control characters.
    """
    if not name:
        return "unnamed_attachment"
    # Remove directory separators and null bytes
    clean = re.sub(r'[\\/*?:"<>|\x00-\x1f]', "_", name)
    clean = os.path.basename(clean).strip()
    return clean or "unnamed_attachment"


def extract_attachment_metadata(msg: Message) -> List[AttachmentMetadata]:
    """
    Safely walks the MIME message parts and extracts metadata and SHA-256 hashes
    without writing executable files to disk or executing any content.
    """
    attachments: List[AttachmentMetadata] = []

    for part in msg.walk():
        # Check if this part is an attachment or has a filename
        disposition = part.get_content_disposition()
        filename = part.get_filename()

        if disposition == "attachment" or filename:
            raw_filename = safe_decode_header(filename or "unnamed_payload")
            clean_filename = sanitize_filename(raw_filename)
            _, ext = os.path.splitext(clean_filename)

            mime_type = part.get_content_type() or "application/octet-stream"

            # Get raw payload bytes safely
            payload_bytes = part.get_payload(decode=True)
            if payload_bytes is None:
                payload_bytes = b""

            size_bytes = len(payload_bytes)
            sha256_hash = hashlib.sha256(payload_bytes).hexdigest()

            attachments.append(
                AttachmentMetadata(
                    filename=clean_filename,
                    extension=ext.lower() if ext else ".bin",
                    mime_type=mime_type,
                    size_bytes=size_bytes,
                    sha256=sha256_hash,
                    content_disposition=disposition or "attachment",
                )
            )

    return attachments
