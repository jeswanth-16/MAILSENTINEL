import html
import re
from email.message import Message
from html.parser import HTMLParser
from typing import Optional, Tuple
from app.services.email.models import BodyAnalysis


class HTMLToTextStripper(HTMLParser):
    """
    Strips HTML tags safely, ignoring scripts and styling tags.
    """
    def __init__(self):
        super().__init__()
        self.text_chunks = []
        self.ignore_tag = False

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() in ('script', 'style', 'head', 'noscript'):
            self.ignore_tag = True
        elif tag.lower() in ('p', 'br', 'div', 'tr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'):
            self.text_chunks.append("\n")

    def handle_endtag(self, tag: str):
        if tag.lower() in ('script', 'style', 'head', 'noscript'):
            self.ignore_tag = False

    def handle_data(self, data: str):
        if not self.ignore_tag and data:
            self.text_chunks.append(data)

    def get_text(self) -> str:
        raw = "".join(self.text_chunks)
        # Normalize excessive newlines and whitespace
        lines = [line.strip() for line in raw.split("\n")]
        return "\n".join(l for l in lines if l)


def decode_payload_bytes(payload_bytes: bytes, charset: Optional[str]) -> str:
    """
    Decodes payload bytes using specified charset or resilient fallbacks.
    """
    if not payload_bytes:
        return ""

    charsets_to_try = [charset, "utf-8", "latin-1", "windows-1252", "ascii"]
    for cs in charsets_to_try:
        if not cs:
            continue
        try:
            return payload_bytes.decode(cs)
        except (UnicodeDecodeError, LookupError):
            continue

    # Resilient replacement fallback
    return payload_bytes.decode("utf-8", errors="replace")


def extract_body_contents(msg: Message) -> Tuple[str, Optional[str]]:
    """
    Walks the MIME tree and extracts plain text and HTML body parts.
    Returns (plain_text, html_body)
    """
    plain_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            # Skip attachments
            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()
            charset = part.get_content_charset()
            payload = part.get_payload(decode=True)

            if not payload:
                continue

            decoded_text = decode_payload_bytes(payload, charset)

            if content_type == "text/plain":
                plain_parts.append(decoded_text)
            elif content_type == "text/html":
                html_parts.append(decoded_text)
    else:
        content_type = msg.get_content_type()
        charset = msg.get_content_charset()
        payload = msg.get_payload(decode=True)
        if payload:
            decoded_text = decode_payload_bytes(payload, charset)
            if content_type == "text/html":
                html_parts.append(decoded_text)
            else:
                plain_parts.append(decoded_text)

    combined_plain = "\n\n".join(plain_parts).strip()
    combined_html = "\n\n".join(html_parts).strip() if html_parts else None

    return combined_plain, combined_html


def analyze_body(
    plain_text: str,
    html_text: Optional[str],
    link_count: int,
    attachment_count: int
) -> BodyAnalysis:
    """
    Generates normalized plain-text preview and statistical body metrics.
    """
    has_html = bool(html_text)
    has_plain = bool(plain_text)

    # If only HTML exists, extract safe text representation
    if not plain_text and html_text:
        stripper = HTMLToTextStripper()
        try:
            stripper.feed(html_text)
            normalized_text = stripper.get_text()
        except Exception:
            normalized_text = re.sub(r'<[^>]+>', ' ', html_text)
    else:
        normalized_text = plain_text

    # Decode HTML entities
    normalized_text = html.unescape(normalized_text)

    # Compute word and char counts
    char_count = len(normalized_text)
    words = normalized_text.split()
    word_count = len(words)
    lines = normalized_text.splitlines()
    line_count = len(lines)

    # Preview excerpt (up to 4000 characters)
    preview = normalized_text[:4000] if len(normalized_text) > 4000 else normalized_text

    return BodyAnalysis(
        has_html=has_html,
        has_plain_text=has_plain,
        character_count=char_count,
        word_count=word_count,
        line_count=line_count,
        link_count=link_count,
        attachment_count=attachment_count,
        normalized_text_preview=preview,
    )
