import re
from email.header import decode_header, make_header
from email.message import Message
from typing import List, Optional, Tuple
from app.services.email.models import EmailMetadata, ExtractedIP, ReceivedHop

# Regex for IPv4 address extraction
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)


def safe_decode_header(header_val: Optional[str]) -> str:
    """
    Safely decodes RFC 2047 encoded email headers into clean unicode strings.
    """
    if not header_val:
        return ""
    try:
        decoded_parts = decode_header(header_val)
        return str(make_header(decoded_parts)).strip()
    except Exception:
        # Fallback to string stripping
        return str(header_val).strip()


def parse_address_list(header_val: Optional[str]) -> List[str]:
    """
    Parses comma-separated email address lists.
    """
    if not header_val:
        return []
    raw_str = safe_decode_header(header_val)
    parts = [p.strip() for p in raw_str.split(",") if p.strip()]
    return parts


def extract_metadata(msg: Message) -> EmailMetadata:
    """
    Extracts high-level RFC 5322 metadata fields from email.
    """
    from_addr = safe_decode_header(msg.get("From", ""))
    to_addrs = parse_address_list(msg.get("To", ""))
    cc_addrs = parse_address_list(msg.get("Cc", ""))
    bcc_addrs = parse_address_list(msg.get("Bcc", ""))
    reply_to = safe_decode_header(msg.get("Reply-To", "")) or None
    return_path = safe_decode_header(msg.get("Return-Path", "")) or None
    subject = safe_decode_header(msg.get("Subject", "(No Subject)"))
    date = safe_decode_header(msg.get("Date", "")) or None
    message_id = safe_decode_header(msg.get("Message-ID", "")) or None
    mime_version = safe_decode_header(msg.get("MIME-Version", "")) or None
    content_type = msg.get_content_type() or safe_decode_header(msg.get("Content-Type", ""))

    return EmailMetadata(
        from_address=from_addr,
        to_addresses=to_addrs,
        cc_addresses=cc_addrs,
        bcc_addresses=bcc_addrs,
        reply_to=reply_to,
        return_path=return_path,
        subject=subject,
        date=date,
        message_id=message_id,
        mime_version=mime_version,
        content_type=content_type,
        raw_headers_count=len(msg.keys()),
    )


def parse_received_headers(msg: Message) -> Tuple[List[ReceivedHop], List[ExtractedIP]]:
    """
    Parses all Received headers in chronological order (hop 1 = earliest origin relay).
    Extracts sending/receiving hostnames, IPs, protocols, and timestamps.
    """
    received_headers = msg.get_all("Received", [])
    if not received_headers:
        return [], []

    # In SMTP, Received headers are prepended by each hop.
    # Therefore, the bottom of the list is the earliest hop (Hop 1), and top is latest.
    chronological_headers = list(reversed(received_headers))

    hops: List[ReceivedHop] = []
    extracted_ips: List[ExtractedIP] = []
    seen_ips = set()

    for idx, raw_header in enumerate(chronological_headers, start=1):
        clean_header = " ".join(str(raw_header).split())

        from_match = re.search(r'from\s+([^\s;]+)', clean_header, re.IGNORECASE)
        by_match = re.search(r'by\s+([^\s;]+)', clean_header, re.IGNORECASE)
        with_match = re.search(r'with\s+([^\s;]+)', clean_header, re.IGNORECASE)
        time_match = re.search(r';\s*([^;]+)$', clean_header)

        from_host = from_match.group(1).strip() if from_match else None
        by_host = by_match.group(1).strip() if by_match else None
        protocol = with_match.group(1).strip() if with_match else None
        timestamp = time_match.group(1).strip() if time_match else None

        # Find all IPs inside this received header
        ips_in_hop = IPV4_PATTERN.findall(clean_header)
        hop_ip = ips_in_hop[0] if ips_in_hop else None

        for ip in ips_in_hop:
            if ip not in seen_ips:
                seen_ips.add(ip)
                extracted_ips.append(
                    ExtractedIP(
                        ip=ip,
                        source="Received",
                        header_index=idx,
                        context=f"Hop {idx} transit record (from {from_host or 'unknown'} by {by_host or 'unknown'})",
                    )
                )

        hops.append(
            ReceivedHop(
                hop=idx,
                source="Received header",
                from_host=from_host,
                by_host=by_host,
                ip=hop_ip,
                protocol=protocol,
                timestamp=timestamp,
                raw=clean_header,
            )
        )

    # Also search for standalone IP headers
    other_ip_headers = [
        ("X-Originating-IP", "X-Originating-IP header"),
        ("X-Sender-IP", "X-Sender-IP header"),
        ("X-Real-IP", "X-Real-IP header"),
        ("X-Client-IP", "X-Client-IP header"),
    ]

    for header_name, context_desc in other_ip_headers:
        val = msg.get(header_name)
        if val:
            found_ips = IPV4_PATTERN.findall(str(val))
            for ip in found_ips:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    extracted_ips.append(
                        ExtractedIP(
                            ip=ip,
                            source=header_name,
                            context=context_desc,
                        )
                    )

    return hops, extracted_ips
