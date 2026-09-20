import re
from email.message import Message
from typing import Optional, Tuple
from app.services.email.models import AuthenticationResult, AuthenticationVerdict


def normalize_verdict(raw_status: Optional[str]) -> AuthenticationVerdict:
    """
    Normalizes arbitrary authentication status strings into standard AuthenticationVerdict enum.
    """
    if not raw_status:
        return AuthenticationVerdict.NOT_AVAILABLE

    clean = raw_status.strip().upper()

    mapping = {
        "PASS": AuthenticationVerdict.PASS,
        "FAIL": AuthenticationVerdict.FAIL,
        "SOFTFAIL": AuthenticationVerdict.SOFTFAIL,
        "NEUTRAL": AuthenticationVerdict.NEUTRAL,
        "NONE": AuthenticationVerdict.NONE,
        "TEMPERROR": AuthenticationVerdict.TEMPERROR,
        "TEMPFAIL": AuthenticationVerdict.TEMPERROR,
        "PERMERROR": AuthenticationVerdict.PERMERROR,
        "PERMFAIL": AuthenticationVerdict.PERMERROR,
        "UNKNOWN": AuthenticationVerdict.UNKNOWN,
    }

    return mapping.get(clean, AuthenticationVerdict.UNKNOWN)


def parse_authentication_results(msg: Message) -> AuthenticationResult:
    """
    Parses SPF, DKIM, and DMARC authentication verdicts from email headers.
    Headers checked: Authentication-Results, ARC-Authentication-Results, Received-SPF, DKIM-Signature.
    """
    auth_results_header = msg.get("Authentication-Results") or msg.get("ARC-Authentication-Results")
    received_spf_header = msg.get("Received-SPF")
    dkim_sig_header = msg.get("DKIM-Signature")

    spf_verdict = AuthenticationVerdict.NOT_AVAILABLE
    spf_detail: Optional[str] = None

    dkim_verdict = AuthenticationVerdict.NOT_AVAILABLE
    dkim_detail: Optional[str] = None

    dmarc_verdict = AuthenticationVerdict.NOT_AVAILABLE
    dmarc_detail: Optional[str] = None

    raw_header_str = auth_results_header or received_spf_header or None

    # 1. Check Authentication-Results header
    if auth_results_header:
        clean_auth = " ".join(str(auth_results_header).split())

        # SPF matching inside Authentication-Results
        spf_match = re.search(r'\bspf=([a-zA-Z0-9_-]+)(?:\s+([^;]+))?', clean_auth, re.IGNORECASE)
        if spf_match:
            spf_verdict = normalize_verdict(spf_match.group(1))
            spf_detail = spf_match.group(2).strip() if spf_match.group(2) else None

        # DKIM matching inside Authentication-Results
        dkim_match = re.search(r'\bdkim=([a-zA-Z0-9_-]+)(?:\s+([^;]+))?', clean_auth, re.IGNORECASE)
        if dkim_match:
            dkim_verdict = normalize_verdict(dkim_match.group(1))
            dkim_detail = dkim_match.group(2).strip() if dkim_match.group(2) else None

        # DMARC matching inside Authentication-Results
        dmarc_match = re.search(r'\bdmarc=([a-zA-Z0-9_-]+)(?:\s+([^;]+))?', clean_auth, re.IGNORECASE)
        if dmarc_match:
            dmarc_verdict = normalize_verdict(dmarc_match.group(1))
            dmarc_detail = dmarc_match.group(2).strip() if dmarc_match.group(2) else None

    # 2. Check Received-SPF if SPF was not resolved from Authentication-Results
    if spf_verdict == AuthenticationVerdict.NOT_AVAILABLE and received_spf_header:
        clean_spf = " ".join(str(received_spf_header).split())
        match = re.match(r'^([a-zA-Z0-9_-]+)(?:\s+(.*))?', clean_spf, re.IGNORECASE)
        if match:
            spf_verdict = normalize_verdict(match.group(1))
            spf_detail = match.group(2).strip() if match.group(2) else None

    # 3. Check presence of DKIM-Signature if DKIM is still NOT_AVAILABLE
    if dkim_verdict == AuthenticationVerdict.NOT_AVAILABLE and dkim_sig_header:
        # DKIM signature is present on the message, but no validation header was injected by the receiving MTA
        dkim_match = re.search(r'd=([a-zA-Z0-9_.-]+)', str(dkim_sig_header), re.IGNORECASE)
        domain = dkim_match.group(1) if dkim_match else "unknown"
        dkim_detail = f"DKIM-Signature present on message for domain '{domain}' (unverified by gateway)"
        dkim_verdict = AuthenticationVerdict.UNKNOWN

    return AuthenticationResult(
        spf=spf_verdict,
        spf_detail=spf_detail,
        dkim=dkim_verdict,
        dkim_detail=dkim_detail,
        dmarc=dmarc_verdict,
        dmarc_detail=dmarc_detail,
        raw_header=str(raw_header_str) if raw_header_str else None,
    )
