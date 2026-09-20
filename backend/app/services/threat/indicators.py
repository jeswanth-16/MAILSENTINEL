import os
import re
from typing import Any, List, Optional, Set
from app.services.email.models import EmailForensicResult
from app.services.threat.models import ThreatCategory, ThreatIndicator, ThreatSeverityLevel

# Common brand names targeted by typosquatting and homoglyphs
PROTECTED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "meta", "facebook",
    "instagram", "chase", "wellsfargo", "bankofamerica", "citibank", "dhl", "fedex",
    "ups", "office365", "outlook", "docusign", "dropbox", "adobesign"
]

# Obfuscated / homoglyph lookalike patterns
LOOKALIKE_PATTERNS = [
    (r'paypa[1l|i]-', "paypal"),
    (r'paypa1', "paypal"),
    (r'micros[0o]ft', "microsoft"),
    (r'm1crosoft', "microsoft"),
    (r'g00gle', "google"),
    (r'app[1l]e', "apple"),
    (r'off[i1]ce365', "office365"),
    (r'd0cus[i1]gn', "docusign"),
]

# Social engineering keyword patterns
URGENCY_REGEX = re.compile(
    r'\b(?:urgent|immediately|immediate action|critical deadline|expires? (?:in \d+|today|shortly)|'
    r'account (?:suspended|locked|terminated|disabled)|action required|immediate response)\b',
    re.IGNORECASE,
)

FINANCIAL_REGEX = re.compile(
    r'\b(?:wire authorization|wire transfer|urgent invoice|remittance|outstanding (?:invoice|payment|balance)|'
    r'payment authorization|bank transfer|direct deposit|swift transfer|acquisition payment)\b',
    re.IGNORECASE,
)

CREDENTIAL_REGEX = re.compile(
    r'\b(?:password (?:expires?|reset|has expired)|verify your (?:account|identity|password|credentials)|'
    r'log in to (?:verify|confirm|unlock)|credential verification|session expired|re-authenticate)\b',
    re.IGNORECASE,
)

SECRECY_REGEX = re.compile(
    r'\b(?:keep this (?:confidential|secret|private)|do not discuss with|strict confidentiality|'
    r'off the record|private transaction)\b',
    re.IGNORECASE,
)

AUTHORITY_TITLES = [
    "ceo", "chief executive", "cfo", "chief financial", "coo", "president",
    "executive desk", "executive office", "it support", "it desk", "security team",
    "system administrator", "human resources", "payroll department"
]


def detect_authentication_indicators(forensic: EmailForensicResult) -> List[ThreatIndicator]:
    """
    Detects SPF, DKIM, and DMARC authentication failures.
    """
    indicators: List[ThreatIndicator] = []
    auth = forensic.authentication

    if auth.spf.value == "FAIL":
        indicators.append(
            ThreatIndicator(
                id="AUTH_SPF_FAIL",
                category=ThreatCategory.AUTHENTICATION,
                name="SPF Authentication Failure",
                description="The sending relay IP was not authorized by the sender domain's SPF record.",
                evidence=f"SPF status: FAIL ({auth.spf_detail or 'SPF verification failed'})",
                severity=ThreatSeverityLevel.HIGH,
                weight=15,
                confidence=1.0,
                source="email_headers",
            )
        )
    elif auth.spf.value == "SOFTFAIL":
        indicators.append(
            ThreatIndicator(
                id="AUTH_SPF_SOFTFAIL",
                category=ThreatCategory.AUTHENTICATION,
                name="SPF Softfail Detected",
                description="The sending server IP is discouraged by the domain's SPF record (~all).",
                evidence=f"SPF status: SOFTFAIL ({auth.spf_detail or 'discouraged relay IP'})",
                severity=ThreatSeverityLevel.MEDIUM,
                weight=8,
                confidence=0.9,
                source="email_headers",
            )
        )

    if auth.dmarc.value in ("FAIL", "PERMERROR"):
        indicators.append(
            ThreatIndicator(
                id="AUTH_DMARC_FAIL",
                category=ThreatCategory.AUTHENTICATION,
                name="DMARC Policy Failure",
                description="The message failed DMARC alignment validation between From header and envelope SPF/DKIM.",
                evidence=f"DMARC status: FAIL ({auth.dmarc_detail or 'DMARC alignment failure'})",
                severity=ThreatSeverityLevel.HIGH,
                weight=15,
                confidence=1.0,
                source="email_headers",
            )
        )

    if auth.dkim.value in ("FAIL", "PERMERROR"):
        indicators.append(
            ThreatIndicator(
                id="AUTH_DKIM_FAIL",
                category=ThreatCategory.AUTHENTICATION,
                name="DKIM Cryptographic Signature Failure",
                description="The cryptographic DKIM signature attached to the message failed mathematical verification.",
                evidence=f"DKIM status: FAIL ({auth.dkim_detail or 'DKIM verification failed'})",
                severity=ThreatSeverityLevel.HIGH,
                weight=12,
                confidence=1.0,
                source="email_headers",
            )
        )

    return indicators


def detect_sender_indicators(forensic: EmailForensicResult) -> List[ThreatIndicator]:
    """
    Detects sender header anomalies, envelope mismatches, and authority impersonation.
    """
    indicators: List[ThreatIndicator] = []
    meta = forensic.metadata

    # 1. From vs Return-Path domain mismatch
    if meta.from_address and meta.return_path:
        from_dom = meta.from_address.split("@")[-1].strip(">").strip().lower()
        return_dom = meta.return_path.split("@")[-1].strip(">").strip().lower()
        if from_dom and return_dom and from_dom != return_dom:
            indicators.append(
                ThreatIndicator(
                    id="SENDER_RETURN_PATH_MISMATCH",
                    category=ThreatCategory.SENDER,
                    name="From vs Return-Path Domain Mismatch",
                    description="The visible sender address domain differs from the actual bounce/envelope Return-Path domain.",
                    evidence=f"From: '{from_dom}' vs Return-Path: '{return_dom}'",
                    severity=ThreatSeverityLevel.HIGH,
                    weight=12,
                    confidence=0.95,
                    source="email_headers",
                )
            )

    # 2. From vs Reply-To domain mismatch
    if meta.from_address and meta.reply_to:
        from_dom = meta.from_address.split("@")[-1].strip(">").strip().lower()
        reply_dom = meta.reply_to.split("@")[-1].strip(">").strip().lower()
        if from_dom and reply_dom and from_dom != reply_dom:
            indicators.append(
                ThreatIndicator(
                    id="SENDER_REPLY_TO_MISMATCH",
                    category=ThreatCategory.SENDER,
                    name="Reply-To Redirection Mismatch",
                    description="Replies are explicitly routed to an external recipient domain rather than the sender address.",
                    evidence=f"Sender: '{meta.from_address}' directs replies to: '{meta.reply_to}'",
                    severity=ThreatSeverityLevel.HIGH,
                    weight=15,
                    confidence=0.95,
                    source="email_headers",
                )
            )

    # 3. Authority Title Impersonation in Display Name
    from_raw = meta.from_address.lower()
    for title in AUTHORITY_TITLES:
        if title in from_raw:
            # If authority title is in display name, check if sender is using generic or non-internal address
            indicators.append(
                ThreatIndicator(
                    id="SENDER_AUTHORITY_IMPERSONATION",
                    category=ThreatCategory.SENDER,
                    name="Authority / Executive Display-Name Impersonation",
                    description="Display name contains executive, IT, or payroll authority titles commonly spoofed in BEC attacks.",
                    evidence=f"From display title '{title}' identified in '{meta.from_address}'",
                    severity=ThreatSeverityLevel.MEDIUM,
                    weight=10,
                    confidence=0.85,
                    source="sender_metadata",
                )
            )
            break

    return indicators


def detect_url_and_domain_indicators(forensic: EmailForensicResult) -> List[ThreatIndicator]:
    """
    Detects typosquatting, lookalike brand domains, IP-based URLs, and suspicious URL paths.
    """
    indicators: List[ThreatIndicator] = []
    seen_ids: Set[str] = set()

    for url_obj in forensic.urls:
        domain = url_obj.domain.lower()
        full_url = url_obj.normalized_url

        # 1. IP-based URL
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', domain):
            ind_id = f"URL_IP_HOST_{domain}"
            if ind_id not in seen_ids:
                seen_ids.add(ind_id)
                indicators.append(
                    ThreatIndicator(
                        id="URL_IP_BASED_HOST",
                        category=ThreatCategory.URL,
                        name="IP-Based URL Host",
                        description="URL points directly to a raw IP address rather than a registered hostname.",
                        evidence=f"Direct IP URL: '{full_url}'",
                        severity=ThreatSeverityLevel.HIGH,
                        weight=12,
                        confidence=0.95,
                        source="url_extraction",
                    )
                )

        # 2. Non-standard port
        if url_obj.port and url_obj.port not in (80, 443):
            ind_id = f"URL_PORT_{url_obj.port}"
            if ind_id not in seen_ids:
                seen_ids.add(ind_id)
                indicators.append(
                    ThreatIndicator(
                        id="URL_SUSPICIOUS_PORT",
                        category=ThreatCategory.URL,
                        name="Non-Standard Destination Port in URL",
                        description="URL connects over a non-standard HTTP/HTTPS port frequently associated with attacker staging servers.",
                        evidence=f"URL with custom port :{url_obj.port} -> '{full_url}'",
                        severity=ThreatSeverityLevel.MEDIUM,
                        weight=8,
                        confidence=0.9,
                        source="url_extraction",
                    )
                )

        # 3. Lookalike regex / typosquatting
        for pattern, brand in LOOKALIKE_PATTERNS:
            if re.search(pattern, domain):
                ind_id = f"DOMAIN_LOOKALIKE_{brand}"
                if ind_id not in seen_ids:
                    seen_ids.add(ind_id)
                    indicators.append(
                        ThreatIndicator(
                            id="DOMAIN_LOOKALIKE_BRAND",
                            category=ThreatCategory.DOMAIN,
                            name=f"Lookalike / Typosquatted Domain ({brand.capitalize()})",
                            description=f"Domain contains character substitutions or lookalike structure mimicking '{brand}'.",
                            evidence=f"Domain '{domain}' resembles brand '{brand}'",
                            severity=ThreatSeverityLevel.CRITICAL,
                            weight=20,
                            confidence=0.95,
                            source="domain_analysis",
                        )
                    )

        # 4. Credential phishing path
        if re.search(r'/(?:auth|login|signin|portal|verify|account|password|secure)', url_obj.path, re.IGNORECASE):
            ind_id = f"URL_PHISH_PATH_{url_obj.domain}"
            if ind_id not in seen_ids:
                seen_ids.add(ind_id)
                indicators.append(
                    ThreatIndicator(
                        id="URL_CREDENTIAL_PHISH_PATH",
                        category=ThreatCategory.URL,
                        name="Credential Capture Path in URL",
                        description="URL path targets authentication or login workflows on third-party infrastructure.",
                        evidence=f"Authentication path '{url_obj.path}' on host '{url_obj.domain}'",
                        severity=ThreatSeverityLevel.MEDIUM,
                        weight=10,
                        confidence=0.85,
                        source="url_extraction",
                    )
                )

    # 5. Domain homoglyph / punycode check
    for dom_obj in forensic.domains:
        d = dom_obj.domain.lower()
        if d.startswith("xn--") or "xn--" in d:
            indicators.append(
                ThreatIndicator(
                    id="DOMAIN_PUNYCODE_HOMOGLYPH",
                    category=ThreatCategory.DOMAIN,
                    name="Punycode / IDN Homoglyph Domain",
                    description="Internationalized domain name (Punycode) detected, often used to spoof Latin characters with Unicode lookalikes.",
                    evidence=f"Punycode domain: '{d}'",
                    severity=ThreatSeverityLevel.HIGH,
                    weight=15,
                    confidence=0.95,
                    source="domain_analysis",
                )
            )

    return indicators


def detect_social_engineering_indicators(forensic: EmailForensicResult) -> List[ThreatIndicator]:
    """
    Detects social engineering triggers in email subject and normalized body text.
    """
    indicators: List[ThreatIndicator] = []
    text_content = f"{forensic.metadata.subject} \n {forensic.body_analysis.normalized_text_preview}"

    # 1. Financial / Wire Fraud triggers
    fin_matches = FINANCIAL_REGEX.findall(text_content)
    if fin_matches:
        indicators.append(
            ThreatIndicator(
                id="SOCENG_FINANCIAL_PRESSURE",
                category=ThreatCategory.SOCIAL_ENGINEERING,
                name="Urgent Financial / Wire Transfer Request",
                description="Email text contains requests for urgent payments, invoice authorizations, or bank wire modifications.",
                evidence=f"Financial keywords: {', '.join(set(fin_matches[:3]))}",
                severity=ThreatSeverityLevel.HIGH,
                weight=14,
                confidence=0.9,
                source="nlp_body_analysis",
            )
        )

    # 2. Urgency & Time Pressure triggers
    urg_matches = URGENCY_REGEX.findall(text_content)
    if urg_matches:
        indicators.append(
            ThreatIndicator(
                id="SOCENG_URGENCY_PRESSURE",
                category=ThreatCategory.SOCIAL_ENGINEERING,
                name="Artificial Urgency & Time-Pressure Language",
                description="Message induces panic or artificial time limits to bypass normal verification procedures.",
                evidence=f"Urgency phrases: {', '.join(set(urg_matches[:3]))}",
                severity=ThreatSeverityLevel.MEDIUM,
                weight=10,
                confidence=0.88,
                source="nlp_body_analysis",
            )
        )

    # 3. Credential Harvesting triggers
    cred_matches = CREDENTIAL_REGEX.findall(text_content)
    if cred_matches:
        indicators.append(
            ThreatIndicator(
                id="SOCENG_CREDENTIAL_HARVESTING",
                category=ThreatCategory.SOCIAL_ENGINEERING,
                name="Credential Harvesting / Account Verification Prompt",
                description="Message prompts user to log in, verify credentials, or update expired passwords.",
                evidence=f"Credential phrases: {', '.join(set(cred_matches[:3]))}",
                severity=ThreatSeverityLevel.HIGH,
                weight=14,
                confidence=0.9,
                source="nlp_body_analysis",
            )
        )

    # 4. Secrecy / Confidentiality triggers
    sec_matches = SECRECY_REGEX.findall(text_content)
    if sec_matches:
        indicators.append(
            ThreatIndicator(
                id="SOCENG_SECRECY_PRESSURE",
                category=ThreatCategory.SOCIAL_ENGINEERING,
                name="Strict Secrecy / Out-of-Band Prevention",
                description="Sender instructs recipient not to communicate with colleagues or verify instructions through normal channels.",
                evidence=f"Secrecy phrases: {', '.join(set(sec_matches[:3]))}",
                severity=ThreatSeverityLevel.MEDIUM,
                weight=10,
                confidence=0.85,
                source="nlp_body_analysis",
            )
        )

    return indicators


def detect_attachment_indicators(forensic: EmailForensicResult) -> List[ThreatIndicator]:
    """
    Detects dangerous attachment extensions, double extensions, and script payloads.
    """
    indicators: List[ThreatIndicator] = []
    suspicious_exts = {".html", ".htm", ".exe", ".vbs", ".js", ".bat", ".ps1", ".scr", ".iso", ".img", ".wsf"}
    macro_exts = {".docm", ".xlsm", ".pptm", ".dotm"}

    for att in forensic.attachments:
        fname = att.filename.lower()
        ext = att.extension.lower()

        # 1. Double extension detection (e.g. .pdf.html, .invoice.doc.exe)
        parts = fname.split(".")
        if len(parts) > 2 and f".{parts[-1]}" in suspicious_exts:
            indicators.append(
                ThreatIndicator(
                    id="ATTACH_DOUBLE_EXTENSION",
                    category=ThreatCategory.ATTACHMENT,
                    name="Double Extension Attachment Obfuscation",
                    description="Attachment disguises its true file format using multiple file extensions (e.g. filename.pdf.html).",
                    evidence=f"Attachment '{att.filename}' hides '{ext}' payload behind '{parts[-2]}'",
                    severity=ThreatSeverityLevel.CRITICAL,
                    weight=15,
                    confidence=1.0,
                    source="attachment_metadata",
                )
            )

        # 2. Executable or HTML/script attachment
        elif ext in suspicious_exts:
            indicators.append(
                ThreatIndicator(
                    id="ATTACH_SCRIPT_OR_EXECUTABLE",
                    category=ThreatCategory.ATTACHMENT,
                    name=f"Script / HTML Attachment ({ext})",
                    description="Attachment carries active HTML or script content commonly used for offline credential harvesting forms.",
                    evidence=f"Attachment '{att.filename}' with extension '{ext}'",
                    severity=ThreatSeverityLevel.HIGH,
                    weight=12,
                    confidence=1.0,
                    source="attachment_metadata",
                )
            )

        # 3. Macro enabled document
        elif ext in macro_exts:
            indicators.append(
                ThreatIndicator(
                    id="ATTACH_MACRO_ENABLED",
                    category=ThreatCategory.ATTACHMENT,
                    name="Macro-Enabled Office Document",
                    description="Attachment contains VBA macros capable of executing arbitrary code upon opening.",
                    evidence=f"Attachment '{att.filename}' is a macro-enabled container ({ext})",
                    severity=ThreatSeverityLevel.HIGH,
                    weight=10,
                    confidence=0.95,
                    source="attachment_metadata",
                )
            )

    return indicators


def detect_route_indicators(forensic: EmailForensicResult) -> List[ThreatIndicator]:
    """
    Detects route and transit hop anomalies in Received headers.
    """
    indicators: List[ThreatIndicator] = []

    if len(forensic.received_chain) == 1:
        # Only single hop recorded
        hop = forensic.received_chain[0]
        indicators.append(
            ThreatIndicator(
                id="ROUTE_DIRECT_INBOUND_HOP",
                category=ThreatCategory.HEADER_ROUTE,
                name="Direct Single-Hop Delivery",
                description="Message was delivered directly to the MX without intermediate relay traces.",
                evidence=f"Single Received hop from '{hop.from_host or 'unknown'}'",
                severity=ThreatSeverityLevel.LOW,
                weight=4,
                confidence=0.7,
                source="received_chain",
            )
        )

    return indicators


def detect_correlation_indicators(
    forensic: EmailForensicResult, correlation: Optional[Any] = None
) -> List[ThreatIndicator]:
    """
    Detects cross-entity threat correlation signals connecting emails, domains, URLs, and IPs.
    """
    indicators: List[ThreatIndicator] = []

    if correlation and hasattr(correlation, "signals"):
        sev_map = {
            "CRITICAL": ThreatSeverityLevel.CRITICAL,
            "HIGH": ThreatSeverityLevel.HIGH,
            "MEDIUM": ThreatSeverityLevel.MEDIUM,
            "LOW": ThreatSeverityLevel.LOW,
            "INFO": ThreatSeverityLevel.CLEAN,
        }
        for sig in correlation.signals:
            indicators.append(
                ThreatIndicator(
                    id=sig.signal_id,
                    category=ThreatCategory.CORRELATION,
                    name=sig.title,
                    description=sig.description,
                    evidence=f"{sig.title}: {sig.description} (Entities: {', '.join(sig.entities_involved)})",
                    severity=sev_map.get(sig.severity, ThreatSeverityLevel.MEDIUM),
                    weight=sig.weight,
                    confidence=0.9,
                    source="indicator_correlation_engine",
                )
            )
        return indicators

    # Deterministic fallback when correlation bundle is not explicitly precomputed:
    meta = forensic.metadata
    from_dom = meta.from_address.split("@")[-1].strip(">").strip().lower() if meta.from_address and "@" in meta.from_address else ""
    reply_dom = meta.reply_to.split("@")[-1].strip(">").strip().lower() if meta.reply_to and "@" in meta.reply_to else ""

    # 1. Sender vs Reply-To mismatch signal
    if from_dom and reply_dom and from_dom != reply_dom:
        indicators.append(
            ThreatIndicator(
                id="CORR_SENDER_REPLYTO_MISMATCH",
                category=ThreatCategory.CORRELATION,
                name="Sender and Reply-To Domain Discrepancy",
                description="Cross-entity correlation identified a divergence between visible sender domain and reply-to destination.",
                evidence=f"Sender domain '{from_dom}' diverges from reply recipient '{reply_dom}'",
                severity=ThreatSeverityLevel.HIGH,
                weight=6.0,
                confidence=0.95,
                source="indicator_correlation_engine",
            )
        )

    # 2. Raw IP host in URL
    ip_urls = [u for u in forensic.urls if getattr(u, "is_ip", False) or (u.domain and u.domain.replace(".", "").isdigit())]
    if ip_urls:
        indicators.append(
            ThreatIndicator(
                id="CORR_URL_IP_HOSTNAME",
                category=ThreatCategory.CORRELATION,
                name="Direct IP Address in Hyperlink",
                description="Email body contains URLs targeting direct IP addresses rather than domain names.",
                evidence=f"Found {len(ip_urls)} link(s) with raw IP destinations (e.g. '{ip_urls[0].url}')",
                severity=ThreatSeverityLevel.HIGH,
                weight=5.0,
                confidence=0.95,
                source="indicator_correlation_engine",
            )
        )

    # 3. Disposable email domain
    try:
        from app.services.intelligence.providers.email_provider import DISPOSABLE_EMAIL_DOMAINS
        if from_dom in DISPOSABLE_EMAIL_DOMAINS:
            indicators.append(
                ThreatIndicator(
                    id="CORR_DISPOSABLE_EMAIL_SENDER",
                    category=ThreatCategory.CORRELATION,
                    name="Disposable Email Provider Detected",
                    description="Sender utilizes a disposable/temporary email address provider to evade attribution.",
                    evidence=f"Sender domain '{from_dom}' is in the known disposable email directory",
                    severity=ThreatSeverityLevel.HIGH,
                    weight=6.0,
                    confidence=0.95,
                    source="indicator_correlation_engine",
                )
            )
    except Exception:
        pass

    return indicators


def detect_all_indicators(
    forensic: EmailForensicResult, correlation: Optional[Any] = None
) -> List[ThreatIndicator]:
    """
    Executes all observable threat indicator detectors across the forensic result.
    """
    indicators: List[ThreatIndicator] = []
    indicators.extend(detect_authentication_indicators(forensic))
    indicators.extend(detect_sender_indicators(forensic))
    indicators.extend(detect_url_and_domain_indicators(forensic))
    indicators.extend(detect_social_engineering_indicators(forensic))
    indicators.extend(detect_attachment_indicators(forensic))
    indicators.extend(detect_route_indicators(forensic))
    indicators.extend(detect_correlation_indicators(forensic, correlation))
    return indicators
