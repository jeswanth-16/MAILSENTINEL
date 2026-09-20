# MAILSENTINEL — AI-Powered Email Threat Detection & Forensic Intelligence Platform

> **Theme**: Blockchain & Cybersecurity (Smart India Hackathon Prototype)  
> **Core Philosophy**: *"From detecting a suspicious email to reconstructing and preserving the evidence behind the threat."*

---

## 1. Executive Overview

**MAILSENTINEL** is an investigation-grade cybersecurity and digital forensics platform designed for Security Operations Centers (SOC) and Incident Response teams. Rather than acting as a superficial spam filter, MAILSENTINEL deconstructs suspicious `.EML` files into structured forensic investigations.

### Complete Investigation & Integrity Workflow
```text
Suspicious .EML
       │
       ▼
Email Forensics (RFC 5322 Parsing & Attachment Hashing)
       │
       ▼
Header & Authentication Analysis (SPF, DKIM, DMARC, Return-Path, Received Hop Chain)
       │
       ▼
Threat Detection (7 Categories) + Explainable Risk Scoring (0 - 100)
       │
       ▼
Threat Intelligence (RFC IP Classifier, GeoIP, Punycode / Domain Homoglyph Analyzer)
       │
       ▼
Forensic Timeline & Attack Graph Reconstruction
       │
       ▼
Canonical Evidence Package & SHA-256 Fingerprint
       │
       ▼
Blockchain Integrity Anchor (Demo Ledger / EVM Testnet)
       │
       ▼
Unified Case Management & SOC Investigation Workbench
       │
       ▼
Executive Dossier & Multi-Format Report Generation
```

---

## 2. Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, React Flow, Leaflet, React Router DOM |
| **Backend** | Python 3.12, FastAPI, Uvicorn, Pydantic v2, Python-dotenv, Pytest |
| **Forensics & AI** | MIME/RFC 5322 Engine, Deterministic Risk Matrix + AI/NLP Semantic Analyzer, SHA-256 Hashing |
| **Blockchain** | Solidity Smart Contract (`EvidenceRegistry.sol`), Demo Blockchain Provider, EVM Testnet Provider |
| **Visualizations** | React Flow (Evidence Graph), Leaflet (Observed IP Infrastructure Map), Interactive Timeline |

---

## 3. Blockchain Evidence Integrity Architecture

### Design Principle & Privacy Guard
In compliance with digital forensics and privacy regulations (GDPR/HIPAA):
- **RAW EMAIL BODIES, ATTACHMENTS, PASSWORDS, AND PII ARE NEVER STORED ON-CHAIN.**
- Only cryptographic SHA-256 digests of the canonical evidence package are anchored on the blockchain ledger.

### Deterministic Canonical Serialization Method
To prevent hash drift caused by dictionary key ordering or JSON whitespace:
1. All dictionary keys are recursively sorted lexicographically (`sort_keys=True`).
2. Compact separators `(',', ':')` and `ensure_ascii=True` are enforced.
3. Variable / self-referential fields (`canonical_digest`) are excluded during serialization.
4. Serialized UTF-8 bytes are hashed with SHA-256 to produce the authoritative evidence fingerprint:

$$\text{Canonical JSON} \xrightarrow{\text{UTF-8}} \text{Bytes} \xrightarrow{\text{SHA-256}} \text{Evidence Digest (64 Hex Characters)}$$

### Provider Abstraction
- **Demo Blockchain Provider** (`MAILSENTINEL-DEMO-CHAIN`): Local immutable ledger maintaining realistic block numbers, transaction hashes (`0x...`), previous block hashes, and verification without requiring cryptocurrency, gas, or API keys.
- **EVM Testnet Provider**: Connects to EVM-compatible testnets (e.g. Ethereum Sepolia, Polygon Amoy) via `.env` configuration, falling back safely to the Demo Provider when unconfigured.

### Smart Contract (`EvidenceRegistry.sol`)
Located at `blockchain/contracts/EvidenceRegistry.sol`:
- `anchorEvidence(string evidenceId, string investigationId, bytes32 evidenceHash)`
- `verifyEvidence(string evidenceId, bytes32 currentEvidenceHash) returns (bool isMatch, uint256 timestamp, bytes32 anchoredHash)`
- Emits `EvidenceAnchored` events for real-time audit trails.

---

## 4. API Endpoints Reference

### Email Forensics & Risk
- `POST /api/v1/analysis/email` — Ingest raw `.EML` container and extract forensic artifacts.
- `POST /api/v1/analysis/threat` — Evaluate indicators and compute explainable risk score (0-100).

### Threat Intelligence & Geolocation
- `POST /api/v1/intelligence/ip` — RFC IP classification and geolocation lookup.
- `POST /api/v1/intelligence/domain` — Punycode, TLD risk, and homoglyph analysis.
- `POST /api/v1/intelligence/url` — URL host and credential path analysis.
- `POST /api/v1/intelligence/investigation/{id}` — Batch entity enrichment.

### Timeline & Attack Graph
- `GET /api/v1/investigations/{id}/timeline` — Chronological forensic hop timeline.
- `GET /api/v1/investigations/{id}/graph` — Interactive evidence relationship graph.

### Case Management & Unified Investigation
- `GET /api/v1/investigations` — Filterable active investigations queue.
- `POST /api/v1/investigations` — Create manual investigation case.
- `GET /api/v1/investigations/stats/dashboard` — Live SOC metrics and threat distributions.
- `POST /api/v1/investigations/run-full` — 1-click automated 10-step SOC triage pipeline (.EML to case).
- `GET /api/v1/investigations/{id}` — Retrieve single investigation details.
- `PATCH /api/v1/investigations/{id}` — Update case properties.
- `GET /api/v1/investigations/{id}/overview` — Aggregated multi-tab investigation overview.
- `POST /api/v1/investigations/{id}/notes` — Append analyst note to audit trail.
- `DELETE /api/v1/investigations/{id}/notes/{note_id}` — Delete analyst note from audit log.
- `POST /api/v1/investigations/{id}/assign` — Assign SOC analyst.
- `POST /api/v1/investigations/{id}/status` — Update case lifecycle status.
- `POST /api/v1/investigations/{id}/escalate` — Escalate to Tier 3 Incident Response.
- `POST /api/v1/investigations/{id}/false-positive` — Categorize as false positive.
- `GET /api/v1/investigations/{id}/report` — Structured forensic report dossier bundle.

### Blockchain Evidence Integrity
- `POST /api/v1/evidence/package/{investigation_id}` — Create canonical evidence package bundle.
- `POST /api/v1/blockchain/anchor/{evidence_id}` — Anchor evidence digest on-chain.
- `POST /api/v1/blockchain/verify/{evidence_id}` — Recompute digest and verify against on-chain anchor.
- `POST /api/v1/blockchain/tamper-simulate/{evidence_id}` — Simulate memory modification for demo tamper detection.
- `POST /api/v1/blockchain/tamper-reset/{evidence_id}` — Restore authentic evidence state.
- `GET /api/v1/blockchain/evidence/{evidence_id}` — Retrieve on-chain anchor record.
- `GET /api/v1/blockchain/ledger` — View full immutable blockchain ledger.
- `GET /api/v1/blockchain/custody/{investigation_id}` — Audit chain of custody timeline.

### Automated Threat Analysis & Forensic Decision Engine (Phase 4)
- `GET /api/v1/investigations/{id}/assessment` — Retrieve structured, explainable forensic decision assessment.
- `POST /api/v1/investigations/{id}/assessment/recalculate` — Recalculate and persist forensic assessment across all evidence categories.
- `POST /api/v1/ai/analyze/{investigation_id}` — Run AI threat pattern recognition and decision evaluation.
- `GET /api/v1/ai/assessment/{investigation_id}` — Backward-compatible endpoint retrieving structured investigation assessment.
- `GET /api/v1/ai/correlation/{investigation_id}` — Fetch multi-entity correlation findings.
- `GET /api/v1/ai/related-cases/{investigation_id}` — Retrieve cross-case campaign linkages.
- `POST /api/v1/ai/refresh/{investigation_id}` — Force refresh AI and decision engine analysis.

### Incident Response & SOC Case Management
- `GET /api/v1/cases` — Filterable incident cases table (status, priority, verdict, search).
- `GET /api/v1/cases/metrics` — Real-time SOC metrics (Total, Active, P1 Critical, MTTR, Containment Rate).
- `POST /api/v1/cases` — Create or promote investigation into formal incident case.
- `GET /api/v1/cases/{case_id}` — Retrieve full case model with 11-tab data bindings.
- `POST /api/v1/cases/{case_id}/status` — Strict lifecycle state transition engine.
- `POST /api/v1/cases/{case_id}/actions` — Propose standardized response actions.
- `PATCH /api/v1/cases/{case_id}/actions/{action_id}` — Approve, execute, and complete containment actions.
- `POST /api/v1/cases/{case_id}/blockchain/verify` — Live cryptographic case proof on-chain.

### Forensic Reporting, Evidence Export & Case Documentation
- `POST /api/v1/reports/generate/{case_id}` — Generate comprehensive forensic report dossier.
- `GET /api/v1/reports/{case_id}` — Retrieve report JSON model.
- `GET /api/v1/reports/{case_id}/pdf` — Download formal ReportLab digital forensics report PDF.
- `GET /api/v1/reports/{case_id}/json` — Download canonical report JSON.
- `GET /api/v1/reports/{case_id}/iocs.csv` — Download extracted IOCs (IPs, domains, hashes) in CSV.
- `GET /api/v1/reports/{case_id}/timeline.csv` — Download chronological forensic timeline CSV.
- `GET /api/v1/reports/{case_id}/findings.csv` — Download detailed security findings CSV.
- `POST /api/v1/reports/{case_id}/package` — Generate tamper-evident Evidence Package ZIP (with `manifest.json` and artifact SHA-256s).
- `GET /api/v1/reports/{case_id}/manifest` — Fetch cryptographic evidence manifest.
- `POST /api/v1/reports/{report_id}/verify` — Verify report integrity against cryptographic hash.

---

## 5. Getting Started & Development Commands

### Step 1: Running Backend & Tests
```bash
cd backend
python -m pip install -r requirements.txt
python -m pytest -v
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Root: `http://127.0.0.1:8000`
- Swagger UI: `http://127.0.0.1:8000/docs`

### Step 2: Running Frontend
```bash
cd frontend
npm install
npm run build
npm run dev
```
- Frontend Application: `http://localhost:5173`

---

## 6. Demonstration Scenarios

1. **Phishing Investigation (`INV-2026-00001`)**:
   - High-risk BEC wire fraud email (`sample_phishing.eml`).
   - Risk score: **94/100 (CRITICAL)**.
   - Identified indicators: SPF/DMARC failure, homoglyph domain (`paypa1-security.com`), credential URL, double-extension attachment (`.pdf.html`).
   - Anchored on Blockchain: Block `#1042`.
   - Verification: `✓ HASH MATCH • EVIDENCE INTEGRITY VERIFIED`.
   - Tamper Demonstration: Clicking **"Simulate Evidence Modification"** modifies the in-memory bundle, recalculating the hash and triggering an instant `✕ HASH MISMATCH • TAMPER DETECTED` alert.

2. **Clean Email Investigation (`INV-2026-00004`)**:
   - Verified benign internal email (`valid_clean.eml`).
   - Risk score: **4/100 (CLEAN)** with valid DKIM & SPF.

---

## 7. Persistence

MAILSENTINEL uses SQLite for local persistent investigation and case storage.
The database is automatically initialized on application startup.
The path can be configured through `MAILSENTINEL_DB_PATH` (defaults to `mailsentinel.db`).

---

## 8. Threat Intelligence

MAILSENTINEL features a resilient hybrid threat intelligence pipeline combining real-time API verification with local offline databases and thread-safe in-memory caching.

### AbuseIPDB Integration
- **Provider**: Official AbuseIPDB API v2 (`GET /api/v2/check`).
- **Telemetry**: IP reputation, abuse confidence score (0-100), total report counts, usage type, ISP, domain, and last reported timestamp.
- **RFC Boundary Filtering**: Private (RFC 1918), loopback, link-local, multicast, and documentation (RFC 5737) networks are strictly bypassed prior to network or cache calls, preventing accidental leakage of internal infrastructure.

### Configuration
```bash
# Threat Intelligence Configuration (.env)
ABUSEIPDB_API_KEY=your_key_here
INTELLIGENCE_CACHE_TTL=21600
```
- `ABUSEIPDB_API_KEY`: API key for AbuseIPDB v2. If missing, the platform automatically routes queries to offline intelligence.
- `INTELLIGENCE_CACHE_TTL`: Time-to-live for cached intelligence results in seconds (default: `21600`, or 6 hours).

> **Offline Resilience Guarantee**: MAILSENTINEL remains functional without an external threat-intelligence API key through its offline intelligence providers.

### Hybrid Lookup Order & Fallback Behavior
1. **RFC Boundary Filter**: Immediately handles non-routable subnets without network egress.
2. **TTL Cache**: Returns cached entries with `CACHED` delivery status to prevent redundant API queries and rate-limit exhaustion.
3. **Real-Time AbuseIPDB**: Triggered when `ABUSEIPDB_API_KEY` is configured. On HTTP 200, normalizes score and attributes result as `REAL-TIME`.
4. **Offline Intelligence Fallback**: If external API key is omitted, timed out (5s), rate-limited (HTTP 429), or unavailable, queries fall back seamlessly to local reference datasets attributed as `OFFLINE FALLBACK`.
5. **Safe Failure Degradation**: If an unindexed public IP cannot be resolved by either provider, returns a structured `NOT_AVAILABLE` status without crashing investigations.

### Source Attribution
Every lookup result clearly states its data source and delivery state:
- `REAL-TIME`: Live verified against AbuseIPDB API v2.
- `CACHED`: Retrieved from in-memory TTL cache.
- `OFFLINE FALLBACK`: Resolved from curated local threat reference database.
- `UNAVAILABLE`: Provider and offline database unindexed.

---

## 9. Phase 3 — Advanced Indicator Correlation & Multi-Entity Threat Intelligence

Phase 3 introduces cross-entity indicator intelligence and deterministic graph-level correlation across email addresses, domain names, URLs, and IP addresses.

### 9.1 Multi-Entity Intelligence Pipelines
- **Domain Intelligence**:
  - RFC internal/localhost domain detection (`.internal`, `.local`, `.lan`, `.corp`, `.home`, `.test`, `localhost`).
  - IDNA Punycode normalization and homoglyph/lookalike brand detection (e.g. `paypa1`, `micros0ft`).
  - Two-part public suffix extraction (`co.uk`, `com.au`, `org.uk`, etc.) isolating true registrable domains from multi-label hostnames.
  - Transparent attribution tagging: `LOCAL ANALYSIS`, `OFFLINE FALLBACK`, or `CACHED`.
- **URL Intelligence**:
  - Safe URI decomposition extracting scheme, hostname, port, query strings, and credential paths (`login`, `signin`, `auth`, `token`, `verify`, `password`).
  - Strict containment guarantee: **Zero outbound HTTP requests or web scraping**.
  - Host IP classification separating domain names from direct IP links (e.g., `http://185.220.101.5/login.php`).
- **Email Intelligence**:
  - RFC 5322 compliance and syntax verification with display name extraction.
  - Role-based tagging: `SENDER`, `REPLY_TO`, `RETURN_PATH`, `RECIPIENT`.
  - Disposable email provider detection (`mailinator.com`, `guerrillamail.com`, `temp-mail.org`, `10minutemail.com`, etc.).
  - Free webmail provider classification (`gmail.com`, `yahoo.com`, `outlook.com`, etc.).
  - Address normalization and lookalike domain verification.

### 9.2 Correlation Engine
The Correlation Engine constructs an evidence graph mapping cross-indicator relationships and calculating correlation threat signals:

| Relationship Type | Source Entity | Target Entity | Confidence | Description |
| :--- | :--- | :--- | :--- | :--- |
| `URL_HOSTED_ON_DOMAIN` | URL | Registrable Domain | 95% | URL hostname maps to registrable domain |
| `DOMAIN_RESOLVES_TO_IP` | Domain | IP Address | 90% | Domain associated with observed network hop |
| `EMAIL_USES_DOMAIN` | Email Address | Domain | 95% | Email identity belongs to target domain |
| `EMAIL_ROUTED_TO_REPLY_TO` | From Email | Reply-To Email | 90% | Email specifies alternative response mailbox |
| `URL_DIRECT_IP_HOST` | URL | IP Address | 95% | URL directly targets numerical IP host |

#### Correlation Threat Signals:
1. **`SENDER_REPLYTO_DOMAIN_MISMATCH`** (Severity: HIGH, Weight: 8.0)  
   Detected when the `Reply-To` domain differs from the `From` sender domain.
2. **`SENDER_URL_DOMAIN_MISMATCH`** (Severity: MEDIUM, Weight: 5.0)  
   Detected when embedded links navigate to external domains unrelated to the claimed sender organization.
3. **`RAW_IP_URL_HOST`** (Severity: HIGH, Weight: 7.0)  
   Detected when embedded links use numerical IP addresses instead of legitimate domain names.
4. **`MALICIOUS_INFRASTRUCTURE_LINKAGE`** (Severity: CRITICAL, Weight: 10.0)  
   Detected when a sender, domain, or URL resolves to an IP address with known malicious reputation.
5. **`DISPOSABLE_SENDER_DOMAIN`** (Severity: HIGH, Weight: 8.0)  
   Detected when a sender utilizes a temporary/disposable mailbox service.

### 9.3 Threat Scoring Integration & Capping
- Added `ThreatCategory.CORRELATION` ("Correlation") to the explainable risk matrix.
- Enforced a hard weight cap of **15.0 points** for the Correlation category (`CATEGORY_WEIGHT_CAPS[CORRELATION] = 15.0`) to preserve scoring equilibrium and prevent runaway risk scores.

### 9.4 Attack Graph Extensions
Extended the forensic graph model with new edge types:
- `HOSTED_ON`: Links URLs or domains to hosting IP nodes.
- `REPLY_TO`: Links Sender nodes to designated Reply-To mailbox nodes.
- `ATTACHED_TO`: Links attachment payload nodes to email messages.
- `INVOLVED_IN`: Links IOC nodes to investigation cases.
- `BELONGS_TO_DOMAIN`: Links email addresses and subdomains to registrable domains.
- `REFERENCES`: Links threat signals to correlated entity nodes.

### 9.5 Phase 3 API Endpoints
- `POST /api/v1/intelligence/email` — Email syntax, role classification, disposable & lookalike check.
- `POST /api/v1/intelligence/correlate` — Multi-entity cross-indicator correlation engine.
- `GET /api/v1/intelligence/investigation/{id}/correlation` — Retrieve correlated indicators, signals, and evidence graph for an investigation.

---

## 10. Phase 4 — Automated Threat Analysis & Forensic Decision Engine

Phase 4 implements a deterministic, explainable evidence evaluation layer (`ForensicDecisionEngine`) transforming raw indicators and correlation signals into audit-ready forensic decisions.

### 10.1 Deterministic Decision Engine & Scoring Model
- **Explainable Evidence Evaluation**: Aggregates forensic signals across 6 core categories with category caps to maintain scoring equilibrium:
  - `Authentication`: SPF, DKIM, DMARC, Return-Path alignment (Cap: 30.0 pts)
  - `Header Analysis`: Relay anomalies, client discrepancies, hop timeline delays (Cap: 20.0 pts)
  - `Content & Language`: Urgent wire fraud keywords, extortion patterns, BEC phrasing (Cap: 25.0 pts)
  - `Threat Intelligence`: Real-time AbuseIPDB scores, malicious infrastructure, TOR exit nodes (Cap: 25.0 pts)
  - `Correlation`: Sender/Reply-To mismatches, raw IP URLs, disposable senders (Cap: 15.0 pts)
  - `Attachment & Payload`: Executable payloads, double extensions, suspicious script macros (Cap: 25.0 pts)
- **Engine Versioning**: Every assessment is generated with `engine_version = "4.0"` and cryptographic hash verification.

### 10.2 Structured Assessment Model & Confidence Levels
- **`InvestigationAssessment`**: Standardized schema extending `AIAnalystAssessment` for 100% backward compatibility:
  - `threat_verdict`: `MALICIOUS`, `HIGH_RISK`, `SUSPICIOUS`, `LOW_RISK`, `BENIGN`, `UNKNOWN`.
  - `confidence`: `VERY_HIGH`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
  - `risk_score`: Calibrated numerical score (0 - 100).
  - `why_verdict`: Top high-impact evidence findings explaining the verdict with category contributions.
  - `contradictions`: Detected security conflicts and their analyst impact.
  - `investigation_gaps`: Missing or unindexed telemetry items with forensic statuses.
  - `mitre_techniques`: Grounded MITRE ATT&CK techniques with observable evidence references.
  - `attack_chain`: Factual chronological attack progression narrative.
  - `recommended_actions`: Prioritized containment and remediation steps.
  - `investigation_questions`: Targeted forensic inquiry prompts for SOC analysts.

### 10.3 Contradiction Detection
The engine systematically detects deceptive or conflicting signals in email forensic telemetry:
1. **Authentication Pass with Malicious Intent**: SPF/DMARC passes, but the email redirects to an external Reply-To or lookalike brand domain.
2. **Clean Network IP with Malicious Content/Payload**: Delivery IP has 0% abuse score, but the message contains phishing URLs, credential harvesters, or high-risk attachments.
3. **Unindexed / Private IP with Malicious Indicators**: Local/RFC-private hops where external intelligence is unavailable (`NOT_AVAILABLE`), preventing false "clean" assumptions.

### 10.4 Grounded MITRE ATT&CK Mapping
Techniques are mapped **strictly** when grounded in concrete, observable telemetry (never hallmarked or fabricated):
- **`T1566`** (Phishing): Grounded in failed authentication or phishing markers.
- **`T1566.002`** (Spearphishing Link): Grounded in detected suspicious/credential URLs.
- **`T1566.001`** (Spearphishing Attachment): Grounded in malicious/suspicious attachments.
- **`T1583.001`** (Domains): Grounded in Punycode or brand lookalike domains.
- **`T1204`** (User Execution): Grounded in urgent call-to-action BEC language or credentials prompt.

### 10.5 Factual Attack Chain Reconstruction
Reconstructs an unembellished 4-stage attack narrative directly from forensic telemetry:
1. **Initial Delivery**: Originating IP, country, and mail server hop latency.
2. **Identity & Authentication**: SPF, DKIM, and DMARC alignment status.
3. **Payload / Weaponization**: Embedded URLs, lookalikes, or attachment hashes.
4. **Intended Impact**: Wire fraud, credential harvesting, or extortion objective.

### 10.6 Investigation Gap Analysis
Explicitly documents investigative blind spots without assuming absence of evidence is evidence of absence:
- `NOT_AVAILABLE`: Unindexed public indicator without external threat intelligence.
- `NOT_APPLICABLE`: RFC private/internal IP or local development domain.
- `NOT_CHECKED`: Intelligence provider disabled or skipped during quick triage.
- `PROVIDER_UNAVAILABLE`: Upstream provider timeout (5s) or HTTP 429 rate limit.

### 10.7 SQLite Persistence & Case Audit Logging
- **`assessments` Table**: High-performance SQLite table indexing `investigation_id` and `verdict`.
- **`AssessmentSqliteRepository`**: Parameterized SQL CRUD operations with transparent JSON serialization surviving server restarts.
- **Audit Trail Note**: Automatically logs an audit note in the case record on assessment creation/recalculation:
  ```text
  [Decision Engine v4.0] Assessment generated: MALICIOUS (Score: 94/100, Confidence: VERY_HIGH)
  ```

### 10.8 SOC Decision Workbench Integration
Tab 4 (`AI_ANALYST`) in the Investigation Workbench is upgraded to the **Automated Threat Analysis & Forensic Decision Engine**:
- Executive KPI Header with Verdict badge, Severity, Score, Confidence, and Recalculate button.
- Contradiction Alert Box highlighting deceptive indicators.
- "Why this verdict?" evidence findings with individual point contributions.
- Category Weight Contributions grid with progress bars and score caps.
- Grounded MITRE ATT&CK Technique Matrix with evidence mapping.
- Observed Attack Progression Narrative chain.
- Investigation Gap Analysis cards.
- Targeted Analyst Inquiry Questions & Recommended SOC Actions.

---

## 11. Phase 5 — Final Productization, Hardening, SOC Polish & Demo Readiness

Phase 5 delivers the final engineering pass across the entire MAILSENTINEL platform, unifying the complete pipeline:
```text
EMAIL / EVIDENCE
       ↓
INGESTION & FORENSIC EXTRACTION
       ↓
INDICATOR EXTRACTION
       ↓
THREAT INTELLIGENCE (AbuseIPDB + RFC Subnet Filter + TTL Cache)
       ↓
MULTI-ENTITY CORRELATION (Domain / URL / Email / IP Cross-Links)
       ↓
ATTACK GRAPH (Hardened Invariants, No Dangling / Duplicate Edges)
       ↓
RISK & THREAT ENGINE (Explainable Matrix with Category Caps)
       ↓
FORENSIC DECISION ENGINE (Deterministic Verdicts & Confidence)
       ↓
AI NARRATIVE & MITRE MAPPING (Grounded in Observable Evidence Only)
       ↓
PERSISTENT ASSESSMENT (SQLite Write-Through & Case Audit Trail)
       ↓
SOC DECISION WORKBENCH (KPI Cards, Contradictions, Gaps, Actions)
       ↓
INCIDENT CASE MANAGEMENT & REPORT DOSSIER EXPORT
```

### 11.1 Key Hardening & Integration Upgrades
- **Attack Graph Integrity**: Strict invariant verification ensuring zero dangling edges (both source and target nodes must exist in the node set) and zero duplicate edges. Consolidated duplicate URL-to-domain edges into canonical `HOSTED_ON` relationships.
- **Contradiction Engine Expansion**: Explicitly covers four deterministic security contradiction scenarios:
  - `CONTRA-001`: Valid SPF/DMARC cryptographic pass vs. divergent Reply-To routing or brand homoglyphs.
  - `CONTRA-002`: Benign network relay IP reputation (0% abuse) delivering suspicious links or attachments.
  - `CONTRA-003`: Unindexed external threat feed lookups defaulting violation (strictly classified as UNKNOWN, never CLEAN).
  - `CONTRA-004`: Legitimate organizational sender identity diverting users to lookalike external destination links.
- **Taxonomy Harmonization**: Aligned `IncidentVerdict` with `ThreatVerdict` across backend and frontend (`MALICIOUS`, `HIGH_RISK`, `SUSPICIOUS`, `LOW_RISK`, `BENIGN`, `UNKNOWN`), ensuring case promotion directly inherits the authoritative decision engine verdict.
- **Investigation Gap Hardening**: Enforces that absence of external threat intelligence (`NOT_AVAILABLE`, `NOT_APPLICABLE`, `PROVIDER_UNAVAILABLE`) is never interpreted as clean evidence.
- **API Hardening & 404 Safety**: All assessment endpoints (`/investigations/{id}/assessment`, `/recalculate`, `/ai/analyze`, `/ai/assessment`, `/ai/refresh`) strictly validate case existence, returning clean HTTP 404 responses for missing investigations instead of defaulting to ungrounded placeholder objects.

### 11.2 Deterministic Demo Scenarios
MAILSENTINEL ships with 4 pre-seeded, fully deterministic demonstration cases:
1. **DEMO 1 — MALICIOUS PHISHING (`INV-2026-00001`)**:
   - Executive wire fraud BEC lure impersonating PayPal (`paypa1-security.com`).
   - Failed SPF/DMARC transport, known malicious IP relay (`185.220.101.5`), and double-extension payload (`.pdf.html`).
   - Outcome: **MALICIOUS** verdict, **94/100** score, **VERY_HIGH** confidence, grounded MITRE T1566/T1566.002/T1583.001/T1204 techniques.
2. **DEMO 2 — BENIGN (`INV-2026-00004`)**:
   - Verified internal corporate townhall announcement.
   - Passing SPF, DKIM, and DMARC authentication; clean internal routing; zero suspicious links or attachments.
   - Outcome: **BENIGN** verdict, **4/100** score, **VERY_HIGH** confidence, 0 primary threat indicators, 0 MITRE techniques.
3. **DEMO 3 — CONTRADICTORY SIGNALS (`INV-2026-00003`)**:
   - Tax clearance notification passing SPF and DMARC verification from legitimate bank domain.
   - Divergent Reply-To header (`divert-capture@attacker-drop.com`) and body containing lookalike credential portal link (`http://paypa1-security.com/login.php`).
   - Outcome: Triggers **`CONTRA-001`** and **`CONTRA-004`** contradiction alerts in the Workbench, exposing identity redirection despite transport pass.
4. **DEMO 4 — INCOMPLETE INTELLIGENCE (`INV-2026-00005`)**:
   - Internal scanner alert with private subnet hop (`10.0.4.25`) and unindexed remote link host (`198.51.100.42`).
   - Outcome: Identifies **`NOT_APPLICABLE`** (RFC 1918 private relay) and **`PROVIDER_UNAVAILABLE`** gaps; strictly refuses to assume clean status.

---

## 12. Verification & Test Suite

The platform includes comprehensive test suites across all five phases:
```bash
# Run full backend test suite
cd backend
python -m pytest -q
# Result: 134 passed in ~18.1 seconds

# Run Phase 5 specific integration & demo tests
python -m pytest tests/test_phase5_final_integration.py -v
```
All frontend assets compile cleanly under strict TypeScript checking:
```bash
cd frontend
npm run build
# Result: 0 errors, built in ~8.5s
```
