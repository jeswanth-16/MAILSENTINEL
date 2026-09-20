# MAILSENTINEL — SOC Security Architecture & Access Control Specification

## 1. Executive Security Summary

MAILSENTINEL is an enterprise-grade cybersecurity platform for email threat detection, forensic intelligence, incident response, and blockchain evidence integrity. **Step 14** hardens the platform with production-grade Zero-Trust authentication, Role-Based Access Control (RBAC), cryptographic credential hashing, tamper-resistant session tokens, HTTP security headers, sliding-window rate limiting, and immutable security audit logging.

---

## 2. Authentication & Identity Management

### 2.1 Cryptographic Password Storage
* **Algorithm**: PBKDF2-HMAC-SHA256
* **Iterations**: `200,000` rounds
* **Salt**: Cryptographically secure 16-byte random hex salt (`secrets.token_hex(16)`)
* **Format**: `pbkdf2_sha256$<iterations>$<salt>$<hash>`
* **Verification**: Constant-time comparison (`hmac.compare_digest`) to eliminate timing side-channel attacks.

### 2.2 Pre-Seeded Default SOC Identities
For demonstration and operational evaluation, the system provisions 6 pre-configured SOC accounts:

| Role | Email | Default Password | Operational Authority |
| :--- | :--- | :--- | :--- |
| **ADMIN** | `admin@mailsentinel.local` | `Admin@12345!` | Full system governance, user provisioning, tamper simulation |
| **SENIOR_ANALYST** | `senior@mailsentinel.local` | `Senior@12345!` | Forensics, AI correlation, containment execution, case closure |
| **SOC_ANALYST** | `analyst@mailsentinel.local` | `Analyst@12345!` | Email analysis, triage, risk scoring, proposing case actions |
| **INCIDENT_RESPONDER** | `responder@mailsentinel.local` | `Responder@12345!` | Containment execution, host isolation, firewall/account actions |
| **AUDITOR** | `auditor@mailsentinel.local` | `Auditor@12345!` | Read-only compliance audit, blockchain proof verification, logs |
| **VIEWER** | `viewer@mailsentinel.local` | `Viewer@12345!` | Executive dashboards, case summaries, report inspection |

### 2.3 Account Lockout & Brute-Force Defense
* **Max Consecutive Failures**: `5` failed attempts
* **Lockout Duration**: `15` minutes
* **Tracking**: Per-account atomic counter with automatic unlock timestamp.
* **Audit**: Every failed attempt and lockout event is recorded in the security audit logger.

---

## 3. Session & Token Architecture

* **Format**: Signed JSON Web Tokens (JWT / RFC 7519)
* **Algorithm**: HMAC-SHA256 (`HS256`)
* **Access Token Expiry**: 480 minutes (8 hours)
* **Refresh Token Expiry**: 7 days (opaque secure token)
* **Claims Validation**: Subject (`sub`), Role (`role`), Expiration (`exp`), Issued-At (`iat`), and Unique JWT ID (`jti`) verified on every API request.
* **Revocation/Logout**: Endpoints invalidate active sessions and purge client-side tokens.

---

## 4. Role-Based Access Control (RBAC) Matrix

| Permission Key | Description | ADMIN | SENIOR_ANALYST | SOC_ANALYST | INCIDENT_RESPONDER | AUDITOR | VIEWER |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `dashboard:view` | View SOC Dashboard & Overview | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `email:analyze` | Upload & Forensically Parse .EML | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `investigation:view` | Inspect Investigation Workbench | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `investigation:create` | Launch New Investigation | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `intelligence:view` | Query Threat Intel & Geolocation | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `ai:request` | Trigger AI SOC Specialist Analysis | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `case:view` | View Incident Cases & Details | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `case:create` | Escalate Investigation to Case | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `case:update` | Update Case Notes, Status, Tags | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| `action:propose` | Propose Containment Action | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| `action:approve` | Approve Response Action | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| `action:execute` | Execute Containment Action | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| `case:close` | Close Incident Case with Verdict | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `report:view` | View Forensic Reports & Dossiers | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `report:generate` | Generate PDF / HTML / JSON Dossier | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `evidence:export` | Export Sealed Evidence Package | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| `blockchain:verify` | Verify Proof of Evidence On-Chain | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `blockchain:anchor` | Anchor New Forensic Hash On-Chain | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `blockchain:simulate_tamper`| Simulate Evidence Tampering | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `audit:view` | Inspect SOC Security Audit Trail | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| `users:manage` | Provision & Manage Users/Roles | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `security:config` | Modify Security System Settings | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

---

## 5. Security Headers & Network Protection

All API responses enforce standard production cybersecurity headers via `SecurityHeadersMiddleware`:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:*; frame-ancestors 'none';
```

---

## 6. Rate Limiting & Denial-of-Service Defense

* **Mechanism**: In-memory sliding-window request tracker per client IP address.
* **Default Threshold**: `120 requests/minute` for standard routes; tightened for authentication routes.
* **Response**: `HTTP 429 Too Many Requests` with `Retry-After` header when limit is exceeded.

---

## 7. Security Audit Logging & Redaction

* **Storage**: In-memory thread-safe ring buffer (`SecurityAuditLogger`) with query API (`/api/v1/admin/security/audit-logs`).
* **Logged Events**: User authentication (success/failure/locked), user provisioning, role promotions, account disabling, password resets, containment action execution, case state transitions, and tamper simulations.
* **Sensitive Data Redaction**: Passwords, raw tokens, and authorization secrets are automatically scrubbed from event metadata before persistence.
