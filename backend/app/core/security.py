import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import re
import secrets
from typing import Any, Dict, Optional

from app.core.config import settings


# -------------------------------------------------------------------------
# Password Hashing & Verification (PBKDF2-HMAC-SHA256)
# -------------------------------------------------------------------------

PBKDF2_ITERATIONS = 200_000
HASH_ALGORITHM = "sha256"


def hash_password(password: str) -> str:
    """
    Hashes a password securely using PBKDF2-HMAC-SHA256 with 200,000 rounds
    and a cryptographically random 16-byte salt.
    Format: pbkdf2_sha256$200000$<salt_hex>$<hash_hex>
    """
    if not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against a stored PBKDF2 hash using constant-time comparison.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = parts[2]
        expected_hash = parts[3]

        computed_key = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM,
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )
        return hmac.compare_digest(computed_key.hex(), expected_hash)
    except Exception:
        return False


# -------------------------------------------------------------------------
# Cryptographic Token Handling (HMAC-SHA256 Signed Tokens / JWT Format)
# -------------------------------------------------------------------------

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _base64url_decode(data: str) -> bytes:
    padding = "=" * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ""
    return base64.urlsafe_b64decode((data + padding).encode("utf-8"))


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a cryptographically signed JWT token using HMAC-SHA256.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
        "jti": secrets.token_hex(16),
    })

    header = {"alg": "HS256", "typ": "JWT"}
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_bytes = json.dumps(to_encode, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8")

    header_b64 = _base64url_encode(header_bytes)
    payload_b64 = _base64url_encode(payload_bytes)

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    secret = (settings.AUTH_SECRET_KEY or settings.SECRET_KEY).encode("utf-8")
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    signature_b64 = _base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def create_refresh_token(user_id: str) -> str:
    """
    Creates a long-lived refresh token.
    """
    payload = {
        "sub": user_id,
        "type": "refresh",
    }
    return create_access_token(payload, expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and verifies a JWT token. Returns payload dict or None if invalid or expired.
    """
    if not token or not isinstance(token, str):
        return None
    
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None

    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    secret = (settings.AUTH_SECRET_KEY or settings.SECRET_KEY).encode("utf-8")
    expected_signature = hmac.new(secret, signing_input, hashlib.sha256).digest()

    try:
        provided_signature = _base64url_decode(signature_b64)
        if not hmac.compare_digest(provided_signature, expected_signature):
            return None

        payload_bytes = _base64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))

        # Verify expiration
        exp = payload.get("exp")
        if exp is not None:
            now_ts = int(datetime.now(timezone.utc).timestamp())
            if now_ts > exp:
                return None  # Expired

        return payload
    except Exception:
        return None


# -------------------------------------------------------------------------
# Input Sanitization & Path Traversal Protections
# -------------------------------------------------------------------------

def generate_sha256(data: bytes) -> str:
    """
    Computes cryptographic SHA-256 hash of arbitrary bytes for evidence integrity.
    """
    return hashlib.sha256(data).hexdigest()


def sanitize_text_input(text: Optional[str]) -> str:
    """
    Sanitizes string inputs to prevent header injection or unexpected control chars.
    """
    if not text:
        return ""
    # Strip null bytes and control chars
    return "".join(c for c in text if c.isprintable() or c in "\r\n\t").strip()


def sanitize_filename(filename: Optional[str]) -> str:
    """
    Sanitizes a filename to prevent path traversal attacks (../, ..\, etc.)
    and stripping forbidden characters.
    """
    if not filename:
        return "unnamed_evidence_file"
    # Extract basename only
    base = os.path.basename(filename.replace("\\", "/"))
    # Remove traversal sequences
    base = base.replace("..", "")
    # Allow alphanumeric, hyphens, underscores, dots
    clean = re.sub(r"[^\w\.\-]", "_", base)
    clean = clean.strip("._")
    return clean or "sanitized_file"


def sanitize_identifier(ident: Optional[str]) -> str:
    """
    Sanitizes identifiers like Case IDs or Investigation IDs (e.g. CASE-2026-00001).
    """
    if not ident:
        return ""
    clean = re.sub(r"[^\w\-]", "", ident.strip())
    return clean
