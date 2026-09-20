import hashlib
import json
from typing import Any, Dict

from app.services.blockchain.models import EvidencePackage


def compute_sha256(data: bytes) -> str:
    """Computes standard hexadecimal SHA-256 digest of input byte sequence."""
    return hashlib.sha256(data).hexdigest().lower()


def canonicalize_dict(d: Any) -> Any:
    """
    Recursively sorts and normalizes nested dictionaries and lists
    to guarantee strictly deterministic serialization.
    """
    if isinstance(d, dict):
        return {k: canonicalize_dict(v) for k, v in sorted(d.items())}
    elif isinstance(d, list):
        return [canonicalize_dict(item) for item in d]
    elif isinstance(d, tuple):
        return [canonicalize_dict(item) for item in d]
    return d


def canonicalize_evidence_package(package: EvidencePackage) -> bytes:
    """
    Serializes an EvidencePackage into a canonical UTF-8 byte stream.
    
    CANONICALIZATION RULES:
    1. Schema version and structural fields strictly preserved.
    2. All dictionary keys sorted lexicographically (sort_keys=True).
    3. Compact JSON formatting with consistent separators (',', ':').
    4. ensure_ascii=True to avoid platform-dependent unicode encoding differences.
    5. The 'canonical_digest' field is excluded so the digest does not self-reference.
    """
    raw_dict = package.model_dump(exclude={"canonical_digest"})
    canonical_obj = canonicalize_dict(raw_dict)
    canonical_json_str = json.dumps(
        canonical_obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return canonical_json_str.encode("utf-8")


def compute_evidence_digest(package: EvidencePackage) -> str:
    """
    Produces the authoritative, deterministic SHA-256 evidence fingerprint
    used for on-chain anchoring and tamper verification.
    """
    canonical_bytes = canonicalize_evidence_package(package)
    return compute_sha256(canonical_bytes)
