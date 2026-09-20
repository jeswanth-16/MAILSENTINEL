import threading
import time
from typing import Any, Dict, Optional, Tuple


class IntelligenceCache:
    """
    In-memory thread-safe TTL cache for threat intelligence lookups.
    Avoids redundant queries for repeated IPs, domains, and URLs.
    """

    def __init__(self, default_ttl_seconds: int = 3600):
        self.default_ttl = default_ttl_seconds
        self._cache: Dict[str, Tuple[Any, float]] = {}  # key -> (value, expiry_timestamp)
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._cache:
                return None
            val, expiry = self._cache[key]
            if time.time() > expiry:
                del self._cache[key]
                return None
            return val

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expiry = time.time() + ttl
        with self._lock:
            self._cache[key] = (value, expiry)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._cache)


from app.core.config import settings


def get_default_cache_ttl() -> int:
    try:
        return getattr(settings, "INTELLIGENCE_CACHE_TTL", 21600)
    except Exception:
        return 21600


default_intel_cache = IntelligenceCache(default_ttl_seconds=get_default_cache_ttl())
