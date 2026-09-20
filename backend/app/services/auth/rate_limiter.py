from collections import defaultdict
from datetime import datetime, timezone
import threading
from typing import Dict, List, Optional, Tuple

from app.core.config import settings


class InMemoryRateLimiter:
    """
    Sliding-window in-memory rate limiter per IP / User identifier.
    Returns True if allowed, False if exceeded.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # key -> list of timestamp floats
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int = 60, window_seconds: int = 60) -> Tuple[bool, int]:
        """
        Checks if a request is allowed within the window.
        Returns: (is_allowed, remaining_requests)
        """
        if not settings.RATE_LIMIT_ENABLED:
            return True, max_requests

        now = datetime.now(timezone.utc).timestamp()
        cutoff = now - window_seconds

        with self._lock:
            # Filter timestamps within current window
            valid_timestamps = [ts for ts in self._requests[key] if ts > cutoff]
            self._requests[key] = valid_timestamps

            if len(valid_timestamps) >= max_requests:
                return False, 0

            self._requests[key].append(now)
            remaining = max(0, max_requests - len(self._requests[key]))
            return True, remaining

    def reset(self, key: Optional[str] = None):
        with self._lock:
            if key:
                self._requests.pop(key, None)
            else:
                self._requests.clear()


default_rate_limiter = InMemoryRateLimiter()
