import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """Sliding-window counter: at most `limit` hits per key in any `window` seconds.

    State lives in this process. With several workers each one counts on its
    own, so put a shared store (Redis, say) behind this before scaling out.
    """

    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key):
        """Record a hit for `key`; return False if it is over the limit."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)
