import time
from collections import deque, defaultdict

from overseer.config import Config


class RateTracker:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._windows: dict[str, deque] = defaultdict(deque)
        self._404_counts: dict[str, int] = defaultdict(int)
        self._403_counts: dict[str, int] = defaultdict(int)
        self._last_cleanup: float = time.time()

    def record(self, ip: str, status: int, now: float | None = None) -> int:
        if now is None:
            now = time.time()

        window = self._windows[ip]
        window.append(now)

        cutoff = now - self._config.rate_window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        if status == 404:
            self._404_counts[ip] += 1
        elif status == 403:
            self._403_counts[ip] += 1

        if now - self._last_cleanup > self._config.cleanup_interval:
            self._cleanup(now)

        return len(window)

    def get_404_count(self, ip: str) -> int:
        return self._404_counts[ip]

    def get_403_count(self, ip: str) -> int:
        return self._403_counts[ip]

    def _cleanup(self, now: float) -> None:
        cutoff = now - self._config.rate_window_seconds
        stale = [
            ip for ip, w in self._windows.items()
            if not w or w[-1] < cutoff
        ]
        for ip in stale:
            del self._windows[ip]
            self._404_counts.pop(ip, None)
            self._403_counts.pop(ip, None)
        self._last_cleanup = now