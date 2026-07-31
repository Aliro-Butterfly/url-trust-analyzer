from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse

from .exceptions import RateLimitExceeded

# How often (calls per bucket) to sweep stale buckets from memory.
_SWEEP_EVERY = 500


class RateLimiter:
    """In-memory sliding-window rate limiter (single-process only).

    FastAPI-compatible callable dependency. Each instance tracks its own
    per-IP buckets independently. Stale buckets are periodically evicted.
    """

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._call_count = 0

    def __call__(self, request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window_start = now - self._window_seconds
        bucket = self._buckets[client_ip]

        while bucket and bucket[0] < window_start:
            bucket.popleft()

        if len(bucket) >= self._max_requests:
            raise RateLimitExceeded("Too many requests. Please try again later.")

        bucket.append(now)

        self._call_count += 1
        if self._call_count >= _SWEEP_EVERY:
            self._sweep(window_start)
            self._call_count = 0

    def _sweep(self, window_start: float) -> None:
        stale = [ip for ip, q in self._buckets.items() if not q or q[-1] < window_start]
        for ip in stale:
            del self._buckets[ip]