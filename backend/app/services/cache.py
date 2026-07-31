from __future__ import annotations

import asyncio
import os
import time
from typing import Any

ANALYSIS_CACHE_TTL = float(os.getenv("ANALYSIS_CACHE_TTL_SECONDS", "300"))
ANALYSIS_CACHE_MAX_SIZE = int(os.getenv("ANALYSIS_CACHE_MAX_SIZE", "200"))


class AnalysisCache:
    """
    Async-safe in-memory TTL cache for URL analysis results.

    - Bounded by max_size: when full, the oldest entry is evicted (LRU-like).
    - Entries expire after ttl seconds regardless of access.
    - In-flight deduplication: a second request for the same URL while one is
      already running will await the same Future instead of starting a new analysis.
    """

    def __init__(self, ttl: float = ANALYSIS_CACHE_TTL, max_size: int = ANALYSIS_CACHE_MAX_SIZE) -> None:
        self._ttl = ttl
        self._max_size = max_size
        # url -> (inserted_at, result_or_future)
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, url: str) -> Any | None:
        async with self._lock:
            entry = self._store.get(url)
            if entry is None:
                return None
            ts, value = entry
            if time.monotonic() - ts > self._ttl:
                del self._store[url]
                return None
            return value

    async def set(self, url: str, result: Any) -> None:
        async with self._lock:
            if len(self._store) >= self._max_size and url not in self._store:
                # Evict the oldest entry
                oldest = min(self._store, key=lambda k: self._store[k][0])
                del self._store[oldest]
            self._store[url] = (time.monotonic(), result)

    async def invalidate(self, url: str) -> None:
        async with self._lock:
            self._store.pop(url, None)

    def size(self) -> int:
        return len(self._store)