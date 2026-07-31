from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

from ..config import ANALYSIS_CACHE_MAX_SIZE, ANALYSIS_CACHE_TTL_SECONDS
from ..schemas import AnalysisResponse


@dataclass
class CacheEntry:
    result: AnalysisResponse
    inserted_at: float
    providers_count: int
    algo_version: str


class AnalysisCache:
    """
    Async-safe in-memory TTL cache for URL analysis results.

    - Bounded by max_size: when full, the oldest entry is evicted.
    - Entries expire after ttl seconds regardless of access.
    """

    def __init__(
        self,
        ttl: float = ANALYSIS_CACHE_TTL_SECONDS,
        max_size: int = ANALYSIS_CACHE_MAX_SIZE,
    ) -> None:
        self._ttl = ttl
        self._max_size = max_size
        self._store: dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()

    async def get(self, url: str) -> CacheEntry | None:
        async with self._lock:
            entry = self._store.get(url)
            if entry is None:
                return None
            if time.monotonic() - entry.inserted_at > self._ttl:
                del self._store[url]
                return None
            return entry

    async def set(
        self,
        url: str,
        result: AnalysisResponse,
        *,
        providers_count: int,
        algo_version: str,
    ) -> None:
        async with self._lock:
            if len(self._store) >= self._max_size and url not in self._store:
                oldest = min(self._store, key=lambda k: self._store[k].inserted_at)
                del self._store[oldest]
            self._store[url] = CacheEntry(
                result=result,
                inserted_at=time.monotonic(),
                providers_count=providers_count,
                algo_version=algo_version,
            )

    def size(self) -> int:
        return len(self._store)