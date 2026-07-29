from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Provider(ABC):
    name: str
    api_key_name: str | None = None

    @abstractmethod
    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        raise NotImplementedError()
