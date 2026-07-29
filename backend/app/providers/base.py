from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Provider(ABC):
    name: str

    @abstractmethod
    async def analyze(self, url: str) -> dict[str, Any]:
        raise NotImplementedError()
