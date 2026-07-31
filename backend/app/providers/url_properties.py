from __future__ import annotations

import httpx

from .base import Provider


class UrlPropertiesProvider(Provider):
    name = "URL Properties"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, object]:
        try:
            parsed = httpx.URL(url)
        except Exception:
            return {
                "provider": self.name,
                "status": "error",
                "score": 20,
                "confidence": 30,
                "summary": "The URL format is invalid.",
                "details": {"url": url},
            }

        scheme = parsed.scheme
        host = parsed.host or ""
        path = parsed.path

        https_score = 100 if scheme == "https" else 20
        infrastructure_score = 90 if len(host) <= 20 else 65
        score = round((https_score + infrastructure_score) / 2)
        confidence = 88
        notes = []

        if scheme != "https":
            notes.append("HTTPS is not used.")
        if len(host) > 20:
            notes.append("The hostname is long, which can reduce trust.")
        if len(host) <= 20 and scheme == "https":
            notes.append("The URL has a secure scheme and a short hostname.")

        return {
            "provider": self.name,
            "status": "success",
            "score": score,
            "confidence": confidence,
            "summary": "Static URL inspection completed.",
            "details": {"scheme": scheme, "host": host, "path": path, "notes": notes},
            "dimensions": {
                "https": https_score,
                "infrastructure": infrastructure_score,
            },
        }
