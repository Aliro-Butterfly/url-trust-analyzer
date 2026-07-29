from __future__ import annotations

import httpx

from .base import Provider


class UrlPropertiesProvider(Provider):
    name = "URL Properties"

    async def analyze(self, url: str) -> dict[str, object]:
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

        score = 90 if scheme == "https" else 40
        confidence = 88
        reasons = []

        if scheme != "https":
            reasons.append("HTTPS is not used.")
        if len(host) > 20:
            score -= 10
            reasons.append("The hostname is long, which may reduce trust.")
        if len(host) <= 20 and scheme == "https":
            reasons.append("The URL has a secure scheme and a short hostname.")

        score = max(25, min(95, score))

        return {
            "provider": self.name,
            "status": "success",
            "score": score,
            "confidence": confidence,
            "summary": "Static URL inspection completed.",
            "details": {"scheme": scheme, "host": host, "path": path, "notes": reasons},
        }
