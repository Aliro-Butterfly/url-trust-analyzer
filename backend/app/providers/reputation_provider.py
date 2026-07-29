from __future__ import annotations

import re
from typing import Any

import httpx

from .base import Provider


class ReputationProvider(Provider):
    name = "Reputation Signals"

    SUSPICIOUS_TLDS = {
        "zip",
        "review",
        "work",
        "loan",
        "top",
        "click",
        "gq",
        "tk",
        "icu",
        "men",
        "party",
        "win",
        "download",
    }

    SUSPICIOUS_TERMS = {
        "login",
        "secure",
        "verify",
        "account",
        "bank",
        "update",
        "password",
        "confirm",
        "signin",
        "auth",
        "webscr",
        "paypal",
        "support",
        "verify",
    }

    async def analyze(self, url: str) -> dict[str, Any]:
        try:
            parsed = httpx.URL(url)
        except Exception:
            return {
                "provider": self.name,
                "status": "error",
                "score": 30,
                "confidence": 20,
                "summary": "The URL format is invalid.",
                "details": {"url": url, "reason": "invalid url"},
                "dimensions": {},
            }

        host = str(parsed.host) if parsed.host is not None else ""
        path = parsed.path.decode() if isinstance(parsed.path, bytes) else (parsed.path or "")
        query = parsed.query.decode() if isinstance(parsed.query, bytes) else (parsed.query or "")
        lower_host = host.lower()
        lower_path = path.lower()
        lower_query = query.lower()

        suspicious_count = 0
        host_score = 100
        path_score = 100
        blacklist_score = 100

        if self._is_ip(host):
            host_score -= 40
            suspicious_count += 2

        if len(host) > 25:
            host_score -= 12
            suspicious_count += 1

        if lower_host.endswith(tuple(self.SUSPICIOUS_TLDS)):
            host_score -= 25
            blacklist_score -= 25
            suspicious_count += 1

        if host.count("-") > 2:
            host_score -= 15
            suspicious_count += 1

        if host.count(".") >= 4:
            host_score -= 10
            suspicious_count += 1

        if "xn--" in lower_host:
            host_score -= 20
            suspicious_count += 1

        if any(term in lower_path or term in lower_query for term in self.SUSPICIOUS_TERMS):
            path_score -= 30
            blacklist_score -= 20
            suspicious_count += 2

        if len(path) > 50:
            path_score -= 10
            suspicious_count += 1

        if query and len(query) > 20:
            path_score -= 10
            suspicious_count += 1

        if query and "=" in query:
            blacklist_score -= 10

        if len(host) <= 15 and "-" not in host and not self._is_ip(host):
            host_score += 5

        reputation_score = self._clamp(round((host_score + path_score) / 2))
        malware_score = self._clamp(round(100 - suspicious_count * 14))
        blacklist_score = self._clamp(blacklist_score)

        score = round((reputation_score + malware_score + blacklist_score) / 3)
        confidence = 80
        notes = []

        if self._is_ip(host):
            notes.append("The host uses an IP address.")
        if any(term in lower_path or term in lower_query for term in self.SUSPICIOUS_TERMS):
            notes.append("The path or query contains terms commonly found in phishing URLs.")
        if lower_host.endswith(tuple(self.SUSPICIOUS_TLDS)):
            notes.append("The top-level domain is often associated with low-reputation sites.")
        if not notes:
            notes.append("No obvious reputation red flags were detected.")

        return {
            "provider": self.name,
            "status": "success",
            "score": score,
            "confidence": confidence,
            "summary": "Reputation signals and suspicious URL patterns were evaluated.",
            "details": {
                "host": host,
                "path": path,
                "query": query,
                "notes": notes,
            },
            "dimensions": {
                "reputation": reputation_score,
                "malware": malware_score,
                "blacklists": blacklist_score,
            },
        }

    @staticmethod
    def _is_ip(value: str) -> bool:
        return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", value))

    @staticmethod
    def _clamp(value: int) -> int:
        return max(0, min(100, value))
