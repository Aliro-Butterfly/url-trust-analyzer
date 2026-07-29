from __future__ import annotations

import datetime as dt
from typing import Any

import httpx

from .base import Provider


class IcannProvider(Provider):
    name = "ICANN/RDAP"
    api_key_name = None

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = self._extract_domain(url)
        if not domain:
            return {
                "provider": self.name,
                "status": "error",
                "score": 40,
                "confidence": 20,
                "summary": "The URL is invalid.",
                "details": {"domain": None, "reason": "invalid url"},
            }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"https://rdap.org/domain/{domain}")
                response.raise_for_status()
                payload = response.json()
        except Exception:
            return {
                "provider": self.name,
                "status": "error",
                "score": 45,
                "confidence": 25,
                "summary": "The RDAP lookup did not return usable data.",
                "details": {"domain": domain, "reason": "rdap lookup failed"},
            }

        registration_date = None
        for event in payload.get("events", []):
            if event.get("eventAction") == "registration":
                registration_date = event.get("eventDate")
                break

        if registration_date:
            age_score = self._score_from_age(registration_date)
            summary = "The domain is publicly registered and appears mature."
            confidence = 84
            details = {"domain": domain, "registration_date": registration_date}
        else:
            age_score = 62
            summary = "The domain was returned by RDAP, but no registration date was exposed."
            confidence = 60
            details = {"domain": domain, "registration_date": None}

        return {
            "provider": self.name,
            "status": "success",
            "score": age_score,
            "confidence": confidence,
            "summary": summary,
            "details": details,
            "dimensions": {
                "age": age_score,
            },
        }

    @staticmethod
    def _extract_domain(url: str) -> str | None:
        try:
            parsed = httpx.URL(url)
        except Exception:
            return None
        return parsed.host

    @staticmethod
    def _score_from_age(registration_date: str) -> int:
        try:
            parsed_date = dt.datetime.fromisoformat(registration_date.replace("Z", "+00:00"))
        except ValueError:
            return 62

        age_days = (dt.datetime.now(tz=dt.timezone.utc) - parsed_date).days
        if age_days > 365 * 5:
            return 92
        if age_days > 365 * 2:
            return 84
        if age_days > 365:
            return 74
        return 64
