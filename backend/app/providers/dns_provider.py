from __future__ import annotations

from typing import Any

import httpx

from .base import Provider


class DnsProvider(Provider):
    name = "DNS Infrastructure"

    async def analyze(self, url: str) -> dict[str, Any]:
        domain = self._extract_domain(url)
        if not domain:
            return {
                "provider": self.name,
                "status": "error",
                "score": 40,
                "confidence": 25,
                "summary": "The URL is invalid.",
                "details": {"domain": None, "reason": "invalid url"},
                "dimensions": {},
            }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"https://dns.google/resolve?name={domain}&type=ANY")
                response.raise_for_status()
                payload = response.json()
        except Exception:
            return {
                "provider": self.name,
                "status": "error",
                "score": 45,
                "confidence": 30,
                "summary": "DNS lookup failed.",
                "details": {"domain": domain, "reason": "dns lookup failed"},
                "dimensions": {},
            }

        answers = payload.get("Answer", []) or []
        ns_records = [record["data"] for record in answers if record.get("type") == 2]
        mx_records = [record["data"] for record in answers if record.get("type") == 15]
        a_records = [record["data"] for record in answers if record.get("type") in (1, 28)]

        if not answers:
            return {
                "provider": self.name,
                "status": "error",
                "score": 50,
                "confidence": 35,
                "summary": "No DNS records were returned.",
                "details": {"domain": domain},
                "dimensions": {},
            }

        infra_score = 95 if len(ns_records) >= 2 else 70 if len(ns_records) == 1 else 45
        transparency_score = 90 if len(mx_records) > 0 else 70 if len(a_records) > 0 else 50

        notes: list[str] = []
        if len(ns_records) >= 2:
            notes.append("Multiple authoritative nameservers are configured.")
        elif len(ns_records) == 1:
            notes.append("A single nameserver is configured.")
        else:
            notes.append("No authoritative nameserver was discovered.")

        if len(mx_records) > 0:
            notes.append("The domain has mail exchanger records.")
        elif len(a_records) > 0:
            notes.append("The domain resolves to IP addresses but has no MX records.")

        return {
            "provider": self.name,
            "status": "success",
            "score": round((infra_score + transparency_score) / 2),
            "confidence": 80,
            "summary": "DNS infrastructure data has been collected.",
            "details": {
                "ns_records": ns_records,
                "mx_records": mx_records,
                "a_records": a_records,
                "record_count": len(answers),
                "notes": notes,
            },
            "dimensions": {
                "infrastructure": infra_score,
                "transparency": transparency_score,
            },
        }

    @staticmethod
    def _extract_domain(url: str) -> str | None:
        try:
            parsed = httpx.URL(url)
        except Exception:
            return None
        return parsed.host
