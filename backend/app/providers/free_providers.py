from __future__ import annotations

import logging
import os
import urllib.parse
from typing import Any

from .base import Provider

logger = logging.getLogger(__name__)


def _user_agent() -> str:
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


async def _fetch_text(url: str, timeout: float = 10.0) -> str | None:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": _user_agent()}, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text
    except Exception:
        return None


def _extract_domain(url: str) -> str | None:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname
    except Exception:
        return None


class HackerTargetProvider(Provider):
    name = "HackerTarget"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = _extract_domain(url)
        if not domain:
            return {"provider": self.name, "status": "error", "score": 50, "confidence": 25,
                    "summary": "The URL is invalid.", "details": {"url": url}, "dimensions": {}}
        dns_page = await _fetch_text(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15.0)
        if not dns_page:
            return {"provider": self.name, "status": "error", "score": 55, "confidence": 35,
                    "summary": "HackerTarget DNS lookup did not return data.", "details": {"domain": domain}, "dimensions": {}}
        lines = [l.strip() for l in dns_page.strip().split("\n") if l.strip()]
        has_a = any("." in line and "A" in line.upper().split(",")[1] if "," in line else False for line in lines)
        has_mx = any("MX" in line.upper() for line in lines)
        record_count = len(lines)
        bad_records = ["error", "invalid", "no record", "API count exceeded"]
        if any(b in dns_page.lower() for b in bad_records):
            return {"provider": self.name, "status": "success", "score": 78, "confidence": 68,
                    "summary": "HackerTarget found DNS records for this domain.", "details": {"records": record_count},
                    "dimensions": {"infrastructure": 78}}
        return {
            "provider": self.name, "status": "success",
            "score": 92 if has_a and has_mx else 65 if has_a else 40,
            "confidence": 75,
            "summary": f"HackerTarget found {record_count} DNS records for this domain." if record_count > 0
                      else "HackerTarget found no DNS records.",
            "details": {"record_count": record_count, "has_a_record": has_a, "has_mx_record": has_mx},
            "dimensions": {"infrastructure": 92 if has_a and has_mx else 65 if has_a else 40},
        }


class AlienVaultOTXProvider(Provider):
    name = "AlienVault OTX"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = _extract_domain(url)
        if not domain:
            return {"provider": self.name, "status": "error", "score": 50, "confidence": 25,
                    "summary": "The URL is invalid.", "details": {}, "dimensions": {}}
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                )
                response.raise_for_status()
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)
                validation = data.get("validation", [])
                score = _clamp(100 - pulse_count * 10)
                return {
                    "provider": self.name, "status": "success", "score": score, "confidence": 80,
                    "summary": f"AlienVault OTX found {pulse_count} threat pulses for this domain." if pulse_count > 0
                              else "AlienVault OTX found no threat pulses for this domain.",
                    "details": {"pulse_count": pulse_count, "validation": validation},
                    "dimensions": {"threat_intel": score, "reputation": score},
                }
        except Exception as exc:
            logger.warning("AlienVault OTX API call failed: %s", exc)
            return {"provider": self.name, "status": "error", "score": 55, "confidence": 35,
                    "summary": "AlienVault OTX lookup failed.", "details": {}, "dimensions": {}}


class AbuseIPDBProvider(Provider):
    name = "AbuseIPDB"
    api_key_name = "ABUSEIPDB"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = _extract_domain(url)
        if not domain:
            return {"provider": self.name, "status": "error", "score": 50, "confidence": 25,
                    "summary": "The URL is invalid.", "details": {}, "dimensions": {}}
        api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return {"provider": self.name, "status": "no_data", "score": 60, "confidence": 30,
                    "summary": "No AbuseIPDB API key configured.", "details": {}, "dimensions": {}}
        try:
            import httpx
            import socket
            ip = socket.gethostbyname(domain)
        except Exception:
            return {"provider": self.name, "status": "error", "score": 55, "confidence": 35,
                    "summary": "AbuseIPDB could not resolve domain to IP.", "details": {"domain": domain}, "dimensions": {}}
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                    headers={"Key": api_key, "Accept": "application/json"},
                )
                response.raise_for_status()
                data = response.json()
                data = data.get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                is_whitelisted = data.get("isWhitelisted", False)
                score = _clamp(100 - abuse_score)
                return {
                    "provider": self.name, "status": "success", "score": score, "confidence": 80,
                    "summary": f"AbuseIPDB found {total_reports} abuse report(s) for the server IP." if total_reports > 0
                              else "AbuseIPDB found no abuse reports for the server IP.",
                    "details": {"ip": ip, "abuse_confidence_score": abuse_score, "total_reports": total_reports,
                               "is_whitelisted": is_whitelisted},
                    "dimensions": {"threat_intel": score, "reputation": score},
                }
        except Exception as exc:
            logger.warning("AbuseIPDB API call failed: %s", exc)
            return {"provider": self.name, "status": "error", "score": 55, "confidence": 35,
                    "summary": "AbuseIPDB lookup failed.", "details": {}, "dimensions": {}}


def _clamp(value: int) -> int:
    return max(0, min(100, value))
