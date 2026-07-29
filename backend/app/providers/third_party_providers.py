from __future__ import annotations

import os
import urllib.parse
from typing import Any

import httpx

from .base import Provider


def _extract_domain(url: str) -> str | None:
    try:
        parsed = httpx.URL(url)
    except Exception:
        return None
    return parsed.host


def _user_agent() -> str:
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


async def _fetch_text(url: str, timeout: float = 10.0) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": _user_agent()}) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text
    except Exception:
        return None


def _score_from_page(content: str, positive: list[str], negative: list[str]) -> tuple[int, str]:
    lower = content.lower()
    if any(token in lower for token in negative):
        return 28, "The scraped page contains negative reputation indicators."

    if any(token in lower for token in positive):
        return 90, "The scraped page contains positive reputation indicators."

    return 60, "The scraped page did not contain a clear verdict."


def _clamp(value: int) -> int:
    return max(0, min(100, value))


class VirusTotalProvider(Provider):
    name = "VirusTotal"
    api_key_name = "VIRUSTOTAL"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
        entity = urllib.parse.quote(url, safe="")

        if api_key:
            try:
                async with httpx.AsyncClient(timeout=20.0, headers={"x-apikey": api_key}) as client:
                    create_response = await client.post(
                        "https://www.virustotal.com/api/v3/urls",
                        data={"url": url},
                    )
                    create_response.raise_for_status()
                    create_payload = create_response.json()
                    resource_id = create_payload.get("data", {}).get("id")

                    if resource_id:
                        report_response = await client.get(f"https://www.virustotal.com/api/v3/urls/{resource_id}")
                        report_response.raise_for_status()
                        payload = report_response.json()
                        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                        total = sum(stats.values())
                        score = _clamp(100 - positives * 15)
                        summary = f"VirusTotal scan results were fetched from the API with {positives} flagged engines."
                        confidence = 90 if total > 0 else 60
                        return {
                            "provider": self.name,
                            "status": "success",
                            "score": score,
                            "confidence": confidence,
                            "summary": summary,
                            "details": {
                                "positives": positives,
                                "total_scanners": total,
                                "analysis_stats": stats,
                            },
                            "dimensions": {"threat_intel": score},
                        }
            except Exception:
                pass

        page = await _fetch_text(f"https://www.virustotal.com/gui/url/search?query={entity}")
        if not page:
            return {
                "provider": self.name,
                "status": "error",
                "score": 55,
                "confidence": 35,
                "summary": "VirusTotal scraping did not return a usable page.",
                "details": {"url": url},
                "dimensions": {"threat_intel": 55},
            }

        score, note = _score_from_page(
            page,
            positive=["no threats detected", "harmless", "clean site", "detected by 0"],
            negative=["malicious", "phishing", "suspicious", "unsafe", "threat"],
        )
        return {
            "provider": self.name,
            "status": "success",
            "score": score,
            "confidence": 70,
            "summary": "VirusTotal reputation was evaluated using a best-effort page scrape.",
            "details": {"source": "scrape", "note": note},
            "dimensions": {"threat_intel": score},
        }


class GoogleSafeBrowsingProvider(Provider):
    name = "Google Safe Browsing"
    api_key_name = "GOOGLE_SAFEBROWSING"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        api_key = api_key or os.getenv("GOOGLE_SAFEBROWSING_API_KEY")
        if api_key:
            try:
                body = {
                    "client": {
                        "clientId": "url-trust-analyzer",
                        "clientVersion": "1.0",
                    },
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                }
                async with httpx.AsyncClient(timeout=15.0) as client:
                    response = await client.post(
                        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                        json=body,
                    )
                    response.raise_for_status()
                    payload = response.json()
                    matches = payload.get("matches")
                    if matches:
                        return {
                            "provider": self.name,
                            "status": "success",
                            "score": 18,
                            "confidence": 90,
                            "summary": "Google Safe Browsing reported a threat for this URL.",
                            "details": {"matches": matches},
                            "dimensions": {"threat_intel": 18},
                        }
                    return {
                        "provider": self.name,
                        "status": "success",
                        "score": 92,
                        "confidence": 90,
                        "summary": "Google Safe Browsing did not detect a known threat for this URL.",
                        "details": {"matches": []},
                        "dimensions": {"threat_intel": 92},
                    }
            except Exception:
                pass

        page = await _fetch_text(
            f"https://transparencyreport.google.com/safe-browsing/search?url={urllib.parse.quote(url, safe='')}",
            timeout=15.0,
        )
        if not page:
            return {
                "provider": self.name,
                "status": "error",
                "score": 58,
                "confidence": 40,
                "summary": "Google Safe Browsing lookup did not return usable data.",
                "details": {"url": url},
                "dimensions": {"threat_intel": 58},
            }

        score, note = _score_from_page(
            page,
            positive=["no unsafe content", "all clear", "no unsafe content found"],
            negative=["unsafe", "malicious", "phishing", "deceptive"],
        )
        return {
            "provider": self.name,
            "status": "success",
            "score": score,
            "confidence": 72,
            "summary": "Google Safe Browsing reputation was estimated from the public report page.",
            "details": {"source": "scrape", "note": note},
            "dimensions": {"threat_intel": score},
        }


class URLScanProvider(Provider):
    name = "URLScan"
    api_key_name = "URLSCAN"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = _extract_domain(url)
        if not domain:
            return {
                "provider": self.name,
                "status": "error",
                "score": 50,
                "confidence": 25,
                "summary": "The URL is invalid.",
                "details": {"url": url},
                "dimensions": {"threat_intel": 50},
            }

        api_key = os.getenv("URLSCAN_API_KEY")
        if api_key:
            try:
                async with httpx.AsyncClient(timeout=20.0, headers={"API-Key": api_key}) as client:
                    response = await client.get(
                        f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(domain)}&size=1"
                    )
                    response.raise_for_status()
                    payload = response.json()
                    results = payload.get("results", [])
                    if results:
                        verdicts = results[0].get("verdicts", {})
                        overall = verdicts.get("overall")
                        score = 90 if overall == "clean" else 20 if overall == "malicious" else 65
                        return {
                            "provider": self.name,
                            "status": "success",
                            "score": score,
                            "confidence": 75,
                            "summary": "URLScan results were retrieved from the API.",
                            "details": {"verdicts": verdicts},
                            "dimensions": {"threat_intel": score},
                        }
            except Exception:
                pass

        page = await _fetch_text(f"https://urlscan.io/domain/{urllib.parse.quote(domain)}")
        if not page:
            return {
                "provider": self.name,
                "status": "error",
                "score": 56,
                "confidence": 35,
                "summary": "URLScan lookup did not return usable data.",
                "details": {"domain": domain},
                "dimensions": {"threat_intel": 56},
            }

        if "no results" in page.lower() or "no scans" in page.lower():
            score = 78
            note = "URLScan has no public scans for this domain yet."
        else:
            score = 68
            note = "URLScan public scan results were found for this domain."

        return {
            "provider": self.name,
            "status": "success",
            "score": score,
            "confidence": 68,
            "summary": "URLScan reputation was estimated from public scan data.",
            "details": {"domain": domain, "note": note},
            "dimensions": {"threat_intel": score},
        }


class UrlVoidProvider(Provider):
    name = "URLVoid"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = _extract_domain(url)
        if not domain:
            return {
                "provider": self.name,
                "status": "error",
                "score": 50,
                "confidence": 25,
                "summary": "The URL is invalid.",
                "details": {"url": url},
                "dimensions": {"threat_intel": 50},
            }

        page = await _fetch_text(f"https://www.urlvoid.com/scan/{urllib.parse.quote(domain)}")
        if not page:
            return {
                "provider": self.name,
                "status": "error",
                "score": 50,
                "confidence": 35,
                "summary": "URLVoid scraping failed.",
                "details": {"domain": domain},
                "dimensions": {"threat_intel": 50},
            }

        score, note = _score_from_page(
            page,
            positive=["not blacklisted", "no blacklist detected", "no threats found"],
            negative=["blacklisted", "malicious", "phishing", "scam"],
        )
        return {
            "provider": self.name,
            "status": "success",
            "score": score,
            "confidence": 70,
            "summary": "URLVoid reputation was estimated from the public site scan page.",
            "details": {"domain": domain, "note": note},
            "dimensions": {"threat_intel": score},
        }


class SucuriProvider(Provider):
    name = "Sucuri"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = _extract_domain(url)
        if not domain:
            return {
                "provider": self.name,
                "status": "error",
                "score": 55,
                "confidence": 30,
                "summary": "The URL is invalid.",
                "details": {"url": url},
                "dimensions": {"threat_intel": 55},
            }

        page = await _fetch_text(f"https://sitecheck.sucuri.net/results/{urllib.parse.quote(domain)}")
        if not page:
            return {
                "provider": self.name,
                "status": "error",
                "score": 55,
                "confidence": 35,
                "summary": "Sucuri lookup failed.",
                "details": {"domain": domain},
                "dimensions": {"threat_intel": 55},
            }

        score, note = _score_from_page(
            page,
            positive=["clean site", "no malware found", "site check clean"],
            negative=["malware", "phishing", "blacklisted", "injected"],
        )
        return {
            "provider": self.name,
            "status": "success",
            "score": score,
            "confidence": 70,
            "summary": "Sucuri site scan was estimated using the public result page.",
            "details": {"domain": domain, "note": note},
            "dimensions": {"threat_intel": score},
        }


class TalosProvider(Provider):
    name = "Cisco Talos"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = _extract_domain(url)
        if not domain:
            return {
                "provider": self.name,
                "status": "error",
                "score": 50,
                "confidence": 30,
                "summary": "The URL is invalid.",
                "details": {"url": url},
                "dimensions": {"threat_intel": 50},
            }

        page = await _fetch_text(
            f"https://talosintelligence.com/reputation_center/lookup?search={urllib.parse.quote(domain)}",
            timeout=15.0,
        )
        if not page:
            return {
                "provider": self.name,
                "status": "error",
                "score": 50,
                "confidence": 35,
                "summary": "Cisco Talos lookup failed.",
                "details": {"domain": domain},
                "dimensions": {"threat_intel": 50},
            }

        score, note = _score_from_page(
            page,
            positive=["good", "medium", "known good"],
            negative=["poor", "very poor", "bad", "unverified"],
        )
        return {
            "provider": self.name,
            "status": "success",
            "score": score,
            "confidence": 72,
            "summary": "Cisco Talos reputation was estimated from the public lookup page.",
            "details": {"domain": domain, "note": note},
            "dimensions": {"threat_intel": score},
        }


class ScamDocProvider(Provider):
    name = "ScamDoc"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        page = await _fetch_text(f"https://www.scamdoc.com/check?url={urllib.parse.quote(url, safe='')}" )
        if not page:
            return {
                "provider": self.name,
                "status": "error",
                "score": 55,
                "confidence": 35,
                "summary": "ScamDoc scraping failed.",
                "details": {"url": url},
                "dimensions": {"threat_intel": 55},
            }

        score, note = _score_from_page(
            page,
            positive=["not a scam", "safe site", "trustworthy"],
            negative=["scam", "fraud", "unsafe", "dangerous"],
        )
        return {
            "provider": self.name,
            "status": "success",
            "score": score,
            "confidence": 70,
            "summary": "ScamDoc reputation was estimated from the public checker page.",
            "details": {"url": url, "note": note},
            "dimensions": {"threat_intel": score},
        }


def _clamp(value: int) -> int:
    return max(0, min(100, value))
