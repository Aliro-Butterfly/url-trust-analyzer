from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from .base import Provider
from .utils import _clamp, _extract_domain, _fetch_text

logger = logging.getLogger(__name__)


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


class PrivacyProvider(Provider):
    name = "Privacy"

    KNOWN_TRACKERS = {
        "google-analytics.com", "googletagmanager.com", "doubleclick.net",
        "facebook.com/tr", "connect.facebook.net", "analytics.twitter.com",
        "ads.linkedin.com", "bat.bing.com", "adservice.google.com",
        "pagead2.googlesyndication.com", "cdn.segment.com", "amplitude.com",
        "mixpanel.com", "hotjar.com", "cdn.heapanalytics.com",
        "snap.licdn.com", "static.ads-twitter.com", "t.co",
        "scorecardresearch.com", "quantserve.com", "exelator.com",
        "bluekai.com", "demdex.net", "adsrvr.org", "rubiconproject.com",
        "pubmatic.com", "openx.net", "criteo.com", "criteo.net",
    }

    FINGERPRINTING_SCRIPTS = {
        "fingerprintjs", "fingerprint2", "clientjs", "canvas-blocker",
        "audio-fingerprint", "webrtc-leak", "evercookie",
    }

    CRYPTO_SCRIPTS = {
        "coinhive", "coin-hive", "cryptoloot", "miner", "webmine",
        "coinnebula", "coinimp",
    }

    ANALYTICS_SCRIPTS = {
        "gtag", "ga.js", "analytics.js", "fbevents.js", "fbq",
        "mc.js", "hs-analytics", "snap.js",
    }

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = _extract_domain(url)
        if not domain:
            return {"provider": self.name, "status": "error", "score": 50, "confidence": 25,
                    "summary": "The URL is invalid.", "details": {}, "dimensions": {}}

        html = await _fetch_text(url, timeout=10.0)
        if not html:
            return {"provider": self.name, "status": "no_data", "score": 65, "confidence": 40,
                    "summary": "Could not fetch page content for privacy analysis.", "details": {}, "dimensions": {}}

        text_lower = html.lower()
        penalties = 0

        tracker_count = sum(1 for t in self.KNOWN_TRACKERS if t in text_lower)
        penalties += tracker_count * 5

        analytic_count = sum(1 for a in self.ANALYTICS_SCRIPTS if a in text_lower)
        penalties += analytic_count * 3

        fingerprint_count = sum(1 for f in self.FINGERPRINTING_SCRIPTS if f in text_lower)
        penalties += fingerprint_count * 8

        crypto_count = sum(1 for c in self.CRYPTO_SCRIPTS if c in text_lower)
        penalties += crypto_count * 20

        third_party_scripts = text_lower.count("<script") - text_lower.count("</script>")
        third_party_scripts = abs(third_party_scripts)
        script_tags = text_lower.count("<script")
        if script_tags > 20:
            penalties += (script_tags - 20) * 2

        iframes = text_lower.count("<iframe")
        if iframes > 3:
            penalties += (iframes - 3) * 3

        has_fingerprinting = fingerprint_count > 0
        has_crypto = crypto_count > 0
        has_heavy_tracking = tracker_count > 3
        has_excessive_scripts = script_tags > 50

        score = _clamp(100 - penalties)

        if has_crypto:
            score = min(score, 15)
            note = "Cryptomining scripts detected on the page."
        elif has_fingerprinting and has_heavy_tracking:
            note = "Fingerprinting scripts and heavy tracking detected."
        elif has_fingerprinting:
            note = "Browser fingerprinting scripts detected."
        elif has_heavy_tracking:
            note = "Multiple advertising trackers found on the page."
        elif has_excessive_scripts:
            note = "Excessive number of external scripts detected."
        elif script_tags <= 3 and tracker_count == 0:
            score = max(score, 90)
            note = "Minimal tracking and scripts detected."
        else:
            note = f"Found {tracker_count} tracker(s), {analytic_count} analytics, {script_tags} script(s)."

        return {
            "provider": self.name, "status": "success",
            "score": score, "confidence": 72,
            "summary": note,
            "details": {
                "trackers": tracker_count, "analytics": analytic_count,
                "fingerprinting": fingerprint_count, "crypto_mining": crypto_count,
                "scripts": script_tags, "iframes": iframes,
            },
            "dimensions": {"privacy": score},
        }


class MozillaObservatoryProvider(Provider):
    name = "Mozilla Observatory"

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = _extract_domain(url)
        if not domain:
            return {"provider": self.name, "status": "error", "score": 50, "confidence": 25,
                    "summary": "The URL is invalid.", "details": {}, "dimensions": {}}
        try:
            import httpx
            async with httpx.AsyncClient(timeout=25.0) as client:
                scan_resp = await client.post(
                    f"https://observatory-api.mdn.mozilla.net/api/v2/scan?host={domain}",
                )
                if scan_resp.status_code == 429:
                    analyze_resp = await client.get(
                        f"https://observatory-api.mdn.mozilla.net/api/v2/analyze?host={domain}",
                    )
                    if analyze_resp.status_code == 200:
                        data = analyze_resp.json()
                    else:
                        return {"provider": self.name, "status": "no_data", "score": 65, "confidence": 40,
                                "summary": "Mozilla Observatory rate limited and no cached result.", "details": {}, "dimensions": {}}
                else:
                    scan_resp.raise_for_status()
                    data = scan_resp.json()

                grade = data.get("grade", "F")
                raw_score = data.get("score", 0)
                score = _clamp(raw_score)
                return {
                    "provider": self.name, "status": "success",
                    "score": score, "confidence": 75,
                    "summary": f"Mozilla Observatory grade: {grade} (score: {raw_score}).",
                    "details": {"grade": grade, "raw_score": raw_score,
                                "tests_passed": data.get("tests_passed"),
                                "tests_failed": data.get("tests_failed")},
                    "dimensions": {"https": score},
                }
        except Exception as exc:
            logger.warning("Mozilla Observatory scan failed: %s", exc)
            return {"provider": self.name, "status": "error", "score": 55, "confidence": 35,
                    "summary": "Mozilla Observatory scan failed.", "details": {}, "dimensions": {}}


class CertificateTransparencyProvider(Provider):
    name = "Certificate Transparency"

    HIGH_TRUST_ISSUERS = {
        "let's encrypt", "digicert", "globalsign", "comodo", "sectigo",
        "godaddy", "geotrust", "thawte", "rapidssl", "entrust",
        "buypass", "certum", "actalis", "ssl.com",
    }

    LOW_TRUST_ISSUERS = {
        "wo-sign", "china internet network", "cnnic", "gdca",
        "certificates rsa", "self-signed",
    }

    async def analyze(self, url: str, api_key: str | None = None) -> dict[str, Any]:
        domain = _extract_domain(url)
        if not domain:
            return {"provider": self.name, "status": "error", "score": 50, "confidence": 25,
                    "summary": "The URL is invalid.", "details": {}, "dimensions": {}}

        json_text = await _fetch_text(f"https://crt.sh/?identity={domain}&output=json", timeout=15.0)
        if not json_text:
            return {"provider": self.name, "status": "no_data", "score": 65, "confidence": 40,
                    "summary": "Certificate Transparency lookup returned no data.", "details": {}, "dimensions": {}}
        try:
            import json
            certs = json.loads(json_text)
            if not certs or not isinstance(certs, list):
                return {"provider": self.name, "status": "no_data", "score": 65, "confidence": 40,
                        "summary": "No certificates found in Certificate Transparency logs.", "details": {}, "dimensions": {}}
        except Exception:
            return {"provider": self.name, "status": "no_data", "score": 65, "confidence": 40,
                    "summary": "Certificate Transparency response could not be parsed.", "details": {}, "dimensions": {}}

        subdomains = set()
        issuers = set()
        expiring_soon = 0
        expired = 0
        now = datetime.now(timezone.utc)

        for cert in certs[:200]:
            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip()
                if name.endswith("." + domain):
                    subdomains.add(name)
            issuer = (cert.get("issuer_name") or "").lower()
            issuers.add(issuer)
            not_after_str = cert.get("not_after")
            if not_after_str:
                try:
                    not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
                    days_left = (not_after - now).days
                    if days_left < 0:
                        expired += 1
                    elif days_left < 30:
                        expiring_soon += 1
                except Exception:
                    pass

        subdomain_count = len(subdomains)
        has_low_trust_issuer = any(
            low in issuer for issuer in issuers for low in self.LOW_TRUST_ISSUERS
        )
        has_high_trust_issuer = any(
            high in issuer for issuer in issuers for high in self.HIGH_TRUST_ISSUERS
        )

        score = 80
        reasons = []

        if not has_high_trust_issuer:
            score -= 15
            reasons.append("no trusted CA")
        if has_low_trust_issuer:
            score -= 25
            reasons.append("low-trust issuer detected")
        if expired > 0:
            score -= 20
            reasons.append(f"{expired} expired cert(s)")
        if expiring_soon > 0:
            score -= 10
            reasons.append(f"{expiring_soon} cert(s) expiring soon")
        if subdomain_count > 50:
            score -= 10
        elif subdomain_count == 0:
            score -= 5
            reasons.append("no subdomains found")

        score = _clamp(score)
        summary = f"Found {subdomain_count} subdomain(s), {len(issuers)} issuer(s)."
        if reasons:
            summary += " Issues: " + ", ".join(reasons) + "."

        return {
            "provider": self.name, "status": "success",
            "score": score, "confidence": 70,
            "summary": summary,
            "details": {
                "subdomain_count": subdomain_count, "issuers": list(issuers),
                "expired_certs": expired, "expiring_soon_certs": expiring_soon,
            },
            "dimensions": {"infrastructure": score, "transparency": score},
        }

