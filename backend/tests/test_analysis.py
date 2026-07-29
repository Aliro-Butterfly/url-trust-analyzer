import asyncio
import os
import tempfile

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.providers.dns_provider import DnsProvider
from backend.app.providers.icann import IcannProvider
from backend.app.providers.reputation_provider import ReputationProvider


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("request failed")


def test_health_endpoint_returns_ok():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_icann_provider_returns_a_result(monkeypatch):
    async def fake_get(self, url, timeout=10.0):
        return FakeResponse(
            {
                "ldhName": "example.com",
                "events": [{"eventAction": "registration", "eventDate": "1990-01-01T00:00:00Z"}],
            }
        )

    monkeypatch.setattr("backend.app.providers.icann.httpx.AsyncClient.get", fake_get)

    provider = IcannProvider()
    result = asyncio.run(provider.analyze("https://example.com"))

    assert result["provider"] == "ICANN/RDAP"
    assert result["status"] == "success"
    assert result["score"] >= 70


def test_url_properties_provider_returns_a_result():
    from backend.app.providers.url_properties import UrlPropertiesProvider

    provider = UrlPropertiesProvider()
    result = asyncio.run(provider.analyze("https://example.com/path"))

    assert result["provider"] == "URL Properties"
    assert result["status"] == "success"
    assert result["score"] >= 80
    assert result["details"]["scheme"] == "https"
    assert result["details"]["host"] == "example.com"


def test_dns_provider_returns_a_result(monkeypatch):
    async def fake_get(self, url, timeout=10.0):
        return FakeResponse(
            {
                "Answer": [
                    {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns1.example.com."},
                    {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns2.example.com."},
                    {"name": "example.com.", "type": 15, "TTL": 300, "data": "mail.example.com."},
                ]
            }
        )

    monkeypatch.setattr("backend.app.providers.dns_provider.httpx.AsyncClient.get", fake_get)

    provider = DnsProvider()
    result = asyncio.run(provider.analyze("https://example.com"))

    assert result["provider"] == "DNS Infrastructure"
    assert result["status"] == "success"
    assert result["dimensions"]["infrastructure"] >= 90
    assert result["dimensions"]["transparency"] >= 90


def test_reputation_provider_returns_a_result():
    provider = ReputationProvider()
    result = asyncio.run(provider.analyze("https://example.com/login?user=test"))

    assert result["provider"] == "Reputation Signals"
    assert result["status"] == "success"
    assert "reputation" in result["dimensions"]
    assert "malware" in result["dimensions"]
    assert "blacklists" in result["dimensions"]
    assert 0 <= result["dimensions"]["reputation"] <= 100


def test_analyze_endpoint_returns_a_report(monkeypatch):
    async def fake_get(self, url, timeout=10.0):
        if "rdap.org" in url:
            return FakeResponse(
                {
                    "ldhName": "example.com",
                    "events": [{"eventAction": "registration", "eventDate": "1990-01-01T00:00:00Z"}],
                }
            )
        if "dns.google" in url:
            return FakeResponse(
                {
                    "Answer": [
                        {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns1.example.com."},
                        {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns2.example.com."},
                        {"name": "example.com.", "type": 15, "TTL": 300, "data": "mail.example.com."},
                    ]
                }
            )
        return FakeResponse({})

    monkeypatch.setattr("backend.app.providers.icann.httpx.AsyncClient.get", fake_get)
    monkeypatch.setattr("backend.app.providers.dns_provider.httpx.AsyncClient.get", fake_get)

    client = TestClient(app)
    response = client.post("/analyze", json={"url": "https://example.com"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["url"] == "https://example.com"
    assert payload["overall_score"] >= 70
    assert len(payload["results"]) == 4
    assert "reasons" in payload
    assert isinstance(payload["reasons"], list)


def test_history_endpoint_records_analysis(monkeypatch):
    db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    db_file.close()
    monkeypatch.setenv("URL_TRUST_ANALYZER_DB", db_file.name)

    async def fake_get(self, url, timeout=10.0):
        if "rdap.org" in url:
            return FakeResponse(
                {
                    "ldhName": "example.com",
                    "events": [{"eventAction": "registration", "eventDate": "1990-01-01T00:00:00Z"}],
                }
            )
        if "dns.google" in url:
            return FakeResponse(
                {
                    "Answer": [
                        {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns1.example.com."},
                        {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns2.example.com."},
                        {"name": "example.com.", "type": 15, "TTL": 300, "data": "mail.example.com."},
                    ]
                }
            )
        return FakeResponse({})

    monkeypatch.setattr("backend.app.providers.icann.httpx.AsyncClient.get", fake_get)
    monkeypatch.setattr("backend.app.providers.dns_provider.httpx.AsyncClient.get", fake_get)

    client = TestClient(app)
    analyze_response = client.post("/analyze", json={"url": "https://example.com"})
    assert analyze_response.status_code == 200

    history_response = client.get("/history")
    assert history_response.status_code == 200
    history = history_response.json()
    assert isinstance(history, list)
    assert len(history) == 1
    assert history[0]["url"] == "https://example.com"
    assert history[0]["report"]["overall_score"] == analyze_response.json()["overall_score"]
