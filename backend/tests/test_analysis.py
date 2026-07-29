import asyncio

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.providers.icann import IcannProvider


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


def test_analyze_endpoint_returns_a_report(monkeypatch):
    async def fake_get(self, url, timeout=10.0):
        return FakeResponse(
            {
                "ldhName": "example.com",
                "events": [{"eventAction": "registration", "eventDate": "1990-01-01T00:00:00Z"}],
            }
        )

    monkeypatch.setattr("backend.app.providers.icann.httpx.AsyncClient.get", fake_get)

    client = TestClient(app)
    response = client.post("/analyze", json={"url": "https://example.com"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["url"] == "https://example.com"
    assert payload["overall_score"] >= 70
    assert len(payload["results"]) == 2
    assert "reasons" in payload
    assert isinstance(payload["reasons"], list)
