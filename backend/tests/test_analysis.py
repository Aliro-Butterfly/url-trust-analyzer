import asyncio
import os
import tempfile
import uuid

from fastapi.testclient import TestClient

from backend.app.main import analyzer_service, app
from backend.app.database import initialize_database
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


def create_temporary_db(monkeypatch):
    db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    db_file.close()
    monkeypatch.setenv("URL_TRUST_ANALYZER_DB", db_file.name)
    initialize_database()
    return db_file.name


def register_test_user(client):
    username = f"testuser_{uuid.uuid4().hex[:8]}"
    response = client.post("/auth/register", json={"username": username, "password": "password123"})
    assert response.status_code == 200
    return username


def unwrap(response):
    """Unwrap the ApiResponse envelope and return the data payload."""
    envelope = response.json()
    assert envelope["success"], f"API call failed: {envelope}"
    return envelope["data"]


def test_health_endpoint_returns_ok():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = unwrap(response)
    assert data["status"] == "ok"


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
    create_temporary_db(monkeypatch)

    async def fake_get(self, url, timeout=10.0):
        if "rdap.org" in url:
            return FakeResponse({"ldhName": "example.com", "events": [{"eventAction": "registration", "eventDate": "1990-01-01T00:00:00Z"}]})
        if "dns.google" in url:
            return FakeResponse({"Answer": [
                {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns1.example.com."},
                {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns2.example.com."},
                {"name": "example.com.", "type": 15, "TTL": 300, "data": "mail.example.com."},
            ]})
        return FakeResponse({})

    monkeypatch.setattr("backend.app.providers.icann.httpx.AsyncClient.get", fake_get)
    monkeypatch.setattr("backend.app.providers.dns_provider.httpx.AsyncClient.get", fake_get)

    client = TestClient(app)
    register_test_user(client)
    response = client.post("/analyze", json={"url": "https://example.com"})

    assert response.status_code == 200
    envelope = response.json()
    assert envelope["success"] is True
    assert "processingTime" in envelope["metadata"]
    assert "providerCount" in envelope["metadata"]
    assert envelope["metadata"]["cached"] is False

    payload = envelope["data"]
    assert payload["url"] == "https://example.com"
    assert payload["overall_score"] >= 50
    assert len(payload["results"]) == len(analyzer_service.providers)
    assert any(r["provider"] == "VirusTotal" for r in payload["results"])
    assert any(r["provider"] == "Cisco Talos" for r in payload["results"])
    assert "reasons" in payload


def test_history_endpoint_records_analysis(monkeypatch):
    db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    db_file.close()
    monkeypatch.setenv("URL_TRUST_ANALYZER_DB", db_file.name)
    initialize_database()

    async def fake_get(self, url, timeout=10.0):
        if "rdap.org" in url:
            return FakeResponse({"ldhName": "example.com", "events": [{"eventAction": "registration", "eventDate": "1990-01-01T00:00:00Z"}]})
        if "dns.google" in url:
            return FakeResponse({"Answer": [
                {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns1.example.com."},
                {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns2.example.com."},
                {"name": "example.com.", "type": 15, "TTL": 300, "data": "mail.example.com."},
            ]})
        return FakeResponse({})

    monkeypatch.setattr("backend.app.providers.icann.httpx.AsyncClient.get", fake_get)
    monkeypatch.setattr("backend.app.providers.dns_provider.httpx.AsyncClient.get", fake_get)

    client = TestClient(app)
    register_test_user(client)
    analyze_response = client.post("/analyze", json={"url": "https://example.com"})
    assert analyze_response.status_code == 200

    history_response = client.get("/history")
    assert history_response.status_code == 200
    history = unwrap(history_response)
    assert isinstance(history, list)
    assert len(history) == 1
    assert history[0]["url"] == "https://example.com"
    assert history[0]["report"]["overall_score"] == analyze_response.json()["data"]["overall_score"]
    assert "processing_time_ms" in history[0]
    assert "providers_count" in history[0]
    assert "algo_version" in history[0]


def test_protected_endpoints_require_auth():
    client = TestClient(app)

    analyze_response = client.post("/analyze", json={"url": "https://example.com"})
    assert analyze_response.status_code == 401
    assert analyze_response.json()["success"] is False

    history_response = client.get("/history")
    assert history_response.status_code == 401
    assert history_response.json()["success"] is False


def test_api_key_endpoints_are_user_scoped():
    client = TestClient(app)
    register_test_user(client)

    response = client.get("/auth/api-keys")
    assert response.status_code == 200
    data = unwrap(response)
    assert data == {"has_urlscan": False, "has_google_safebrowsing": False, "has_virustotal": False, "has_abuseipdb": False}

    update_response = client.put("/auth/api-keys", json={"urlscan": "test-urlscan-key", "google_safebrowsing": "test-google-key", "virustotal": "test-vt-key"})
    assert update_response.status_code == 200
    data2 = unwrap(update_response)
    assert data2 == {"has_urlscan": True, "has_google_safebrowsing": True, "has_virustotal": True, "has_abuseipdb": False}

    second_client = TestClient(app)
    register_test_user(second_client)
    second_keys = unwrap(second_client.get("/auth/api-keys"))
    assert second_keys == {"has_urlscan": False, "has_google_safebrowsing": False, "has_virustotal": False, "has_abuseipdb": False}


def test_history_is_scoped_per_user(monkeypatch):
    create_temporary_db(monkeypatch)

    async def fake_get(self, url, timeout=10.0):
        if "rdap.org" in url:
            return FakeResponse({"ldhName": "example.com", "events": [{"eventAction": "registration", "eventDate": "1990-01-01T00:00:00Z"}]})
        if "dns.google" in url:
            return FakeResponse({"Answer": [
                {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns1.example.com."},
                {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns2.example.com."},
                {"name": "example.com.", "type": 15, "TTL": 300, "data": "mail.example.com."},
            ]})
        return FakeResponse({})

    monkeypatch.setattr("backend.app.providers.icann.httpx.AsyncClient.get", fake_get)
    monkeypatch.setattr("backend.app.providers.dns_provider.httpx.AsyncClient.get", fake_get)

    client = TestClient(app)
    register_test_user(client)
    client.post("/analyze", json={"url": "https://example.com"})

    assert len(unwrap(client.get("/history"))) == 1

    second_client = TestClient(app)
    register_test_user(second_client)
    assert unwrap(second_client.get("/history")) == []


def test_admin_config_rejects_invalid_values(monkeypatch):
    monkeypatch.setattr("backend.app.main.ADMIN_USERNAME", "admin")
    monkeypatch.setattr("backend.app.main.ADMIN_PASSWORD", "secret")
    monkeypatch.setattr("backend.app.admin_config.ADMIN_USERNAME", "admin")

    client = TestClient(app)
    client.post("/admin/login", json={"username": "admin", "password": "secret"})

    config = unwrap(client.get("/admin/config"))
    config["dimension_weights"]["malware"] = -1

    resp = client.put("/admin/config", json=config)
    assert resp.status_code == 422
    assert resp.json()["success"] is False
    assert "malware" in resp.json()["errors"][0]