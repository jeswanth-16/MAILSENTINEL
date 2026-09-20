import asyncio
import logging
import os
import time
from unittest.mock import AsyncMock, patch
import httpx
import pytest

from app.services.intelligence.cache import IntelligenceCache
from app.services.intelligence.models import (
    IPCategory,
    LookupStatus,
    ReputationStatus,
)
from app.services.intelligence.providers.abuseipdb_provider import AbuseIPDBProvider
from app.services.intelligence.providers.ip_provider import OfflineIPIntelligenceProvider
from app.services.intelligence.service import IntelligenceService


def create_mock_abuseipdb_response(status_code: int = 200, score: int = 92, payload_override: dict = None):
    if payload_override is not None:
        data = payload_override
    else:
        data = {
            "data": {
                "ipAddress": "185.220.101.5",
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidenceScore": score,
                "countryCode": "NL",
                "countryName": "Netherlands",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Tor Relay Subnet Provider",
                "domain": "tor-node.net",
                "totalReports": 142,
                "numDistinctUsers": 48,
                "lastReportedAt": "2026-04-21T18:31:39+00:00",
            }
        }
    req = httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check")
    return httpx.Response(status_code=status_code, json=data, request=req)


# 1. AbuseIPDB provider with mocked successful response
@pytest.mark.anyio
async def test_abuseipdb_mocked_success():
    provider = AbuseIPDBProvider(api_key="test_api_key_12345")
    mock_resp = create_mock_abuseipdb_response(status_code=200, score=92)

    with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_resp)):
        res = await provider.lookup_ip("185.220.101.5")

    assert res.ip == "185.220.101.5"
    assert res.status == LookupStatus.SUCCESS
    assert res.source == "AbuseIPDB"
    assert res.attribution == "REAL-TIME"
    assert res.cached is False
    assert res.country == "Netherlands"
    assert res.country_code == "NL"
    assert res.isp == "Tor Relay Subnet Provider"
    assert res.domain == "tor-node.net"
    assert res.usage_type == "Data Center/Web Hosting/Transit"
    assert res.abuse_confidence_score == 92
    assert res.total_reports == 142
    assert res.last_reported_at == "2026-04-21T18:31:39+00:00"
    assert res.reputation == ReputationStatus.KNOWN_MALICIOUS


# 2. AbuseIPDB malicious result normalization
@pytest.mark.anyio
async def test_abuseipdb_malicious_normalization():
    provider = AbuseIPDBProvider(api_key="test_api_key")

    # High abuse score >= 50
    mock_resp_mal = create_mock_abuseipdb_response(score=85)
    with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_resp_mal)):
        res_mal = await provider.lookup_ip("185.220.101.5")
    assert res_mal.reputation == ReputationStatus.KNOWN_MALICIOUS

    # Suspicious score > 0 and < 50
    mock_resp_susp = create_mock_abuseipdb_response(score=25)
    with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_resp_susp)):
        res_susp = await provider.lookup_ip("185.220.101.5")
    assert res_susp.reputation == ReputationStatus.SUSPICIOUS


# 3. AbuseIPDB clean result normalization
@pytest.mark.anyio
async def test_abuseipdb_clean_normalization():
    provider = AbuseIPDBProvider(api_key="test_api_key")
    mock_resp_clean = create_mock_abuseipdb_response(score=0)
    with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_resp_clean)):
        res_clean = await provider.lookup_ip("185.220.101.5")
    assert res_clean.reputation == ReputationStatus.CLEAN
    assert res_clean.abuse_confidence_score == 0


# 4. Missing API key fallback
@pytest.mark.anyio
async def test_missing_api_key_fallback():
    # Without an API key, IntelligenceService falls back to offline reference DB
    cache = IntelligenceCache(default_ttl_seconds=300)
    service = IntelligenceService(
        abuseipdb_provider=AbuseIPDBProvider(api_key=None),
        offline_ip_provider=OfflineIPIntelligenceProvider(),
        cache=cache,
    )

    res = await service.get_ip_intelligence("185.220.101.5")
    assert res.status == LookupStatus.SUCCESS
    assert res.source == "Offline Intelligence"
    assert res.attribution == "OFFLINE FALLBACK"
    assert res.country == "Netherlands"
    assert res.asn == "AS208323"


# 5. Provider timeout fallback
@pytest.mark.anyio
async def test_provider_timeout_fallback():
    cache = IntelligenceCache(default_ttl_seconds=300)
    service = IntelligenceService(
        abuseipdb_provider=AbuseIPDBProvider(api_key="valid_key"),
        offline_ip_provider=OfflineIPIntelligenceProvider(),
        cache=cache,
    )

    with patch.object(httpx.AsyncClient, "get", side_effect=httpx.TimeoutException("Timeout")):
        res = await service.get_ip_intelligence("185.220.101.5")

    assert res.status == LookupStatus.SUCCESS
    assert res.source == "Offline Intelligence"
    assert res.attribution == "OFFLINE FALLBACK"


# 6. Provider HTTP error fallback
@pytest.mark.anyio
async def test_provider_http_error_fallback():
    cache = IntelligenceCache(default_ttl_seconds=300)
    service = IntelligenceService(
        abuseipdb_provider=AbuseIPDBProvider(api_key="valid_key"),
        offline_ip_provider=OfflineIPIntelligenceProvider(),
        cache=cache,
    )

    req = httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check")
    err_resp = httpx.Response(status_code=500, request=req)

    with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=err_resp)):
        res = await service.get_ip_intelligence("185.220.101.5")

    assert res.status == LookupStatus.SUCCESS
    assert res.source == "Offline Intelligence"
    assert res.attribution == "OFFLINE FALLBACK"


# 7. Rate-limit handling
@pytest.mark.anyio
async def test_rate_limit_handling():
    cache = IntelligenceCache(default_ttl_seconds=300)
    service = IntelligenceService(
        abuseipdb_provider=AbuseIPDBProvider(api_key="valid_key"),
        offline_ip_provider=OfflineIPIntelligenceProvider(),
        cache=cache,
    )

    req = httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check")
    rate_resp = httpx.Response(status_code=429, request=req)

    with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=rate_resp)):
        res = await service.get_ip_intelligence("185.220.101.5")

    assert res.status == LookupStatus.SUCCESS
    assert res.source == "Offline Intelligence"
    assert res.attribution == "OFFLINE FALLBACK"


# 8. Invalid provider response
@pytest.mark.anyio
async def test_invalid_provider_response():
    cache = IntelligenceCache(default_ttl_seconds=300)
    service = IntelligenceService(
        abuseipdb_provider=AbuseIPDBProvider(api_key="valid_key"),
        offline_ip_provider=OfflineIPIntelligenceProvider(),
        cache=cache,
    )

    req = httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check")
    bad_resp = httpx.Response(status_code=200, json={"data": "corrupt_string_not_dict"}, request=req)

    with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=bad_resp)):
        res = await service.get_ip_intelligence("185.220.101.5")

    assert res.status == LookupStatus.SUCCESS
    assert res.source == "Offline Intelligence"


# 9. Cache hit
@pytest.mark.anyio
async def test_cache_hit():
    cache = IntelligenceCache(default_ttl_seconds=300)
    provider = AbuseIPDBProvider(api_key="test_key")
    service = IntelligenceService(abuseipdb_provider=provider, cache=cache)

    mock_resp = create_mock_abuseipdb_response(score=90)
    with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_resp)) as mock_get:
        # First call: cache miss, hits provider
        res1 = await service.get_ip_intelligence("185.220.101.5")
        assert res1.source == "AbuseIPDB"
        assert res1.attribution == "REAL-TIME"
        assert res1.cached is False
        assert mock_get.call_count == 1

        # Second call: cache hit, provider NOT called
        res2 = await service.get_ip_intelligence("185.220.101.5")
        assert res2.source == "AbuseIPDB"
        assert res2.attribution == "CACHED"
        assert res2.cached is True
        assert mock_get.call_count == 1  # No second external request


# 10. Cache expiry
def test_cache_expiry():
    cache = IntelligenceCache(default_ttl_seconds=1)
    cache.set("test_key", {"result": "ok"})
    assert cache.get("test_key") == {"result": "ok"}

    time.sleep(1.2)
    assert cache.get("test_key") is None


# 11. Offline fallback
@pytest.mark.anyio
async def test_offline_fallback():
    provider = OfflineIPIntelligenceProvider()
    res = await provider.lookup_ip("185.220.101.5")
    assert res.status == LookupStatus.SUCCESS
    assert res.source == "Offline Intelligence"
    assert res.attribution == "OFFLINE FALLBACK"
    assert res.country == "Netherlands"


# 12. Unknown IP -> NOT_AVAILABLE
@pytest.mark.anyio
async def test_unknown_ip_not_available():
    cache = IntelligenceCache(default_ttl_seconds=300)
    service = IntelligenceService(
        abuseipdb_provider=AbuseIPDBProvider(api_key=None),
        offline_ip_provider=OfflineIPIntelligenceProvider(),
        cache=cache,
    )

    res = await service.get_ip_intelligence("8.8.4.4")
    assert res.status == LookupStatus.NOT_AVAILABLE
    assert res.attribution == "UNAVAILABLE"
    assert res.source == "Offline Intelligence"
    assert "External threat intelligence provider unavailable" in res.status_message


# 13. Private/reserved IP handling
@pytest.mark.anyio
async def test_private_reserved_ip_handling():
    provider = AbuseIPDBProvider(api_key="real_key_should_not_be_used")

    with patch.object(httpx.AsyncClient, "get") as mock_get:
        # Private RFC 1918
        res_priv = await provider.lookup_ip("192.168.1.50")
        assert res_priv.status == LookupStatus.PRIVATE_IP_SKIPPED
        assert res_priv.attribution == "RFC PRIVATE / SKIPPED"
        assert res_priv.latitude is None
        assert res_priv.longitude is None

        # Documentation RFC 5737
        res_doc = await provider.lookup_ip("192.0.2.1")
        assert res_doc.status == LookupStatus.PRIVATE_IP_SKIPPED
        assert res_doc.attribution == "RFC PRIVATE / SKIPPED"

        # Verify no external HTTP requests were attempted
        mock_get.assert_not_called()


# 14. API endpoint compatibility
def test_api_endpoint_compatibility(client):
    resp = client.post("/api/v1/intelligence/ip", json={"ip": "185.220.101.5"})
    assert resp.status_code == 200
    data = resp.json()
    assert "entity_id" in data
    assert "ip" in data
    assert "reputation" in data
    assert "status" in data
    assert "source" in data
    assert "attribution" in data
    assert "cached" in data


# 15. API key never appears in response or log output
@pytest.mark.anyio
async def test_api_key_never_appears_in_response_or_logs(caplog):
    secret_key = "CONFIDENTIAL_KEY_XYZ_98765"
    provider = AbuseIPDBProvider(api_key=secret_key)
    mock_resp = create_mock_abuseipdb_response(score=80)

    with caplog.at_level(logging.DEBUG):
        with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_resp)):
            res = await provider.lookup_ip("185.220.101.5")

    # Verify key is not in serialized model dict
    res_dict = res.model_dump()
    for v in res_dict.values():
        assert secret_key not in str(v)

    # Verify key is not in any logging text
    assert secret_key not in caplog.text
