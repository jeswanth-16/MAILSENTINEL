import asyncio
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.intelligence.cache import IntelligenceCache
from app.services.intelligence.models import (
    IPCategory,
    LookupStatus,
    ReputationStatus,
)
from app.services.intelligence.providers.domain_provider import (
    OfflineDomainIntelligenceProvider,
)
from app.services.intelligence.providers.ip_provider import (
    OfflineIPIntelligenceProvider,
    classify_ip_address,
)
from app.services.intelligence.providers.url_provider import (
    OfflineURLIntelligenceProvider,
)
from app.services.intelligence.service import IntelligenceService


def test_ip_classification_rfc_rules():
    # Private RFC 1918
    cat, routable, _ = classify_ip_address("192.168.1.100")
    assert cat == IPCategory.PRIVATE
    assert routable is False

    cat, routable, _ = classify_ip_address("10.0.0.1")
    assert cat == IPCategory.PRIVATE
    assert routable is False

    # Loopback
    cat, routable, _ = classify_ip_address("127.0.0.1")
    assert cat == IPCategory.LOOPBACK
    assert routable is False

    # Documentation RFC 5737
    cat, routable, _ = classify_ip_address("192.0.2.1")
    assert cat == IPCategory.DOCUMENTATION_TEST
    assert routable is False

    # Public
    cat, routable, _ = classify_ip_address("185.220.101.5")
    assert cat == IPCategory.PUBLIC
    assert routable is True

    # Invalid
    cat, routable, _ = classify_ip_address("999.999.999.999")
    assert cat == IPCategory.INVALID
    assert routable is False


def test_offline_ip_provider_safe_behavior():
    provider = OfflineIPIntelligenceProvider()

    # 1. Private IP must be skipped without coordinates
    priv_res = asyncio.run(provider.lookup_ip("192.168.0.1"))
    assert priv_res.status == LookupStatus.PRIVATE_IP_SKIPPED
    assert priv_res.latitude is None
    assert priv_res.longitude is None
    assert priv_res.country is None

    # 2. Known offline public IP
    known_res = asyncio.run(provider.lookup_ip("185.220.101.5"))
    assert known_res.status == LookupStatus.SUCCESS
    assert known_res.country == "Netherlands"
    assert known_res.asn == "AS208323"
    assert known_res.latitude == 52.374
    assert known_res.reputation == ReputationStatus.SUSPICIOUS

    # 3. Unknown public IP in offline mode must NOT invent coordinates
    unknown_res = asyncio.run(provider.lookup_ip("8.8.4.4"))
    assert unknown_res.status == LookupStatus.NOT_AVAILABLE
    assert unknown_res.latitude is None
    assert unknown_res.longitude is None
    assert unknown_res.country is None


def test_offline_domain_provider():
    provider = OfflineDomainIntelligenceProvider()

    # Punycode detection
    puny_res = asyncio.run(provider.lookup_domain("xn--pypal-4ve.com"))
    assert puny_res.is_punycode is True
    assert any("Punycode" in ind for ind in puny_res.structural_indicators)

    # High-risk TLD and suspicious keywords
    tld_res = asyncio.run(provider.lookup_domain("secure-login-account.xyz"))
    assert tld_res.tld == "xyz"
    assert any("High-Risk" in ind for ind in tld_res.structural_indicators)
    assert any("Suspicious Keywords" in ind for ind in tld_res.structural_indicators)

    # Known domain
    known_res = asyncio.run(provider.lookup_domain("paypa1-security.com"))
    assert known_res.reputation == ReputationStatus.KNOWN_MALICIOUS


def test_offline_url_provider():
    provider = OfflineURLIntelligenceProvider()

    # Raw IP Host + Credential Path
    ip_url_res = asyncio.run(provider.lookup_url("http://185.220.101.5/auth/login.php"))
    assert ip_url_res.is_ip_host is True
    assert ip_url_res.has_credential_path is True
    assert ip_url_res.reputation == ReputationStatus.KNOWN_MALICIOUS

    # Clean legitimate URL
    clean_res = asyncio.run(provider.lookup_url("https://github.com/login"))
    assert clean_res.reputation == ReputationStatus.CLEAN


def test_intelligence_cache():
    cache = IntelligenceCache(default_ttl_seconds=2)
    cache.set("test_key", {"status": "ok"})
    assert cache.get("test_key") == {"status": "ok"}
    assert cache.size() == 1

    cache.clear()
    assert cache.get("test_key") is None
    assert cache.size() == 0


def test_intelligence_service_enrich_investigation():
    service = IntelligenceService()
    res = asyncio.run(
        service.enrich_investigation(
            investigation_id="inv_test_99",
            ips=["185.220.101.5", "192.168.1.1"],
            domains=["paypa1-security.com", "google.com"],
            urls=["http://185.220.101.5/auth/login.php"],
        )
    )

    assert res.investigation_id == "inv_test_99"
    assert len(res.ips) == 2
    assert len(res.domains) == 2
    assert len(res.urls) == 1
    assert res.summary.entities_analyzed == 5
    assert res.summary.private_skipped >= 1
    assert res.summary.successful_lookups >= 3


def test_api_intelligence_endpoints(client):
    # 1. IP Lookup API
    ip_resp = client.post("/api/v1/intelligence/ip", json={"ip": "185.220.101.5"})
    assert ip_resp.status_code == 200
    ip_data = ip_resp.json()
    assert ip_data["country"] == "Netherlands"
    assert ip_data["asn"] == "AS208323"

    # 2. Domain Lookup API
    dom_resp = client.post("/api/v1/intelligence/domain", json={"domain": "paypa1-security.com"})
    assert dom_resp.status_code == 200
    dom_data = dom_resp.json()
    assert dom_data["reputation"] == "KNOWN_MALICIOUS"

    # 3. URL Lookup API
    url_resp = client.post("/api/v1/intelligence/url", json={"url": "http://185.220.101.5/auth/login.php"})
    assert url_resp.status_code == 200
    url_data = url_resp.json()
    assert url_data["is_ip_host"] is True

    # 4. Investigation Enrichment API
    enrich_resp = client.post(
        "/api/v1/intelligence/investigation/inv_test_api",
        json={
            "ips": ["185.220.101.5", "10.0.0.5"],
            "domains": ["google.com"],
            "urls": ["http://185.220.101.5/auth/login.php"],
        },
    )
    assert enrich_resp.status_code == 200
    enrich_data = enrich_resp.json()
    assert enrich_data["investigation_id"] == "inv_test_api"
    assert enrich_data["summary"]["entities_analyzed"] == 4
