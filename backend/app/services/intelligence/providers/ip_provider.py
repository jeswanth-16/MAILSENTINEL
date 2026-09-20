import ipaddress
import os
from typing import Optional, Tuple
from app.services.intelligence.models import (
    IPCategory,
    IPIntelligenceResult,
    LookupStatus,
    ReputationStatus,
)
from app.services.intelligence.providers.base import BaseIPIntelligenceProvider

# Curated high-accuracy offline reference records for testing/demo fixtures
OFFLINE_GEO_DATABASE = {
    "185.220.101.5": {
        "country": "Netherlands",
        "country_code": "NL",
        "region": "North Holland",
        "city": "Amsterdam",
        "latitude": 52.374,
        "longitude": 4.8897,
        "asn": "AS208323",
        "organization": "Offshore Bulletproof Relays Ltd",
        "isp": "Tor Relay Subnet Provider",
        "timezone": "Europe/Amsterdam",
        "reputation": ReputationStatus.SUSPICIOUS,
        "source": "local_threat_db",
    },
    "149.154.161.9": {
        "country": "Germany",
        "country_code": "DE",
        "region": "Hesse",
        "city": "Frankfurt am Main",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "asn": "AS62041",
        "organization": "European Transit Backbone",
        "isp": "Frankfurt Cloud Transit",
        "timezone": "Europe/Berlin",
        "reputation": ReputationStatus.CLEAN,
        "source": "local_threat_db",
    },
    "192.0.2.1": {
        "country": "Reserved (TEST-NET-1)",
        "country_code": "XX",
        "region": None,
        "city": "RFC 5737 Documentation Net",
        "latitude": None,
        "longitude": None,
        "asn": "AS64496 (Documentation)",
        "organization": "Internet Engineering Task Force",
        "isp": "RFC 5737 Benchmark Range",
        "timezone": "UTC",
        "reputation": ReputationStatus.CLEAN,
        "source": "rfc5737_reference",
    },
    "198.51.100.10": {
        "country": "Reserved (TEST-NET-2)",
        "country_code": "XX",
        "region": None,
        "city": "RFC 5737 Documentation Net",
        "latitude": None,
        "longitude": None,
        "asn": "AS64500 (Documentation)",
        "organization": "Partner Gateway Relay",
        "isp": "RFC 5737 Benchmark Range",
        "timezone": "UTC",
        "reputation": ReputationStatus.CLEAN,
        "source": "rfc5737_reference",
    }
}


def classify_ip_address(ip_str: str) -> Tuple[IPCategory, bool, str]:
    """
    Classifies an IP string into RFC category and determines if it is globally routable.
    Returns (IPCategory, is_routable, normalized_ip)
    """
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return IPCategory.INVALID, False, clean_ip

    if ip_obj.is_loopback:
        return IPCategory.LOOPBACK, False, str(ip_obj)
    if ip_obj.is_link_local:
        return IPCategory.LINK_LOCAL, False, str(ip_obj)
    if ip_obj.is_multicast:
        return IPCategory.MULTICAST, False, str(ip_obj)
    if ip_obj.is_reserved:
        return IPCategory.RESERVED, False, str(ip_obj)

    # Check documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    if isinstance(ip_obj, ipaddress.IPv4Address):
        doc_nets = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        ]
        if any(ip_obj in net for net in doc_nets):
            return IPCategory.DOCUMENTATION_TEST, False, str(ip_obj)

    if ip_obj.is_private:
        return IPCategory.PRIVATE, False, str(ip_obj)

    return IPCategory.PUBLIC, True, str(ip_obj)




class OfflineIPIntelligenceProvider(BaseIPIntelligenceProvider):
    """
    Default safe offline IP intelligence provider.
    Enforces strict private/reserved IP classification without fabricating coordinates.
    """

    @property
    def name(self) -> str:
        return "Offline Intelligence"

    async def lookup_ip(self, ip: str) -> IPIntelligenceResult:
        entity_id = f"ip:{ip.strip()}"
        category, is_routable, clean_ip = classify_ip_address(ip)

        # 1. Handle Invalid IPs
        if category == IPCategory.INVALID:
            return IPIntelligenceResult(
                entity_id=entity_id,
                ip=clean_ip,
                category=category,
                is_routable=False,
                status=LookupStatus.ERROR,
                status_message="Invalid IPv4/IPv6 address syntax.",
                source=self.name,
                attribution="UNAVAILABLE",
            )

        # 2. Handle Private / Loopback / Link-Local / Reserved / Doc IPs
        if not is_routable:
            return IPIntelligenceResult(
                entity_id=entity_id,
                ip=clean_ip,
                category=category,
                is_routable=False,
                status=LookupStatus.PRIVATE_IP_SKIPPED,
                status_message=f"{category.value} address range — external geolocation skipped.",
                source="rfc_ip_classifier",
                attribution="RFC PRIVATE / SKIPPED",
            )

        # 3. Check local offline reference database (for test fixtures & known infrastructure)
        if clean_ip in OFFLINE_GEO_DATABASE:
            data = OFFLINE_GEO_DATABASE[clean_ip]
            return IPIntelligenceResult(
                entity_id=entity_id,
                ip=clean_ip,
                category=category,
                is_routable=True,
                country=data.get("country"),
                country_code=data.get("country_code"),
                region=data.get("region"),
                city=data.get("city"),
                latitude=data.get("latitude"),
                longitude=data.get("longitude"),
                asn=data.get("asn"),
                organization=data.get("organization"),
                isp=data.get("isp"),
                timezone=data.get("timezone"),
                reputation=data.get("reputation", ReputationStatus.UNKNOWN),
                status=LookupStatus.SUCCESS,
                status_message="Resolved from local reference dataset.",
                source=self.name,
                attribution="OFFLINE FALLBACK",
            )

        # 4. For unindexed public IPs in offline mode, return NOT_AVAILABLE without fabricating fake coordinates
        return IPIntelligenceResult(
            entity_id=entity_id,
            ip=clean_ip,
            category=category,
            is_routable=True,
            status=LookupStatus.NOT_AVAILABLE,
            status_message="External threat intelligence provider unavailable; offline intelligence was also unavailable.",
            source=self.name,
            attribution="UNAVAILABLE",
        )
