from abc import ABC, abstractmethod
from typing import Optional
from app.services.intelligence.models import (
    DomainIntelligenceResult,
    IPIntelligenceResult,
    URLIntelligenceResult,
)


class BaseIPIntelligenceProvider(ABC):
    """Abstract interface for IP geolocation and ASN intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def lookup_ip(self, ip: str) -> IPIntelligenceResult:
        pass


class BaseDomainIntelligenceProvider(ABC):
    """Abstract interface for Domain analysis and DNS intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> DomainIntelligenceResult:
        pass


class BaseURLIntelligenceProvider(ABC):
    """Abstract interface for URL structural and reputation intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def lookup_url(self, url: str) -> URLIntelligenceResult:
        pass
