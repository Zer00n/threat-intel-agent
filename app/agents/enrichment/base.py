from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog
from aiolimiter import AsyncLimiter

logger = structlog.get_logger()


def make_proxied_client(**kwargs) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with proxy from settings if configured."""
    from app.config import settings
    proxy = settings.http_proxy
    if proxy:
        kwargs["proxy"] = proxy
    return httpx.AsyncClient(**kwargs)


@dataclass
class SourceResult:
    source: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    from_cache: bool = False
    response_time_ms: int = 0


class EnrichmentSource(ABC):
    name: str = "unknown"
    base_url: str = ""
    cache_ttl: int = 86400  # seconds

    def __init__(self, client: httpx.AsyncClient | None = None, limiter: AsyncLimiter | None = None):
        self._client = client or make_proxied_client(timeout=15)
        self._limiter = limiter or AsyncLimiter(10, 1)
        self._owns_client = client is None

    @abstractmethod
    async def fetch(self, entity: str) -> SourceResult:
        """Fetch data for a given entity (CVE ID, technique ID, etc.)."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if this source is reachable."""
        ...

    async def close(self) -> None:
        if self._owns_client and self._client:
            await self._client.aclose()
