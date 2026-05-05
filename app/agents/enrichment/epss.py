from __future__ import annotations

import time

import httpx
import structlog
from aiolimiter import AsyncLimiter

from app.agents.enrichment.base import EnrichmentSource, SourceResult

logger = structlog.get_logger()

EPSS_BASE = "https://api.first.org/data/v1/epss"
_RATE_LIMIT = AsyncLimiter(10, 1)


class EpssSource(EnrichmentSource):
    name = "epss"
    base_url = EPSS_BASE
    cache_ttl = 21600  # 6 hours

    def __init__(self, client: httpx.AsyncClient | None = None, limiter: AsyncLimiter | None = None):
        super().__init__(client, limiter or _RATE_LIMIT)

    async def fetch(self, entity: str) -> SourceResult:
        t0 = time.monotonic()
        async with self._limiter:
            try:
                resp = await self._client.get(EPSS_BASE, params={"cve": entity}, timeout=15)
                resp.raise_for_status()
                data = resp.json()
                elapsed = int((time.monotonic() - t0) * 1000)
                items = data.get("data", [])
                if items:
                    item = items[0]
                    return SourceResult(
                        source=self.name,
                        success=True,
                        data={
                            "epss": item.get("epss"),
                            "percentile": item.get("percentile"),
                            "date": item.get("date"),
                        },
                        response_time_ms=elapsed,
                    )
                return SourceResult(source=self.name, success=True, data={}, response_time_ms=elapsed)
            except Exception as e:
                elapsed = int((time.monotonic() - t0) * 1000)
                logger.warning("epss_fetch_error", entity=entity, error=str(e))
                return SourceResult(source=self.name, success=False, error=str(e), response_time_ms=elapsed)

    async def health_check(self) -> bool:
        try:
            async with self._limiter:
                resp = await self._client.get(EPSS_BASE, params={"cve": "CVE-2024-21413"}, timeout=10)
                return resp.status_code == 200
        except Exception:
            return False
