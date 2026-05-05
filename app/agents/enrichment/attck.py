from __future__ import annotations

import time

import structlog

from app.agents.enrichment.base import EnrichmentSource, SourceResult
from app.utils.attck_loader import get_group, get_software, get_technique, load_attck

logger = structlog.get_logger()


class AttckSource(EnrichmentSource):
    name = "attck"
    cache_ttl = 604800  # 7 days

    async def fetch(self, entity: str) -> SourceResult:
        t0 = time.monotonic()
        try:
            load_attck()
            obj = get_technique(entity) or get_group(entity) or get_software(entity)
            elapsed = int((time.monotonic() - t0) * 1000)
            if obj:
                return SourceResult(source=self.name, success=True, data=obj, response_time_ms=elapsed)
            return SourceResult(
                source=self.name,
                success=True,
                data={"found": False, "entity": entity},
                response_time_ms=elapsed,
            )
        except Exception as e:
            elapsed = int((time.monotonic() - t0) * 1000)
            logger.warning("attck_fetch_error", entity=entity, error=str(e))
            return SourceResult(source=self.name, success=False, error=str(e), response_time_ms=elapsed)

    async def health_check(self) -> bool:
        try:
            load_attck()
            return True
        except Exception:
            return False
