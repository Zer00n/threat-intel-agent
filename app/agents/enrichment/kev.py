from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import structlog

from app.agents.enrichment.base import EnrichmentSource, SourceResult
from app.config import settings

logger = structlog.get_logger()

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevSource(EnrichmentSource):
    name = "kev"
    base_url = KEV_URL
    cache_ttl = 86400

    def __init__(self, client: httpx.AsyncClient | None = None):
        super().__init__(client)
        self._local_index: dict[str, dict] = {}
        self._loaded = False

    def _cache_path(self) -> Path:
        return settings.data_dir_path / "kev_cache.json"

    async def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        cache_file = self._cache_path()
        if cache_file.exists():
            try:
                raw = json.loads(cache_file.read_text(encoding="utf-8"))
                self._build_index(raw)
                return
            except Exception:
                logger.warning("kev_cache_load_failed")
        await self._download_and_cache()

    async def _download_and_cache(self) -> None:
        try:
            resp = await self._client.get(KEV_URL, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            self._build_index(data)
            self._cache_path().parent.mkdir(parents=True, exist_ok=True)
            self._cache_path().write_text(json.dumps(data), encoding="utf-8")
            logger.info("kev_downloaded", count=len(self._local_index))
        except Exception as e:
            logger.warning("kev_download_failed", error=str(e))

    def _build_index(self, raw: dict) -> None:
        self._local_index.clear()
        for vuln in raw.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                self._local_index[cve_id] = vuln
        self._loaded = True

    async def fetch(self, entity: str) -> SourceResult:
        t0 = time.monotonic()
        await self._ensure_loaded()
        vuln = self._local_index.get(entity)
        elapsed = int((time.monotonic() - t0) * 1000)
        if vuln:
            return SourceResult(source=self.name, success=True, data=vuln, response_time_ms=elapsed)
        return SourceResult(
            source=self.name,
            success=True,
            data={"in_kev": False},
            response_time_ms=elapsed,
        )

    async def sync(self) -> bool:
        """Manual sync trigger."""
        try:
            await self._download_and_cache()
            return True
        except Exception:
            return False

    async def health_check(self) -> bool:
        try:
            resp = await self._client.head(KEV_URL, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False
