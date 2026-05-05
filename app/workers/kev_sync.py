from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()
_INTERVAL = 86400  # 24 hours

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def run_periodic() -> None:
    while True:
        try:
            await sync_kev()
        except Exception:
            logger.exception("kev_sync_error")
        await asyncio.sleep(_INTERVAL)


async def sync_kev() -> bool:
    cache_path = settings.data_dir_path / "kev_cache.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
        cache_path.write_text(json.dumps(data), encoding="utf-8")

    count = len(data.get("vulnerabilities", []))
    logger.info("kev_synced", count=count)
    return True
