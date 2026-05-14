from __future__ import annotations

import asyncio

import httpx
import structlog

from app.agents.enrichment.base import make_proxied_client
from app.agents.enrichment.orchestrator import SOURCE_MAP
from app.db.engine import async_session_factory
from app.db.repositories.sources_health import upsert_health
from app.utils.time import now_iso

logger = structlog.get_logger()
_INTERVAL = 300  # 5 minutes


async def run_periodic() -> None:
    while True:
        try:
            await check_all_sources()
        except Exception:
            logger.exception("health_check_error")
        await asyncio.sleep(_INTERVAL)


async def check_all_sources() -> None:
    """Check health of all configured data sources and persist results."""
    async with make_proxied_client(timeout=10) as client:
        async with async_session_factory() as db:
            for source_name, source_cls in SOURCE_MAP.items():
                try:
                    src = source_cls(client=client)
                    t0 = __import__("time").monotonic()
                    ok = await src.health_check()
                    elapsed = int((__import__("time").monotonic() - t0) * 1000)
                    status = "ok" if ok else "down"
                    await upsert_health(db, source_name, status, elapsed)
                    await src.close()
                except Exception as e:
                    logger.warning("source_health_check_failed", source=source_name, error=str(e))
                    await upsert_health(db, source_name, "down", error=str(e))

    logger.debug("health_check_done")
