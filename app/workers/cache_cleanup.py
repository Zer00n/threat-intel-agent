from __future__ import annotations

import asyncio

import structlog

from app.db.engine import async_session_factory
from app.db.repositories.cache import cleanup_expired

logger = structlog.get_logger()
_INTERVAL = 3600  # 1 hour


async def run_periodic() -> None:
    while True:
        try:
            await _do_cleanup()
        except Exception:
            logger.exception("cache_cleanup_error")
        await asyncio.sleep(_INTERVAL)


async def _do_cleanup() -> None:
    async with async_session_factory() as db:
        removed = await cleanup_expired(db)
        if removed > 0:
            logger.info("cache_cleanup_done", removed=removed)
        else:
            logger.debug("cache_cleanup_tick")
