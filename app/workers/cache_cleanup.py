from __future__ import annotations

import asyncio

import structlog

logger = structlog.get_logger()
_INTERVAL = 3600  # 1 hour


async def run_periodic() -> None:
    while True:
        try:
            await _cleanup_expired()
        except Exception:
            logger.exception("cache_cleanup_error")
        await asyncio.sleep(_INTERVAL)


async def _cleanup_expired() -> None:
    # Placeholder - will be implemented in Phase 2
    logger.debug("cache_cleanup_tick")
