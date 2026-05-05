from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()
_INTERVAL = 604800  # 7 days

ATTCK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


async def run_periodic() -> None:
    while True:
        try:
            await sync_attck()
        except Exception:
            logger.exception("attck_sync_error")
        await asyncio.sleep(_INTERVAL)


async def sync_attck() -> bool:
    target = settings.attck_bundle_file
    target.parent.mkdir(parents=True, exist_ok=True)

    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.get(ATTCK_URL)
        resp.raise_for_status()
        target.write_bytes(resp.content)

    logger.info("attck_synced", path=str(target), size=target.stat().st_size)
    return True
