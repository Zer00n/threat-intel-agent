from __future__ import annotations

import asyncio
import json
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


async def sync_attck() -> dict:
    target = settings.attck_bundle_file
    target.parent.mkdir(parents=True, exist_ok=True)

    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.get(ATTCK_URL)
        resp.raise_for_status()
        target.write_bytes(resp.content)

    data = json.loads(target.read_text(encoding="utf-8"))
    objects = data.get("objects", [])
    summary = {
        "success": True,
        "objects_count": len(objects),
        "attack_patterns": sum(1 for obj in objects if obj.get("type") == "attack-pattern"),
        "groups": sum(1 for obj in objects if obj.get("type") == "intrusion-set"),
        "software": sum(1 for obj in objects if obj.get("type") in {"malware", "tool"}),
        "size_bytes": target.stat().st_size,
        "path": str(target),
    }
    logger.info("attck_synced", **summary)
    return summary
