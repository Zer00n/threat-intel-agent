from __future__ import annotations

import time

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.db.repositories.sources_health import get_all_health
from app.db.repositories.sources_health import upsert_health
from app.utils.time import now_iso

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get("/health")
async def sources_health(db: AsyncSession = Depends(get_db)):
    health = await get_all_health(db)
    return {"sources": health}


@router.post("/test/{source_name}")
async def test_source(source_name: str, db: AsyncSession = Depends(get_db)):
    from app.agents.enrichment.orchestrator import SOURCE_MAP

    cls = SOURCE_MAP.get(source_name)
    if not cls:
        return {"error": f"Unknown source: {source_name}"}

    src = cls()
    try:
        start = time.monotonic()
        ok = await src.health_check()
        elapsed = int((time.monotonic() - start) * 1000)
        status = "ok" if ok else "down"
        error = None if ok else _source_hint(source_name)
        await upsert_health(db, source_name, status, elapsed, error)
        return {"source": source_name, "status": status, "response_time_ms": elapsed, "hint": error}
    except Exception as e:
        await upsert_health(db, source_name, "down", error=str(e))
        return {"source": source_name, "status": "error", "error": str(e)}
    finally:
        await src.close()


@router.post("/refresh_attck")
async def refresh_attck():
    from app.workers.attck_sync import sync_attck

    result = await sync_attck()
    return {**result, "timestamp": now_iso()}


@router.post("/refresh_kev")
async def refresh_kev():
    from app.workers.kev_sync import sync_kev

    result = await sync_kev()
    return {**result, "timestamp": now_iso()}


def _source_hint(source_name: str) -> str | None:
    if source_name == "ghsa":
        return "GitHub Advisory requires a valid github_token saved in settings or GITHUB_TOKEN in .env"
    if source_name == "attck":
        return "Run refresh_attck to download the local ATT&CK STIX bundle"
    return None
