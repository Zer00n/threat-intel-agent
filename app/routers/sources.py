from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.db.repositories.sources_health import get_all_health
from app.utils.time import now_iso

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get("/health")
async def sources_health(db: AsyncSession = Depends(get_db)):
    health = await get_all_health(db)
    return {"sources": health}


@router.post("/test/{source_name}")
async def test_source(source_name: str):
    from app.agents.enrichment.orchestrator import SOURCE_MAP

    cls = SOURCE_MAP.get(source_name)
    if not cls:
        return {"error": f"Unknown source: {source_name}"}

    src = cls()
    try:
        ok = await src.health_check()
        return {"source": source_name, "status": "ok" if ok else "down"}
    except Exception as e:
        return {"source": source_name, "status": "error", "error": str(e)}
    finally:
        await src.close()


@router.post("/refresh_attck")
async def refresh_attck():
    from app.workers.attck_sync import sync_attck

    ok = await sync_attck()
    return {"success": ok, "timestamp": now_iso()}


@router.post("/refresh_kev")
async def refresh_kev():
    from app.workers.kev_sync import sync_kev

    ok = await sync_kev()
    return {"success": ok, "timestamp": now_iso()}
