from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.db.engine import close_db, init_db
from app.routers import analyze, export, history, settings as settings_router, sources, stream, system

logger = structlog.get_logger()


async def startup_recovery() -> None:
    from app.db.engine import async_session_factory
    from app.db.models import Analysis
    from app.utils.time import now_iso
    from sqlalchemy import update

    async with async_session_factory() as db:
        await db.execute(
            update(Analysis)
            .where(Analysis.status == "running")
            .values(
                status="interrupted",
                error_message="Service restarted while running",
                updated_at=now_iso(),
            )
        )
        await db.commit()
    logger.info("startup_recovery_done")


async def start_background_workers() -> None:
    from app.workers import attck_sync, cache_cleanup, health_check, kev_sync, token_aggregator  # noqa: F401

    asyncio.create_task(health_check.run_periodic(), name="health_check")
    asyncio.create_task(cache_cleanup.run_periodic(), name="cache_cleanup")
    asyncio.create_task(attck_sync.run_periodic(), name="attck_sync")
    asyncio.create_task(kev_sync.run_periodic(), name="kev_sync")
    asyncio.create_task(token_aggregator.run_periodic(), name="token_aggregator")
    logger.info("background_workers_started")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    settings.data_dir_path.mkdir(parents=True, exist_ok=True)
    (settings.data_dir_path / "attck").mkdir(parents=True, exist_ok=True)

    await init_db()
    await startup_recovery()
    await start_background_workers()

    logger.info("app_started", host=settings.host, port=settings.port)
    yield

    # Shutdown
    await close_db()
    logger.info("app_stopped")


app = FastAPI(
    title="Threat Intel Agent",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(system.router)
app.include_router(sources.router)
app.include_router(analyze.router)
app.include_router(stream.router)
app.include_router(history.router)
app.include_router(export.router)
app.include_router(settings_router.router)


@app.get("/api/info")
async def api_info():
    return {"name": "ti-agent", "version": "2.0.0"}


# Mount static files - must be last so API routes take priority
try:
    app.mount("/", StaticFiles(directory="static", html=True), name="static")
except Exception:
    pass  # static dir may not exist yet
