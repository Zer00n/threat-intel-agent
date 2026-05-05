from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import SourceHealth
from app.utils.time import now_iso


async def get_all_health(db: AsyncSession) -> list[dict]:
    result = await db.execute(select(SourceHealth))
    return [
        {
            "source_name": row.source_name,
            "status": row.status,
            "last_check_at": row.last_check_at,
            "last_success_at": row.last_success_at,
            "last_error": row.last_error,
            "response_time_ms": row.response_time_ms,
        }
        for row in result.scalars()
    ]


async def upsert_health(
    db: AsyncSession,
    source_name: str,
    status: str,
    response_time_ms: int | None = None,
    error: str | None = None,
) -> None:
    now = now_iso()
    result = await db.execute(select(SourceHealth).where(SourceHealth.source_name == source_name))
    row = result.scalar_one_or_none()
    if row:
        row.status = status
        row.last_check_at = now
        row.response_time_ms = response_time_ms
        row.last_error = error
        if status == "ok":
            row.last_success_at = now
    else:
        db.add(SourceHealth(
            source_name=source_name,
            status=status,
            last_check_at=now,
            last_success_at=now if status == "ok" else None,
            response_time_ms=response_time_ms,
            last_error=error,
        ))
    await db.commit()
