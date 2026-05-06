from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.db.models import Analysis, AuditLog, SourceHealth, TokenUsageMonthly

router = APIRouter(tags=["system"])


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    if not db_ok:
        return {"status": "degraded", "db": False}

    return {"status": "ok", "db": True, "version": "0.5.0"}


@router.get("/stats")
async def stats(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count()).select_from(Analysis))).scalar() or 0
    completed = (await db.execute(
        select(func.count()).select_from(Analysis).where(Analysis.status == "completed")
    )).scalar() or 0
    running = (await db.execute(
        select(func.count()).select_from(Analysis).where(Analysis.status == "running")
    )).scalar() or 0
    cost = (await db.execute(select(func.coalesce(func.sum(Analysis.cost_usd), 0.0)))).scalar() or 0.0
    source_rows = (await db.execute(select(SourceHealth))).scalars().all()
    monthly_rows = (await db.execute(
        select(TokenUsageMonthly).order_by(TokenUsageMonthly.year_month.desc()).limit(12)
    )).scalars().all()

    return {
        "analyses": {
            "total": total,
            "completed": completed,
            "running": running,
        },
        "total_cost_usd": round(float(cost), 6),
        "sources": [
            {
                "source_name": row.source_name,
                "status": row.status,
                "last_check_at": row.last_check_at,
                "response_time_ms": row.response_time_ms,
            }
            for row in source_rows
        ],
        "monthly_usage": [
            {
                "year_month": row.year_month,
                "total_input": row.total_input,
                "total_output": row.total_output,
                "total_cost_usd": row.total_cost_usd,
                "analysis_count": row.analysis_count,
            }
            for row in monthly_rows
        ],
    }


@router.get("/audit_logs")
async def audit_logs(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event_type: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditLog)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    rows = (await db.execute(
        query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    )).scalars().all()
    return {
        "items": [
            {
                "id": row.id,
                "event_type": row.event_type,
                "detail": json.loads(row.detail) if row.detail else None,
                "created_at": row.created_at,
            }
            for row in rows
        ]
    }
