from __future__ import annotations

import asyncio

import structlog
from sqlalchemy import select

from app.db.engine import async_session_factory
from app.db.models import Analysis, TokenUsageMonthly
from app.utils.time import now_iso

logger = structlog.get_logger()
_INTERVAL = 3600  # 1 hour


async def run_periodic() -> None:
    while True:
        try:
            await aggregate_monthly()
        except Exception:
            logger.exception("token_aggregator_error")
        await asyncio.sleep(_INTERVAL)


async def aggregate_monthly() -> None:
    async with async_session_factory() as db:
        result = await db.execute(
            select(Analysis).where(Analysis.status == "completed")
        )
        analyses = result.scalars().all()

        monthly: dict[str, dict] = {}
        for a in analyses:
            ym = a.created_at[:7]  # "2026-05"
            if ym not in monthly:
                monthly[ym] = {"input": 0, "output": 0, "cost": 0.0, "count": 0}
            monthly[ym]["input"] += a.token_input
            monthly[ym]["output"] += a.token_output
            monthly[ym]["cost"] += a.cost_usd
            monthly[ym]["count"] += 1

        now = now_iso()
        for ym, data in monthly.items():
            obj = TokenUsageMonthly(
                year_month=ym,
                total_input=data["input"],
                total_output=data["output"],
                total_cost_usd=data["cost"],
                analysis_count=data["count"],
                updated_at=now,
            )
            await db.merge(obj)
        await db.commit()

    logger.debug("token_aggregation_done", months=len(monthly))
