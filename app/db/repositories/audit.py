from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog
from app.utils.time import now_iso


async def log_event(db: AsyncSession, event_type: str, detail: dict | None = None) -> None:
    log = AuditLog(
        event_type=event_type,
        detail=json.dumps(detail) if detail else None,
        created_at=now_iso(),
    )
    db.add(log)
    await db.commit()


async def get_audit_logs(db: AsyncSession, limit: int = 100) -> list[dict]:
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    )
    return [
        {
            "id": row.id,
            "event_type": row.event_type,
            "detail": json.loads(row.detail) if row.detail else None,
            "created_at": row.created_at,
        }
        for row in result.scalars()
    ]
