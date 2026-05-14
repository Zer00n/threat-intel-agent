from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import DataSourceCache
from app.utils.time import now_iso, parse_iso


async def get_cached(db: AsyncSession, cache_key: str) -> dict | None:
    result = await db.execute(select(DataSourceCache).where(DataSourceCache.cache_key == cache_key))
    row = result.scalar_one_or_none()
    if row is None:
        return None
    expires = parse_iso(row.expires_at)
    if expires < datetime.now(timezone.utc):
        return None
    return json.loads(row.payload)


async def set_cached(db: AsyncSession, cache_key: str, source: str, payload: dict, ttl_seconds: int) -> None:
    now = now_iso()
    expires = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    obj = DataSourceCache(
        cache_key=cache_key,
        source=source,
        payload=json.dumps(payload),
        fetched_at=now,
        ttl_seconds=ttl_seconds,
        expires_at=expires.isoformat(),
    )
    await db.merge(obj)
    await db.commit()


async def cleanup_expired(db: AsyncSession) -> int:
    now = now_iso()
    result = await db.execute(delete(DataSourceCache).where(DataSourceCache.expires_at < now))
    await db.commit()
    return result.rowcount
