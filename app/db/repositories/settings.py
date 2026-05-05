from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Setting
from app.utils.crypto import decrypt_value


async def get_setting(db: AsyncSession, key: str) -> str | None:
    result = await db.execute(select(Setting).where(Setting.key == key))
    row = result.scalar_one_or_none()
    if row is None:
        return None
    if row.is_encrypted:
        try:
            return decrypt_value(row.value)
        except Exception:
            return None
    try:
        return json.loads(row.value)
    except (json.JSONDecodeError, TypeError):
        return row.value
