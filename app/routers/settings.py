from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.db.models import Setting, TrustedSource
from app.utils.crypto import decrypt_value, encrypt_value, mask_value
from app.utils.time import now_iso

router = APIRouter(prefix="/settings", tags=["settings"])

SENSITIVE_KEYS = {"nvd_api_key", "github_token", "secrets_encryption_key"}


class SettingsUpdate(BaseModel):
    nvd_api_key: str | None = None
    github_token: str | None = None
    monthly_budget_usd: float | None = None
    single_task_token_limit: int | None = None
    researcher_count_default: int | None = None
    tlp_default: str | None = None


class TrustedSourceAdd(BaseModel):
    domain: str
    note: str | None = None


@router.get("")
async def get_settings(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Setting))
    settings = {}
    for row in result.scalars():
        if row.key in SENSITIVE_KEYS:
            try:
                val = decrypt_value(row.value)
                settings[row.key] = mask_value(val)
            except Exception:
                settings[row.key] = "****"
        else:
            try:
                settings[row.key] = json.loads(row.value)
            except (json.JSONDecodeError, TypeError):
                settings[row.key] = row.value
    return settings


@router.put("")
async def update_settings(req: SettingsUpdate, db: AsyncSession = Depends(get_db)):
    now = now_iso()
    changed_keys = []
    for key, value in req.model_dump(exclude_none=True).items():
        if value is None:
            continue
        changed_keys.append(key)
        if key in SENSITIVE_KEYS and value:
            encrypted = encrypt_value(value)
            obj = Setting(key=key, value=encrypted, is_encrypted=True, updated_at=now)
        else:
            obj = Setting(key=key, value=json.dumps(value), is_encrypted=False, updated_at=now)
        await db.merge(obj)
    await db.commit()
    # Audit log (PRD §14.4) - only log which keys changed, not values
    if changed_keys:
        from app.db.repositories.audit import log_event
        await log_event(db, "setting_changed", {"keys": changed_keys})
    return {"updated": True}


@router.get("/trusted_sources")
async def list_trusted_sources(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(TrustedSource))
    return [
        {"domain": t.domain, "note": t.note, "added_at": t.added_at}
        for t in result.scalars()
    ]


@router.post("/trusted_sources")
async def add_trusted_source(req: TrustedSourceAdd, db: AsyncSession = Depends(get_db)):
    obj = TrustedSource(domain=req.domain, note=req.note, added_at=now_iso())
    await db.merge(obj)
    await db.commit()
    return {"added": req.domain}


@router.delete("/trusted_sources/{domain}")
async def delete_trusted_source(domain: str, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import delete
    await db.execute(delete(TrustedSource).where(TrustedSource.domain == domain))
    await db.commit()
    return {"deleted": domain}
