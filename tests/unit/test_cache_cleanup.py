"""Tests for cache cleanup worker."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.db.models import Base, DataSourceCache
from app.db.repositories.cache import cleanup_expired, set_cached, get_cached
from app.utils.time import now_iso


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


class TestCleanupExpired:
    @pytest.mark.asyncio
    async def test_removes_expired_entries(self, db_session):
        now = datetime.now(timezone.utc)
        expired = (now - timedelta(hours=1)).isoformat()
        future = (now + timedelta(hours=1)).isoformat()

        db_session.add(DataSourceCache(
            cache_key="expired_1", source="nvd",
            payload=json.dumps({"data": "old"}), fetched_at=now_iso(),
            ttl_seconds=3600, expires_at=expired,
        ))
        db_session.add(DataSourceCache(
            cache_key="valid_1", source="nvd",
            payload=json.dumps({"data": "fresh"}), fetched_at=now_iso(),
            ttl_seconds=3600, expires_at=future,
        ))
        await db_session.commit()

        removed = await cleanup_expired(db_session)
        assert removed == 1

        # Valid entry should still be accessible
        cached = await get_cached(db_session, "valid_1")
        assert cached == {"data": "fresh"}

        # Expired entry should be gone
        cached = await get_cached(db_session, "expired_1")
        assert cached is None

    @pytest.mark.asyncio
    async def test_no_expired_entries(self, db_session):
        now = datetime.now(timezone.utc)
        future = (now + timedelta(hours=1)).isoformat()

        db_session.add(DataSourceCache(
            cache_key="valid_2", source="epss",
            payload=json.dumps({"score": 0.5}), fetched_at=now_iso(),
            ttl_seconds=3600, expires_at=future,
        ))
        await db_session.commit()

        removed = await cleanup_expired(db_session)
        assert removed == 0

    @pytest.mark.asyncio
    async def test_empty_database(self, db_session):
        removed = await cleanup_expired(db_session)
        assert removed == 0


class TestCacheRoundtrip:
    @pytest.mark.asyncio
    async def test_set_and_get(self, db_session):
        data = {"cve_id": "CVE-2024-21413", "score": 9.8}
        await set_cached(db_session, "nvd:CVE-2024-21413", "nvd", data, ttl_seconds=600)

        result = await get_cached(db_session, "nvd:CVE-2024-21413")
        assert result == data

    @pytest.mark.asyncio
    async def test_expired_returns_none(self, db_session):
        data = {"old": True}
        now = datetime.now(timezone.utc)
        expired = (now - timedelta(seconds=1)).isoformat()

        db_session.add(DataSourceCache(
            cache_key="old_entry", source="test",
            payload=json.dumps(data), fetched_at=now_iso(),
            ttl_seconds=0, expires_at=expired,
        ))
        await db_session.commit()

        result = await get_cached(db_session, "old_entry")
        assert result is None

    @pytest.mark.asyncio
    async def test_missing_key_returns_none(self, db_session):
        result = await get_cached(db_session, "nonexistent")
        assert result is None
