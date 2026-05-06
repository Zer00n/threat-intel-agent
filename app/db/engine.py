from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=False,
    connect_args={"check_same_thread": False},
)

async_session_factory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db_session() -> AsyncSession:
    async with async_session_factory() as session:
        yield session


async def init_db() -> None:
    from app.db.models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.execute(text("PRAGMA foreign_keys=ON"))
        await ensure_fts_schema(conn)


async def ensure_fts_schema(conn) -> None:
    """Create FTS5 search table for full-text search on analyses.

    Uses content='analyses' (not contentless) so that DELETE from the
    source table is supported — contentless FTS5 tables reject DELETE
    which was causing OperationalError on history deletion.
    """
    # Drop the old contentless FTS table + triggers if they exist
    await conn.execute(text("DROP TABLE IF EXISTS analyses_fts"))
    await conn.execute(text("DROP TRIGGER IF EXISTS analyses_fts_ai"))
    await conn.execute(text("DROP TRIGGER IF EXISTS analyses_fts_au"))
    await conn.execute(text("DROP TRIGGER IF EXISTS analyses_fts_ad"))

    # Recreate with content table — FTS5 manages sync automatically
    await conn.execute(text("""
        CREATE VIRTUAL TABLE IF NOT EXISTS analyses_fts USING fts5(
            id UNINDEXED,
            query,
            report_md,
            content='analyses',
            content_rowid='rowid'
        )
    """))
    # Rebuild to populate from existing data
    await conn.execute(text("""
        INSERT INTO analyses_fts(analyses_fts) VALUES('rebuild')
    """))


async def close_db() -> None:
    await engine.dispose()
