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
    """Create FTS5 search table and sync triggers used by the history API."""
    await conn.execute(text("""
        CREATE VIRTUAL TABLE IF NOT EXISTS analyses_fts USING fts5(
            id UNINDEXED,
            query,
            report_md,
            content=''
        )
    """))
    await conn.execute(text("""
        CREATE TRIGGER IF NOT EXISTS analyses_fts_ai AFTER INSERT ON analyses BEGIN
            INSERT INTO analyses_fts(rowid, id, query, report_md)
            VALUES (new.rowid, new.id, new.query, COALESCE(new.report_md, ''));
        END
    """))
    await conn.execute(text("""
        CREATE TRIGGER IF NOT EXISTS analyses_fts_au AFTER UPDATE OF query, report_md ON analyses BEGIN
            DELETE FROM analyses_fts WHERE rowid = old.rowid;
            INSERT INTO analyses_fts(rowid, id, query, report_md)
            VALUES (new.rowid, new.id, new.query, COALESCE(new.report_md, ''));
        END
    """))
    await conn.execute(text("""
        CREATE TRIGGER IF NOT EXISTS analyses_fts_ad AFTER DELETE ON analyses BEGIN
            DELETE FROM analyses_fts WHERE rowid = old.rowid;
        END
    """))
    await conn.execute(text("""
        INSERT INTO analyses_fts(rowid, id, query, report_md)
        SELECT rowid, id, query, COALESCE(report_md, '')
        FROM analyses
        WHERE rowid NOT IN (SELECT rowid FROM analyses_fts)
    """))


async def close_db() -> None:
    await engine.dispose()
