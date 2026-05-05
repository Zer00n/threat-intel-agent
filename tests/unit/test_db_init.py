import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from app.db.models import Base


@pytest.mark.asyncio
async def test_create_tables():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Verify tables exist
    async with engine.connect() as conn:
        result = await conn.run_sync(
            lambda sync_conn: sync_conn.execute(
                __import__("sqlalchemy").text(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
            ).fetchall()
        )
        table_names = [row[0] for row in result]

    expected = [
        "analyses",
        "agent_logs",
        "attack_techniques",
        "audit_logs",
        "cve_refs",
        "data_source_cache",
        "findings",
        "iocs",
        "settings",
        "sources_health",
        "sources_used",
        "token_usage_monthly",
        "trusted_sources",
    ]
    for table in expected:
        assert table in table_names, f"Missing table: {table}"

    await engine.dispose()
