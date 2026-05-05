from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx


async def download_attck_bundle(target: Path) -> None:
    if target.exists():
        print(f"ATT&CK bundle already exists at {target}")
        return

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    print(f"Downloading ATT&CK STIX bundle from {url} ...")

    target.parent.mkdir(parents=True, exist_ok=True)

    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        target.write_bytes(resp.content)

    print(f"Downloaded to {target} ({target.stat().st_size:,} bytes)")


async def main() -> None:
    from app.config import settings
    from app.db.engine import engine
    from app.db.models import Base

    # Ensure data directories exist
    settings.data_dir_path.mkdir(parents=True, exist_ok=True)
    (settings.data_dir_path / "attck").mkdir(parents=True, exist_ok=True)

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database tables created.")

    # Download ATT&CK bundle
    await download_attck_bundle(settings.attck_bundle_file)

    # Create FTS virtual table (raw SQL since it's virtual)
    async with engine.begin() as conn:
        await conn.execute(
            __import__("sqlalchemy").text(
                """CREATE VIRTUAL TABLE IF NOT EXISTS analyses_fts USING fts5(
                    id UNINDEXED,
                    query,
                    report_md,
                    content=''
                )"""
            )
        )
    print("FTS5 virtual table created.")

    print("Initialization complete.")


if __name__ == "__main__":
    asyncio.run(main())
