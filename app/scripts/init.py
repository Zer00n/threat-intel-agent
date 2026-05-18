from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

from app.agents.enrichment.base import make_proxied_client


async def download_attck_bundle(target: Path) -> None:
    if target.exists():
        print(f"ATT&CK bundle already exists at {target}")
        return

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    print(f"Downloading ATT&CK STIX bundle from {url} ...")

    target.parent.mkdir(parents=True, exist_ok=True)

    async with make_proxied_client(timeout=120) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        target.write_bytes(resp.content)

    print(f"Downloaded to {target} ({target.stat().st_size:,} bytes)")


async def main() -> None:
    from app.config import settings
    from app.db.engine import ensure_default_asset_space, ensure_demo_asset_cases, ensure_fts_schema, engine
    from app.db.models import Base

    # Ensure data directories exist
    settings.data_dir_path.mkdir(parents=True, exist_ok=True)
    (settings.data_dir_path / "attck").mkdir(parents=True, exist_ok=True)

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(__import__("sqlalchemy").text("PRAGMA journal_mode=WAL"))
        await conn.execute(__import__("sqlalchemy").text("PRAGMA foreign_keys=ON"))
    print("Database tables created.")

    # Download ATT&CK bundle
    await download_attck_bundle(settings.attck_bundle_file)

    # Download CJK font for PDF export
    from app.exporters.pdf import _ensure_font
    _ensure_font()
    print("CJK font ready.")

    async with engine.begin() as conn:
        await ensure_fts_schema(conn)
    print("FTS5 virtual table and triggers created.")

    await ensure_default_asset_space()
    print("Default asset space ready.")
    await ensure_demo_asset_cases()
    print("Demo asset cases ready.")

    print("Initialization complete.")


if __name__ == "__main__":
    asyncio.run(main())
