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
    await ensure_default_asset_space()
    await ensure_demo_asset_cases()


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

    await conn.execute(text("""
        CREATE VIRTUAL TABLE IF NOT EXISTS cpe_dictionary_fts USING fts5(
            cpe,
            vendor,
            product,
            version,
            title,
            content='cpe_dictionary',
            content_rowid='rowid'
        )
    """))


async def ensure_default_asset_space() -> None:
    """Create the always-present default asset space."""
    from app.db.models import AssetSpace
    from app.utils.time import now_iso

    async with async_session_factory() as db:
        existing = await db.get(AssetSpace, "default")
        if existing:
            return
        now = now_iso()
        db.add(AssetSpace(
            id="default",
            name="默认空间",
            type="default",
            description="长期保留的默认资产空间",
            created_at=now,
            updated_at=now,
        ))
        await db.commit()


async def ensure_demo_asset_cases() -> None:
    """Seed two reviewable asset cases for the default space."""
    import json

    from app.db.models import AssetCVEMatch, AssetService, Exposure, Host, NvdCVECache, NvdCpeMatch
    from app.utils.time import now_iso

    now = now_iso()
    cases = [
        {
            "host": {
                "id": "demo-asset-web-prod-01",
                "ip": "10.10.8.21",
                "hostname": "demo-web-prod-01",
                "os_name": "Ubuntu",
                "os_version": "20.04",
                "criticality": "high",
                "environment": "prod",
                "owner": "secops",
                "tags": ["demo", "web", "public"],
                "notes": "示例资产：公网 Web 入口，存在高危 Apache HTTP Server 漏洞命中。",
            },
            "service": {
                "id": "demo-service-apache-httpd-2449",
                "product": "apache",
                "version": "2.4.49",
                "vendor": "apache",
                "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                "service_type": "web",
                "detection_method": "demo_seed",
                "raw_banner": "Apache httpd 2.4.49",
            },
            "exposure": {"id": "demo-exposure-apache-443", "port": 443, "protocol": "tcp", "exposure_scope": "public"},
            "cve": {
                "id": "CVE-2021-41773",
                "description": "Apache HTTP Server 2.4.49 path traversal and file disclosure vulnerability; certain configurations may allow remote code execution.",
                "cvss": 7.5,
                "kev": True,
                "epss": 0.94,
            },
            "match": {"id": "demo-match-apache-cve-2021-41773", "risk_score": 14.2, "confidence": "high"},
        },
        {
            "host": {
                "id": "demo-asset-app-test-01",
                "ip": "10.20.4.15",
                "hostname": "demo-app-test-01",
                "os_name": "CentOS",
                "os_version": "7",
                "criticality": "medium",
                "environment": "test",
                "owner": "app-team",
                "tags": ["demo", "app", "internal"],
                "notes": "示例资产：测试环境应用节点，AJP 端口存在 Tomcat Ghostcat 风险命中。",
            },
            "service": {
                "id": "demo-service-tomcat-9030",
                "product": "tomcat",
                "version": "9.0.30",
                "vendor": "apache",
                "cpe": "cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*",
                "service_type": "web",
                "detection_method": "demo_seed",
                "raw_banner": "Apache Tomcat 9.0.30 AJP",
            },
            "exposure": {"id": "demo-exposure-tomcat-8009", "port": 8009, "protocol": "tcp", "exposure_scope": "internal"},
            "cve": {
                "id": "CVE-2020-1938",
                "description": "Apache Tomcat AJP connector file read and inclusion vulnerability known as Ghostcat.",
                "cvss": 9.8,
                "kev": False,
                "epss": 0.87,
            },
            "match": {"id": "demo-match-tomcat-cve-2020-1938", "risk_score": 10.9, "confidence": "high"},
        },
    ]

    async with async_session_factory() as db:
        for case in cases:
            host_data = case["host"]
            if not await db.get(Host, host_data["id"]):
                db.add(Host(
                    id=host_data["id"],
                    space_id="default",
                    ip=host_data["ip"],
                    hostname=host_data["hostname"],
                    os_name=host_data["os_name"],
                    os_version=host_data["os_version"],
                    criticality=host_data["criticality"],
                    environment=host_data["environment"],
                    owner=host_data["owner"],
                    tags_json=json.dumps(host_data["tags"], ensure_ascii=False),
                    notes=host_data["notes"],
                    source="demo",
                    source_meta_json=json.dumps({"case": "asset-threat-demo"}, ensure_ascii=False),
                    first_seen_at=now,
                    last_seen_at=now,
                    updated_at=now,
                ))

            service_data = case["service"]
            if not await db.get(AssetService, service_data["id"]):
                db.add(AssetService(
                    id=service_data["id"],
                    host_id=host_data["id"],
                    product=service_data["product"],
                    version=service_data["version"],
                    vendor=service_data["vendor"],
                    cpe=service_data["cpe"],
                    cpe_confidence="high",
                    service_type=service_data["service_type"],
                    detection_method=service_data["detection_method"],
                    raw_banner=service_data["raw_banner"],
                    first_seen_at=now,
                    last_seen_at=now,
                ))

            exposure_data = case["exposure"]
            if not await db.get(Exposure, exposure_data["id"]):
                db.add(Exposure(
                    id=exposure_data["id"],
                    service_id=service_data["id"],
                    port=exposure_data["port"],
                    protocol=exposure_data["protocol"],
                    exposure_scope=exposure_data["exposure_scope"],
                    notes="demo",
                ))

            cve_data = case["cve"]
            if not await db.get(NvdCVECache, cve_data["id"]):
                db.add(NvdCVECache(
                    cve_id=cve_data["id"],
                    description=cve_data["description"],
                    cvss_v3_score=cve_data["cvss"],
                    cvss_v3_vector=None,
                    is_in_kev=cve_data["kev"],
                    epss_score=cve_data["epss"],
                    published_at=None,
                    modified_at=None,
                    source_payload=None,
                    updated_at=now,
                ))

            cpe_match_id = f"demo-nvd-match-{cve_data['id'].lower()}"
            if not await db.get(NvdCpeMatch, cpe_match_id):
                db.add(NvdCpeMatch(
                    id=cpe_match_id,
                    cve_id=cve_data["id"],
                    cpe=service_data["cpe"],
                    vulnerable=True,
                ))

            match_data = case["match"]
            if not await db.get(AssetCVEMatch, match_data["id"]):
                db.add(AssetCVEMatch(
                    id=match_data["id"],
                    service_id=service_data["id"],
                    cve_id=cve_data["id"],
                    match_confidence=match_data["confidence"],
                    cvss_score=cve_data["cvss"],
                    kev_flag=cve_data["kev"],
                    epss_score=cve_data["epss"],
                    risk_score=match_data["risk_score"],
                    summary=cve_data["description"],
                    status="open",
                    discovered_at=now,
                    last_updated_at=now,
                ))
        await db.commit()


async def close_db() -> None:
    await engine.dispose()
