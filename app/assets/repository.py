from __future__ import annotations

import json
import uuid

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets.cpe_normalizer import normalize_cpe
from app.db.models import AssetCVEMatch, AssetService, AssetSpace, Exposure, Host
from app.utils.time import now_iso


class AssetRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_spaces(self) -> list[AssetSpace]:
        result = await self.db.execute(
            select(AssetSpace).where(AssetSpace.is_archived == False).order_by(AssetSpace.type, AssetSpace.created_at)  # noqa: E712
        )
        return list(result.scalars().all())

    async def space_summary(self, space_id: str) -> dict:
        hosts = await self.db.scalar(select(func.count()).select_from(Host).where(Host.space_id == space_id)) or 0
        services = await self.db.scalar(
            select(func.count())
            .select_from(AssetService)
            .join(Host, Host.id == AssetService.host_id)
            .where(Host.space_id == space_id)
        ) or 0
        risk_rows = (await self.db.execute(
            select(AssetCVEMatch.risk_score, AssetCVEMatch.status)
            .join(AssetService, AssetService.id == AssetCVEMatch.service_id)
            .join(Host, Host.id == AssetService.host_id)
            .where(Host.space_id == space_id)
        )).all()
        risk = {"high": 0, "medium": 0, "low": 0, "open": 0}
        for score, status in risk_rows:
            if status == "open":
                risk["open"] += 1
            if score is None:
                continue
            if score >= 12:
                risk["high"] += 1
            elif score >= 6:
                risk["medium"] += 1
            else:
                risk["low"] += 1
        return {"asset_count": {"hosts": hosts, "services": services}, "risk_summary": risk}

    async def list_hosts(
        self,
        space_id: str,
        search: str | None = None,
        environment: str | None = None,
        criticality: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        stmt = select(Host).where(Host.space_id == space_id)
        count_stmt = select(func.count()).select_from(Host).where(Host.space_id == space_id)
        if environment:
            stmt = stmt.where(Host.environment == environment)
            count_stmt = count_stmt.where(Host.environment == environment)
        if criticality:
            stmt = stmt.where(Host.criticality == criticality)
            count_stmt = count_stmt.where(Host.criticality == criticality)
        if search:
            pattern = f"%{search}%"
            ids = select(AssetService.host_id).where(AssetService.product.like(pattern))
            stmt = stmt.where(or_(Host.ip.like(pattern), Host.hostname.like(pattern), Host.id.in_(ids)))
            count_stmt = count_stmt.where(or_(Host.ip.like(pattern), Host.hostname.like(pattern), Host.id.in_(ids)))

        total = await self.db.scalar(count_stmt) or 0
        hosts = (await self.db.execute(stmt.order_by(Host.updated_at.desc()).offset(offset).limit(limit))).scalars().all()
        return {"total": total, "items": [await self.host_detail(h.id) for h in hosts]}

    async def host_detail(self, host_id: str) -> dict:
        host = await self.db.get(Host, host_id)
        if not host:
            raise KeyError(host_id)
        services = (await self.db.execute(
            select(AssetService).where(AssetService.host_id == host_id).order_by(AssetService.product)
        )).scalars().all()
        service_items = []
        for service in services:
            exposures = (await self.db.execute(
                select(Exposure).where(Exposure.service_id == service.id).order_by(Exposure.port)
            )).scalars().all()
            matches = (await self.db.execute(
                select(AssetCVEMatch).where(AssetCVEMatch.service_id == service.id).order_by(AssetCVEMatch.risk_score.desc())
            )).scalars().all()
            service_items.append({
                "id": service.id,
                "product": service.product,
                "version": service.version,
                "vendor": service.vendor,
                "cpe": service.cpe,
                "cpe_confidence": service.cpe_confidence,
                "service_type": service.service_type,
                "exposures": [
                    {"id": e.id, "port": e.port, "protocol": e.protocol, "exposure_scope": e.exposure_scope}
                    for e in exposures
                ],
                "cve_matches": [_match_out(m) for m in matches],
            })
        return {
            "id": host.id,
            "space_id": host.space_id,
            "ip": host.ip,
            "hostname": host.hostname,
            "os_name": host.os_name,
            "os_version": host.os_version,
            "criticality": host.criticality,
            "environment": host.environment,
            "owner": host.owner,
            "tags": json.loads(host.tags_json) if host.tags_json else [],
            "notes": host.notes,
            "source": host.source,
            "first_seen_at": host.first_seen_at,
            "last_seen_at": host.last_seen_at,
            "updated_at": host.updated_at,
            "services": service_items,
        }

    async def upsert_asset_row(self, space_id: str, row: dict) -> dict:
        now = now_iso()
        host = await self._find_host(space_id, row.get("ip"), row.get("hostname"))
        result = {
            "hosts_created": 0,
            "hosts_updated": 0,
            "services_created": 0,
            "services_updated": 0,
            "exposures_created": 0,
            "exposures_updated": 0,
            "cpe_confidence": "unknown",
        }
        if host:
            host.last_seen_at = now
            host.updated_at = now
            if not host.ip:
                host.ip = row.get("ip")
            if not host.hostname:
                host.hostname = row.get("hostname")
            if not host.os_name:
                host.os_name = row.get("os_name")
            if not host.os_version:
                host.os_version = row.get("os_version")
            result["hosts_updated"] = 1
        else:
            host = Host(
                id=str(uuid.uuid4()),
                space_id=space_id,
                ip=row.get("ip"),
                hostname=row.get("hostname"),
                os_name=row.get("os_name"),
                os_version=row.get("os_version"),
                criticality=_valid(row.get("criticality"), {"high", "medium", "low"}, "medium"),
                environment=_valid(row.get("environment"), {"prod", "test", "dev", "unknown"}, "unknown"),
                owner=row.get("owner"),
                tags_json=json.dumps(row.get("tags", []), ensure_ascii=False),
                notes=row.get("notes"),
                source=row.get("source", "manual"),
                source_meta_json=json.dumps({"filename": row.get("source_filename")}, ensure_ascii=False) if row.get("source_filename") else None,
                first_seen_at=now,
                last_seen_at=now,
                updated_at=now,
            )
            self.db.add(host)
            await self.db.flush()
            result["hosts_created"] = 1

        service = await self._find_service(host.id, row["product"], row.get("version"))
        if service:
            service.last_seen_at = now
            result["services_updated"] = 1
        else:
            norm = await normalize_cpe(
                self.db,
                product=row["product"],
                version=row.get("version"),
                vendor=row.get("vendor"),
                provided_cpe=row.get("provided_cpe"),
            )
            service = AssetService(
                id=str(uuid.uuid4()),
                host_id=host.id,
                product=row["product"],
                version=row.get("version"),
                vendor=row.get("vendor") or norm.vendor,
                cpe=norm.cpe,
                cpe_confidence=norm.confidence,
                service_type=_infer_service_type(row["product"]),
                detection_method=row.get("detection_method") or row.get("source", "manual"),
                raw_banner=row.get("raw_banner"),
                first_seen_at=now,
                last_seen_at=now,
            )
            self.db.add(service)
            await self.db.flush()
            result["services_created"] = 1
            result["cpe_confidence"] = norm.confidence

        exposure = await self._find_exposure(service.id, row["port"], row["protocol"])
        scope = _valid(row.get("exposure_scope"), {"public", "internal", "isolated", "unknown"}, "unknown")
        if exposure:
            exposure.exposure_scope = scope
            result["exposures_updated"] = 1
        else:
            self.db.add(Exposure(
                id=str(uuid.uuid4()),
                service_id=service.id,
                port=row["port"],
                protocol=row["protocol"],
                exposure_scope=scope,
                notes=row.get("notes"),
            ))
            result["exposures_created"] = 1
        return result

    async def update_host(self, host_id: str, values: dict) -> None:
        allowed = {"criticality", "environment", "owner", "notes"}
        updates = {k: v for k, v in values.items() if k in allowed and v is not None}
        if values.get("tags") is not None:
            updates["tags_json"] = json.dumps(values["tags"], ensure_ascii=False)
        updates["updated_at"] = now_iso()
        await self.db.execute(update(Host).where(Host.id == host_id).values(**updates))
        await self.db.commit()

    async def delete_host(self, host_id: str) -> None:
        await self.db.execute(delete(Host).where(Host.id == host_id))
        await self.db.commit()

    async def _find_host(self, space_id: str, ip: str | None, hostname: str | None) -> Host | None:
        stmt = select(Host).where(Host.space_id == space_id)
        if ip:
            stmt = stmt.where(Host.ip == ip)
        elif hostname:
            stmt = stmt.where(Host.hostname == hostname)
        else:
            return None
        return (await self.db.execute(stmt.limit(1))).scalar_one_or_none()

    async def _find_service(self, host_id: str, product: str, version: str | None) -> AssetService | None:
        stmt = select(AssetService).where(AssetService.host_id == host_id, AssetService.product == product)
        if version:
            stmt = stmt.where(AssetService.version == version)
        return (await self.db.execute(stmt.limit(1))).scalar_one_or_none()

    async def _find_exposure(self, service_id: str, port: int, protocol: str) -> Exposure | None:
        return (await self.db.execute(
            select(Exposure).where(Exposure.service_id == service_id, Exposure.port == port, Exposure.protocol == protocol).limit(1)
        )).scalar_one_or_none()


def _match_out(match: AssetCVEMatch) -> dict:
    score = match.risk_score or 0
    level = "high" if score >= 12 else "medium" if score >= 6 else "low"
    return {
        "id": match.id,
        "cve_id": match.cve_id,
        "match_confidence": match.match_confidence,
        "cvss_score": match.cvss_score,
        "kev_flag": match.kev_flag,
        "epss_score": match.epss_score,
        "risk_score": match.risk_score,
        "risk_level": level,
        "summary": match.summary,
        "status": match.status,
        "user_notes": match.user_notes,
        "last_updated_at": match.last_updated_at,
    }


def _valid(value: str | None, allowed: set[str], default: str) -> str:
    return value if value in allowed else default


def _infer_service_type(product: str) -> str:
    p = product.lower()
    if p in {"nginx", "apache", "httpd", "iis", "tomcat"}:
        return "web"
    if p in {"mysql", "postgresql", "postgres", "oracle", "mssql", "mongodb"}:
        return "database"
    if p in {"redis", "memcached"}:
        return "cache"
    if p in {"openssh", "ssh"}:
        return "middleware"
    return "other"
