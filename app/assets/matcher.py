from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.enrichment.base import make_proxied_client
from app.config import settings
from app.assets.risk import compute_risk_score, match_confidence, risk_level
from app.db.models import AssetCVEMatch, AssetService, Exposure, Host, NvdCVECache, NvdCpeMatch
from app.utils.time import now_iso


async def identify_service_risks(db: AsyncSession, service_id: str) -> dict:
    service = await db.get(AssetService, service_id)
    if not service:
        raise KeyError(service_id)
    host = await db.get(Host, service.host_id)
    if not host:
        raise KeyError(service.host_id)

    exposures = (await db.execute(select(Exposure).where(Exposure.service_id == service_id))).scalars().all()
    if not service.cpe or service.cpe_confidence == "unknown":
        return _result(service, host, [], exposures)

    cpe_rows = (await db.execute(
        select(NvdCpeMatch).where(NvdCpeMatch.vulnerable == True, NvdCpeMatch.cpe == service.cpe)  # noqa: E712
    )).scalars().all()
    if not cpe_rows:
        await _sync_nvd_cves_for_cpe(db, service.cpe)
        cpe_rows = (await db.execute(
            select(NvdCpeMatch).where(NvdCpeMatch.vulnerable == True, NvdCpeMatch.cpe == service.cpe)  # noqa: E712
        )).scalars().all()
    if not cpe_rows:
        cpe_rows = (await db.execute(
            select(NvdCpeMatch).where(
                NvdCpeMatch.vulnerable == True,  # noqa: E712
                NvdCpeMatch.cpe.like(_product_cpe_like(service.cpe)),
            )
        )).scalars().all()

    matches = []
    now = now_iso()
    for cpe_match in cpe_rows:
        cve = await db.get(NvdCVECache, cpe_match.cve_id)
        if not cve:
            continue
        score = compute_risk_score(cve, host, list(exposures))
        confidence = match_confidence(service, cpe_match.cpe)
        existing = (await db.execute(
            select(AssetCVEMatch).where(
                AssetCVEMatch.service_id == service.id,
                AssetCVEMatch.cve_id == cve.cve_id,
            )
        )).scalar_one_or_none()
        if existing:
            existing.match_confidence = confidence
            existing.cvss_score = cve.cvss_v3_score
            existing.kev_flag = cve.is_in_kev
            existing.epss_score = cve.epss_score
            existing.risk_score = score
            existing.summary = cve.description
            existing.last_updated_at = now
            match = existing
        else:
            match = AssetCVEMatch(
                id=str(uuid.uuid4()),
                service_id=service.id,
                cve_id=cve.cve_id,
                match_confidence=confidence,
                cvss_score=cve.cvss_v3_score,
                kev_flag=cve.is_in_kev,
                epss_score=cve.epss_score,
                risk_score=score,
                summary=cve.description,
                status="open",
                discovered_at=now,
                last_updated_at=now,
            )
            db.add(match)
        matches.append(match)
    await db.commit()
    matches.sort(key=lambda item: item.risk_score or 0, reverse=True)
    return _result(service, host, matches, list(exposures))


async def identify_host_risks(db: AsyncSession, host_id: str) -> dict:
    services = (await db.execute(select(AssetService).where(AssetService.host_id == host_id))).scalars().all()
    results = []
    total = {"total": 0, "high": 0, "medium": 0, "low": 0}
    for service in services:
        item = await identify_service_risks(db, service.id)
        results.append(item)
        for key in total:
            total[key] += item["statistics"].get(key, 0)
    return {"host_id": host_id, "services": results, "statistics": total, "identified_at": now_iso()}


def _result(service: AssetService, host: Host, matches: list[AssetCVEMatch], exposures: list[Exposure]) -> dict:
    counts = {"total": len(matches), "high": 0, "medium": 0, "low": 0}
    match_items = []
    for match in matches:
        level = risk_level(match.risk_score)
        if level in counts:
            counts[level] += 1
        match_items.append({
            "id": match.id,
            "cve_id": match.cve_id,
            "cvss_score": match.cvss_score,
            "kev_flag": match.kev_flag,
            "epss_score": match.epss_score,
            "risk_score": match.risk_score,
            "risk_level": level,
            "match_confidence": match.match_confidence,
            "summary": match.summary,
            "status": match.status,
        })
    return {
        "service_id": service.id,
        "service": {
            "product": service.product,
            "version": service.version,
            "vendor": service.vendor,
            "cpe": service.cpe,
            "cpe_confidence": service.cpe_confidence,
            "exposures": [
                {"port": e.port, "protocol": e.protocol, "scope": e.exposure_scope}
                for e in exposures
            ],
        },
        "host": {
            "id": host.id,
            "ip": host.ip,
            "hostname": host.hostname,
            "criticality": host.criticality,
            "environment": host.environment,
        },
        "matches": match_items,
        "statistics": counts,
        "identified_at": now_iso(),
    }


def _product_cpe_like(cpe: str) -> str:
    parts = cpe.split(":")
    if len(parts) < 7:
        return cpe
    parts[6] = "%"
    return ":".join(parts)


async def _sync_nvd_cves_for_cpe(db: AsyncSession, cpe: str) -> None:
    """Populate the local CVE cache for a CPE on first use.

    This keeps the normal matching path local and deterministic while making a
    fresh install useful before a full background NVD sync exists.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        async with make_proxied_client(timeout=20) as client:
            resp = await client.get(url, params={"cpeName": cpe}, headers=headers)
            resp.raise_for_status()
            payload = resp.json()
    except Exception:
        return

    now = now_iso()
    for item in payload.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id")
        if not cve_id:
            continue
        existing = await db.get(NvdCVECache, cve_id)
        description = _nvd_description(cve_data)
        cvss_score, cvss_vector = _nvd_cvss(cve_data)
        if existing:
            existing.description = description
            existing.cvss_v3_score = cvss_score
            existing.cvss_v3_vector = cvss_vector
            existing.modified_at = cve_data.get("lastModified")
            existing.source_payload = None
            existing.updated_at = now
        else:
            db.add(NvdCVECache(
                cve_id=cve_id,
                description=description,
                cvss_v3_score=cvss_score,
                cvss_v3_vector=cvss_vector,
                is_in_kev=False,
                epss_score=None,
                published_at=cve_data.get("published"),
                modified_at=cve_data.get("lastModified"),
                source_payload=None,
                updated_at=now,
            ))
        exists_match = (await db.execute(
            select(NvdCpeMatch).where(NvdCpeMatch.cve_id == cve_id, NvdCpeMatch.cpe == cpe)
        )).scalar_one_or_none()
        if not exists_match:
            db.add(NvdCpeMatch(
                id=str(uuid.uuid4()),
                cve_id=cve_id,
                cpe=cpe,
                vulnerable=True,
            ))
    await db.commit()


def _nvd_description(cve_data: dict) -> str:
    descriptions = cve_data.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _nvd_cvss(cve_data: dict) -> tuple[float | None, str | None]:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        values = metrics.get(key) or []
        if values:
            data = values[0].get("cvssData", {})
            return data.get("baseScore"), data.get("vectorString")
    return None, None
