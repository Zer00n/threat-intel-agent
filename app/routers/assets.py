from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets.csv_import import import_csv_assets
from app.assets.json_import import import_json_assets
from app.assets.nmap_import import import_nmap_assets
from app.assets.matcher import identify_host_risks, identify_service_risks
from app.assets.repository import AssetRepository
from app.assets.space_analysis import analyze_asset_space
from app.db.models import AssetCVEMatch, AssetSpace, Host
from app.deps import get_db
from app.schemas.assets import (
    AssetBatchDeleteRequest,
    AssetManualCreate,
    AssetImportTextRequest,
    AssetSpaceCreate,
    AssetSpaceOut,
    AssetSpacePatch,
    CVEMatchStatusPatch,
    HostPatch,
)
from app.utils.time import now_iso

router = APIRouter(prefix="/api", tags=["assets"])


@router.get("/asset-spaces", response_model=list[AssetSpaceOut])
async def list_asset_spaces(db: AsyncSession = Depends(get_db)):
    repo = AssetRepository(db)
    spaces = await repo.list_spaces()
    result = []
    for space in spaces:
        summary = await repo.space_summary(space.id)
        result.append(_space_out(space, summary))
    return result


@router.post("/asset-spaces", response_model=AssetSpaceOut)
async def create_asset_space(req: AssetSpaceCreate, db: AsyncSession = Depends(get_db)):
    now = now_iso()
    space = AssetSpace(
        id=str(uuid.uuid4()),
        name=req.name,
        type="project",
        description=req.description,
        created_at=now,
        updated_at=now,
        expires_at=req.expires_at,
        auto_action_on_expire=req.auto_action_on_expire,
    )
    db.add(space)
    await db.commit()
    return _space_out(space, await AssetRepository(db).space_summary(space.id))


@router.get("/asset-spaces/{space_id}", response_model=AssetSpaceOut)
async def get_asset_space(space_id: str, db: AsyncSession = Depends(get_db)):
    space = await db.get(AssetSpace, space_id)
    if not space:
        raise HTTPException(status_code=404, detail="Asset space not found")
    return _space_out(space, await AssetRepository(db).space_summary(space.id))


@router.patch("/asset-spaces/{space_id}", response_model=AssetSpaceOut)
async def patch_asset_space(space_id: str, req: AssetSpacePatch, db: AsyncSession = Depends(get_db)):
    space = await db.get(AssetSpace, space_id)
    if not space:
        raise HTTPException(status_code=404, detail="Asset space not found")
    for key, value in req.model_dump(exclude_unset=True).items():
        setattr(space, key, value)
    space.updated_at = now_iso()
    await db.commit()
    return _space_out(space, await AssetRepository(db).space_summary(space.id))


@router.delete("/asset-spaces/{space_id}")
async def delete_asset_space(space_id: str, db: AsyncSession = Depends(get_db)):
    if space_id == "default":
        raise HTTPException(status_code=409, detail="Default asset space cannot be deleted")
    await db.execute(delete(AssetSpace).where(AssetSpace.id == space_id))
    await db.commit()
    return {"deleted": space_id}


@router.post("/asset-spaces/{space_id}/clear")
async def clear_asset_space(space_id: str, db: AsyncSession = Depends(get_db)):
    if not await db.get(AssetSpace, space_id):
        raise HTTPException(status_code=404, detail="Asset space not found")
    await db.execute(delete(Host).where(Host.space_id == space_id))
    await db.commit()
    return {"cleared": space_id}


@router.post("/asset-spaces/{space_id}/analyze")
async def analyze_space(space_id: str, db: AsyncSession = Depends(get_db)):
    try:
        return await analyze_asset_space(db, space_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Asset space not found")


@router.get("/assets")
async def list_assets(
    space_id: str = "default",
    search: str | None = None,
    environment: str | None = None,
    criticality: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    repo = AssetRepository(db)
    try:
        return await repo.list_hosts(
            space_id=space_id,
            search=search,
            environment=environment,
            criticality=criticality,
            limit=page_size,
            offset=(page - 1) * page_size,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Asset not found")


@router.post("/assets")
async def create_asset(req: AssetManualCreate, db: AsyncSession = Depends(get_db)):
    if not req.ip and not req.hostname:
        raise HTTPException(status_code=422, detail="IP or hostname is required")
    if req.protocol not in {"tcp", "udp"}:
        raise HTTPException(status_code=422, detail="Unsupported protocol")
    if req.environment not in {"prod", "test", "dev", "unknown"}:
        raise HTTPException(status_code=422, detail="Unsupported environment")
    if req.criticality not in {"high", "medium", "low"}:
        raise HTTPException(status_code=422, detail="Unsupported criticality")
    if req.exposure_scope not in {"public", "internal", "isolated", "unknown"}:
        raise HTTPException(status_code=422, detail="Unsupported exposure scope")
    if not await db.get(AssetSpace, req.space_id):
        raise HTTPException(status_code=404, detail="Asset space not found")

    await AssetRepository(db).upsert_asset_row(req.space_id, {
        "ip": _blank_to_none(req.ip),
        "hostname": _blank_to_none(req.hostname),
        "os_name": _blank_to_none(req.os_name),
        "os_version": _blank_to_none(req.os_version),
        "environment": req.environment,
        "criticality": req.criticality,
        "owner": _blank_to_none(req.owner),
        "tags": req.tags,
        "notes": _blank_to_none(req.notes),
        "product": req.product.strip(),
        "version": _blank_to_none(req.version),
        "vendor": _blank_to_none(req.vendor),
        "provided_cpe": _blank_to_none(req.cpe),
        "raw_banner": _blank_to_none(req.raw_banner),
        "port": req.port,
        "protocol": req.protocol,
        "exposure_scope": req.exposure_scope,
        "source": "manual",
        "detection_method": "manual",
    })
    await db.commit()

    host = await AssetRepository(db)._find_host(req.space_id, _blank_to_none(req.ip), _blank_to_none(req.hostname))
    if not host:
        raise HTTPException(status_code=500, detail="Asset was not created")
    return await AssetRepository(db).host_detail(host.id)


@router.get("/assets/{host_id}")
async def get_asset(host_id: str, db: AsyncSession = Depends(get_db)):
    try:
        return await AssetRepository(db).host_detail(host_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Asset not found")


@router.patch("/assets/{host_id}")
async def patch_asset(host_id: str, req: HostPatch, db: AsyncSession = Depends(get_db)):
    if not await db.get(Host, host_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    await AssetRepository(db).update_host(host_id, req.model_dump(exclude_unset=True))
    return await AssetRepository(db).host_detail(host_id)


@router.delete("/assets/{host_id}")
async def delete_asset(host_id: str, db: AsyncSession = Depends(get_db)):
    if not await db.get(Host, host_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    await AssetRepository(db).delete_host(host_id)
    return {"deleted": host_id}


@router.post("/assets/batch_delete")
async def batch_delete_assets(req: AssetBatchDeleteRequest, db: AsyncSession = Depends(get_db)):
    hosts = (await db.execute(select(Host).where(Host.id.in_(req.ids)))).scalars().all()
    found_ids = {host.id for host in hosts}
    missing = [host_id for host_id in req.ids if host_id not in found_ids]
    for host in hosts:
        await db.delete(host)
    await db.commit()
    return {"deleted": list(found_ids), "missing": missing}


@router.post("/assets/import/csv-text")
async def import_assets_csv_text(req: AssetImportTextRequest, db: AsyncSession = Depends(get_db)):
    if not await db.get(AssetSpace, req.space_id):
        raise HTTPException(status_code=404, detail="Asset space not found")
    if req.mode != "merge":
        raise HTTPException(status_code=422, detail="Only merge mode is supported in this build")
    summary = await import_csv_assets(db, req.space_id, req.content, req.filename)
    return {"job_id": str(uuid.uuid4()), "status": "completed", "summary": summary}


@router.post("/assets/import/json-text")
async def import_assets_json_text(req: AssetImportTextRequest, db: AsyncSession = Depends(get_db)):
    if not await db.get(AssetSpace, req.space_id):
        raise HTTPException(status_code=404, detail="Asset space not found")
    if req.mode != "merge":
        raise HTTPException(status_code=422, detail="Only merge mode is supported in this build")
    summary = await import_json_assets(db, req.space_id, req.content, req.filename)
    return {"job_id": str(uuid.uuid4()), "status": "completed", "summary": summary}


@router.post("/assets/import/nmap-text")
async def import_assets_nmap_text(req: AssetImportTextRequest, db: AsyncSession = Depends(get_db)):
    if not await db.get(AssetSpace, req.space_id):
        raise HTTPException(status_code=404, detail="Asset space not found")
    if req.mode != "merge":
        raise HTTPException(status_code=422, detail="Only merge mode is supported in this build")
    summary = await import_nmap_assets(db, req.space_id, req.content, req.filename)
    return {"job_id": str(uuid.uuid4()), "status": "completed", "summary": summary}


@router.get("/assets/import/template/csv")
async def csv_template():
    content = (
        "ip,hostname,os_name,os_version,environment,criticality,owner,tags,product,version,vendor,port,protocol,exposure_scope,notes\n"
        "192.168.1.100,web-prod-01,Ubuntu,22.04,prod,high,zhangsan,\"web,core\",nginx,1.18.0,nginx,80,tcp,public,\n"
    )
    return {"filename": "asset-import-template.csv", "content": content}


@router.post("/assets/{host_id}/services/{service_id}/identify")
async def identify_service(host_id: str, service_id: str, db: AsyncSession = Depends(get_db)):
    try:
        result = await identify_service_risks(db, service_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Service not found")
    if result["host"]["id"] != host_id:
        raise HTTPException(status_code=404, detail="Service not found for asset")
    return result


@router.post("/assets/{host_id}/identify")
async def identify_host(host_id: str, db: AsyncSession = Depends(get_db)):
    if not await db.get(Host, host_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    return await identify_host_risks(db, host_id)


@router.get("/assets/{host_id}/cve_matches")
async def asset_cve_matches(host_id: str, db: AsyncSession = Depends(get_db)):
    if not await db.get(Host, host_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    await identify_host_risks(db, host_id)
    return await AssetRepository(db).host_detail(host_id)


@router.patch("/asset-cve-matches/{match_id}")
async def patch_cve_match(match_id: str, req: CVEMatchStatusPatch, db: AsyncSession = Depends(get_db)):
    if req.status not in {"open", "acknowledged", "mitigated", "false_positive"}:
        raise HTTPException(status_code=422, detail="Unsupported match status")
    match = await db.get(AssetCVEMatch, match_id)
    if not match:
        raise HTTPException(status_code=404, detail="CVE match not found")
    await db.execute(
        update(AssetCVEMatch)
        .where(AssetCVEMatch.id == match_id)
        .values(status=req.status, user_notes=req.user_notes, last_updated_at=now_iso())
    )
    await db.commit()
    return {"id": match_id, "status": req.status}


def _space_out(space: AssetSpace, summary: dict) -> AssetSpaceOut:
    return AssetSpaceOut(
        id=space.id,
        name=space.name,
        type=space.type,
        description=space.description,
        expires_at=space.expires_at,
        is_archived=bool(space.is_archived),
        asset_count=summary["asset_count"],
        risk_summary=summary["risk_summary"],
    )


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None
