from __future__ import annotations

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.db.models import Analysis
from app.utils.time import now_iso

router = APIRouter(prefix="/export", tags=["export"])


class BatchExportRequest(BaseModel):
    ids: list[str]
    formats: list[str] = ["md", "stix", "iocs", "sigma"]


async def _get_analysis(analysis_id: str, db: AsyncSession):
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


async def _log_export(db: AsyncSession, analysis_id: str, format: str, filename: str):
    """Audit log for exports (PRD §14.4)."""
    from app.db.repositories.audit import log_event
    await log_event(db, "exported", {"analysis_id": analysis_id, "format": format, "filename": filename})


@router.get("/md/{analysis_id}")
async def export_markdown(analysis_id: str, db: AsyncSession = Depends(get_db)):
    analysis = await _get_analysis(analysis_id, db)
    from app.exporters.markdown import export_markdown as do_export
    content, filename = await do_export(analysis)
    await _log_export(db, analysis_id, "markdown", filename)
    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/pdf/{analysis_id}")
async def export_pdf(analysis_id: str, db: AsyncSession = Depends(get_db)):
    analysis = await _get_analysis(analysis_id, db)
    from app.exporters.pdf import export_pdf as do_export
    try:
        content, filename = await do_export(analysis)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF export failed: {e}") from e
    await _log_export(db, analysis_id, "pdf", filename)
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/stix/{analysis_id}")
async def export_stix(analysis_id: str, db: AsyncSession = Depends(get_db)):
    analysis = await _get_analysis(analysis_id, db)
    from app.exporters.stix import export_stix as do_export
    content, filename = await do_export(analysis)
    await _log_export(db, analysis_id, "stix", filename)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/iocs/{analysis_id}")
async def export_iocs(
    analysis_id: str,
    format: str = Query("csv"),
    defanged: bool = Query(True),
    min_confidence: str = Query("Medium"),
    db: AsyncSession = Depends(get_db),
):
    analysis = await _get_analysis(analysis_id, db)
    from app.exporters.ioc_csv import export_ioc_csv as do_export
    content, filename = await do_export(analysis, defanged=defanged, min_confidence=min_confidence)
    await _log_export(db, analysis_id, "iocs", filename)
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/sigma/{analysis_id}")
async def export_sigma(analysis_id: str, db: AsyncSession = Depends(get_db)):
    analysis = await _get_analysis(analysis_id, db)
    from app.exporters.sigma import export_sigma as do_export
    content, filename = await do_export(analysis)
    await _log_export(db, analysis_id, "sigma", filename)
    return Response(
        content=content,
        media_type="text/yaml; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/zip/{analysis_id}")
async def export_zip(analysis_id: str, db: AsyncSession = Depends(get_db)):
    analysis = await _get_analysis(analysis_id, db)
    from app.exporters.zip_bundle import export_zip as do_export
    content, filename = await do_export(analysis)
    await _log_export(db, analysis_id, "zip", filename)
    return Response(
        content=content,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/batch")
async def export_batch(req: BatchExportRequest, db: AsyncSession = Depends(get_db)):
    """Export multiple analyses into a single ZIP archive."""
    import io
    import zipfile

    allowed = {"md", "pdf", "stix", "iocs", "sigma", "zip"}
    formats = [fmt for fmt in req.formats if fmt in allowed]
    if not req.ids:
        raise HTTPException(status_code=422, detail="ids cannot be empty")
    if not formats:
        raise HTTPException(status_code=422, detail="formats cannot be empty")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for analysis_id in req.ids:
            analysis = await _get_analysis(analysis_id, db)
            for fmt in formats:
                if fmt == "md":
                    from app.exporters.markdown import export_markdown as do_export
                elif fmt == "pdf":
                    from app.exporters.pdf import export_pdf as do_export
                elif fmt == "stix":
                    from app.exporters.stix import export_stix as do_export
                elif fmt == "iocs":
                    from app.exporters.ioc_csv import export_ioc_csv as do_export
                elif fmt == "sigma":
                    from app.exporters.sigma import export_sigma as do_export
                else:
                    from app.exporters.zip_bundle import export_zip as do_export

                content, filename = await do_export(analysis)
                zf.writestr(f"{analysis_id}/{filename}", content)

    filename = f"ti-batch-export-{now_iso().replace(':', '').replace('-', '').replace('T', '-')[:13]}.zip"
    await _log_export(db, ",".join(req.ids), "batch", filename)
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
