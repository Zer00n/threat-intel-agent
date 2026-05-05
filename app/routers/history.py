from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.db.models import AgentLog, Analysis, AttackTechnique, CVERef, Finding, IOC, SourceUsed
from app.schemas.history import HistoryItem, HistoryListResponse
from app.utils.time import now_iso

router = APIRouter(prefix="/history", tags=["history"])


@router.get("", response_model=HistoryListResponse)
async def list_history(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    intent: str | None = None,
    status: str | None = None,
    q: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Analysis)

    if intent:
        query = query.where(Analysis.intent == intent)
    if status:
        query = query.where(Analysis.status == status)

    # Count
    count_q = select(func.count()).select_from(Analysis)
    if intent:
        count_q = count_q.where(Analysis.intent == intent)
    if status:
        count_q = count_q.where(Analysis.status == status)

    if q:
        # Use FTS5 for full-text search
        try:
            fts_q = text("SELECT id FROM analyses_fts WHERE analyses_fts MATCH :q")
            result = await db.execute(fts_q, {"q": q})
            fts_ids = [row[0] for row in result.fetchall()]
            if fts_ids:
                query = query.where(Analysis.id.in_(fts_ids))
                count_q = count_q.where(Analysis.id.in_(fts_ids))
            else:
                # Fallback to LIKE search
                query = query.where(Analysis.query.contains(q))
                count_q = count_q.where(Analysis.query.contains(q))
        except Exception:
            query = query.where(Analysis.query.contains(q))
            count_q = count_q.where(Analysis.query.contains(q))

    total = (await db.execute(count_q)).scalar() or 0

    query = query.order_by(Analysis.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    analyses = result.scalars().all()

    items = [
        HistoryItem(
            id=a.id,
            query=a.query,
            intent=a.intent,
            status=a.status,
            tlp=a.tlp,
            overall_confidence=a.overall_confidence,
            token_input=a.token_input,
            token_output=a.token_output,
            cost_usd=a.cost_usd,
            duration_s=a.duration_s,
            created_at=a.created_at,
            updated_at=a.updated_at,
        )
        for a in analyses
    ]

    return HistoryListResponse(total=total, items=items)


@router.get("/{analysis_id}")
async def get_history_detail(analysis_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Get related data
    logs = (await db.execute(
        select(AgentLog).where(AgentLog.analysis_id == analysis_id).order_by(AgentLog.sequence)
    )).scalars().all()

    findings = (await db.execute(
        select(Finding).where(Finding.analysis_id == analysis_id)
    )).scalars().all()

    iocs = (await db.execute(
        select(IOC).where(IOC.analysis_id == analysis_id)
    )).scalars().all()

    cve_refs = (await db.execute(
        select(CVERef).where(CVERef.analysis_id == analysis_id)
    )).scalars().all()

    techniques = (await db.execute(
        select(AttackTechnique).where(AttackTechnique.analysis_id == analysis_id)
    )).scalars().all()

    sources = (await db.execute(
        select(SourceUsed).where(SourceUsed.analysis_id == analysis_id)
    )).scalars().all()

    return {
        "id": analysis.id,
        "query": analysis.query,
        "intent": analysis.intent,
        "intent_entities": json.loads(analysis.intent_entities) if analysis.intent_entities else None,
        "status": analysis.status,
        "report_md": analysis.report_md,
        "report_meta": json.loads(analysis.report_meta) if analysis.report_meta else None,
        "tlp": analysis.tlp,
        "overall_confidence": analysis.overall_confidence,
        "token_input": analysis.token_input,
        "token_output": analysis.token_output,
        "cost_usd": analysis.cost_usd,
        "duration_s": analysis.duration_s,
        "created_at": analysis.created_at,
        "updated_at": analysis.updated_at,
        "agent_logs": [
            {"sequence": l.sequence, "event_type": l.event_type, "agent_name": l.agent_name,
             "payload": json.loads(l.payload) if l.payload else None, "created_at": l.created_at}
            for l in logs
        ],
        "findings": [
            {"id": f.id, "claim": f.claim, "detail": f.detail, "source_type": f.source_type,
             "source_url": f.source_url, "source_name": f.source_name, "confidence": f.confidence}
            for f in findings
        ],
        "iocs": [
            {"id": i.id, "ioc_type": i.ioc_type, "value": i.value, "value_defanged": i.value_defanged,
             "context": i.context, "confidence": i.confidence, "is_extracted_by": i.is_extracted_by}
            for i in iocs
        ],
        "cve_refs": [
            {"cve_id": c.cve_id, "cvss_v3_score": c.cvss_v3_score, "is_in_kev": c.is_in_kev,
             "epss_score": c.epss_score, "description": c.description}
            for c in cve_refs
        ],
        "attack_techniques": [
            {"technique_id": t.technique_id, "technique_name": t.technique_name,
             "tactic": t.tactic, "confidence": t.confidence}
            for t in techniques
        ],
        "sources_used": [
            {"url": s.url, "domain": s.domain, "source_type": s.source_type, "is_trusted": s.is_trusted}
            for s in sources
        ],
    }


class BatchDeleteRequest(BaseModel):
    ids: list[str]


from pydantic import BaseModel as _BaseModel


class _BatchDeleteReq(_BaseModel):
    ids: list[str]


@router.delete("/{analysis_id}")
async def delete_history(analysis_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    if analysis.status == "running":
        raise HTTPException(status_code=409, detail="Cannot delete running analysis")

    await db.execute(delete(Analysis).where(Analysis.id == analysis_id))
    await db.commit()
    # Audit log (PRD §14.4)
    from app.db.repositories.audit import log_event
    await log_event(db, "analysis_deleted", {"analysis_id": analysis_id})
    return {"deleted": analysis_id}


@router.post("/batch_delete")
async def batch_delete(req: _BatchDeleteReq, db: AsyncSession = Depends(get_db)):
    deleted = []
    for aid in req.ids:
        result = await db.execute(select(Analysis).where(Analysis.id == aid))
        a = result.scalar_one_or_none()
        if a and a.status != "running":
            await db.execute(delete(Analysis).where(Analysis.id == aid))
            deleted.append(aid)
    await db.commit()
    return {"deleted": deleted}
