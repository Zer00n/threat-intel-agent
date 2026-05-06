from __future__ import annotations

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.db.models import AgentLog, Analysis, AttackTechnique, CVERef, Finding, IOC, SourceUsed
from app.schemas.history import HistoryItem, HistoryListResponse
from app.utils.attck_loader import get_technique, validate_technique_id
from app.utils.defang import defang
from app.utils.ioc_regex import extract_all_iocs
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

    display_iocs = _display_iocs(iocs, analysis.report_md or "")
    display_techniques = _display_techniques(techniques, analysis.report_md or "")

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
            for i in display_iocs
        ],
        "cve_refs": [
            {"cve_id": c.cve_id, "cvss_v3_score": c.cvss_v3_score, "is_in_kev": c.is_in_kev,
             "epss_score": c.epss_score, "description": c.description}
            for c in cve_refs
        ],
        "attack_techniques": [
            {"technique_id": t.technique_id, "technique_name": t.technique_name,
             "tactic": t.tactic, "confidence": t.confidence}
            for t in display_techniques
        ],
        "sources_used": [
            {"url": s.url, "domain": s.domain, "source_type": s.source_type, "is_trusted": s.is_trusted}
            for s in sources
        ],
    }


class _DisplayIOC:
    def __init__(self, ioc_type: str, value: str, context: str):
        self.id = ""
        self.ioc_type = ioc_type
        self.value = value
        self.value_defanged = defang(value, ioc_type)
        self.context = context
        self.confidence = "Medium"
        self.is_extracted_by = "regex"


class _DisplayTechnique:
    def __init__(self, technique_id: str, technique_name: str, tactic: str):
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.tactic = tactic
        self.confidence = "Medium"


def _display_iocs(rows: list[IOC], report_md: str):
    if rows or not report_md:
        return rows
    return [
        _DisplayIOC(item["type"], item["value"], _find_context(report_md, item["value"]))
        for item in extract_all_iocs(report_md)
    ]


def _display_techniques(rows: list[AttackTechnique], report_md: str):
    if rows or not report_md:
        return rows
    result = []
    for technique_id in sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", report_md))):
        if not validate_technique_id(technique_id):
            continue
        technique = get_technique(technique_id) or {}
        tactics = technique.get("kill_chain_phases", [])
        tactic = ""
        if tactics:
            first = tactics[0]
            tactic = first.get("phase_name", "") if isinstance(first, dict) else str(first)
        result.append(_DisplayTechnique(technique_id, technique.get("name", technique_id), tactic))
    return result


def _find_context(text: str, value: str) -> str:
    idx = text.lower().find(value.lower())
    if idx == -1:
        return ""
    start = max(0, idx - 80)
    end = min(len(text), idx + len(value) + 80)
    return text[start:end].strip()


@router.get("/{analysis_id}/diff/{compare_id}")
async def diff_history(analysis_id: str, compare_id: str, db: AsyncSession = Depends(get_db)):
    """Compare two analysis records for incremental refresh review."""
    left = (await db.execute(select(Analysis).where(Analysis.id == analysis_id))).scalar_one_or_none()
    right = (await db.execute(select(Analysis).where(Analysis.id == compare_id))).scalar_one_or_none()
    if not left or not right:
        raise HTTPException(status_code=404, detail="Analysis not found")

    left_cves = (await db.execute(select(CVERef).where(CVERef.analysis_id == analysis_id))).scalars().all()
    right_cves = (await db.execute(select(CVERef).where(CVERef.analysis_id == compare_id))).scalars().all()
    left_iocs = (await db.execute(select(IOC).where(IOC.analysis_id == analysis_id))).scalars().all()
    right_iocs = (await db.execute(select(IOC).where(IOC.analysis_id == compare_id))).scalars().all()
    left_tech = (await db.execute(select(AttackTechnique).where(AttackTechnique.analysis_id == analysis_id))).scalars().all()
    right_tech = (await db.execute(select(AttackTechnique).where(AttackTechnique.analysis_id == compare_id))).scalars().all()

    return {
        "base_id": analysis_id,
        "compare_id": compare_id,
        "status_changed": left.status != right.status,
        "cost_delta_usd": round((right.cost_usd or 0) - (left.cost_usd or 0), 6),
        "cve_changes": _diff_cves(left_cves, right_cves),
        "ioc_changes": _diff_sets(
            {(i.ioc_type, i.value) for i in left_iocs},
            {(i.ioc_type, i.value) for i in right_iocs},
        ),
        "attack_technique_changes": _diff_sets(
            {t.technique_id for t in left_tech},
            {t.technique_id for t in right_tech},
        ),
        "report_changed": (left.report_md or "") != (right.report_md or ""),
    }


def _diff_sets(left: set, right: set) -> dict:
    return {
        "added": sorted(list(right - left)),
        "removed": sorted(list(left - right)),
        "unchanged_count": len(left & right),
    }


def _diff_cves(left: list[CVERef], right: list[CVERef]) -> list[dict]:
    left_map = {c.cve_id: c for c in left}
    right_map = {c.cve_id: c for c in right}
    changes = []
    for cve_id in sorted(set(left_map) | set(right_map)):
        before = left_map.get(cve_id)
        after = right_map.get(cve_id)
        if before is None:
            changes.append({"cve_id": cve_id, "change": "added"})
            continue
        if after is None:
            changes.append({"cve_id": cve_id, "change": "removed"})
            continue
        fields = {}
        for field in ("cvss_v3_score", "is_in_kev", "kev_added_date", "epss_score", "epss_percentile"):
            old_value = getattr(before, field)
            new_value = getattr(after, field)
            if old_value != new_value:
                fields[field] = {"before": old_value, "after": new_value}
        if fields:
            changes.append({"cve_id": cve_id, "change": "modified", "fields": fields})
    return changes


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


@router.get("/{analysis_id}/diff/{compare_id}")
async def diff_analyses(analysis_id: str, compare_id: str, db: AsyncSession = Depends(get_db)):
    """Compare two analyses and return field-level differences."""
    result_a = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    a = result_a.scalar_one_or_none()
    result_b = await db.execute(select(Analysis).where(Analysis.id == compare_id))
    b = result_b.scalar_one_or_none()

    if not a or not b:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Compare key fields
    diffs = []

    # Status
    if a.status != b.status:
        diffs.append({"field": "状态", "old": a.status, "new": b.status})

    # Confidence
    if a.overall_confidence != b.overall_confidence:
        diffs.append({"field": "置信度", "old": a.overall_confidence, "new": b.overall_confidence})

    # CVE refs - compare KEV and EPSS
    cves_a = (await db.execute(
        select(CVERef).where(CVERef.analysis_id == analysis_id)
    )).scalars().all()
    cves_b = (await db.execute(
        select(CVERef).where(CVERef.analysis_id == compare_id)
    )).scalars().all()

    cve_map_a = {c.cve_id: c for c in cves_a}
    cve_map_b = {c.cve_id: c for c in cves_b}

    for cve_id in set(cve_map_a.keys()) | set(cve_map_b.keys()):
        ca = cve_map_a.get(cve_id)
        cb = cve_map_b.get(cve_id)
        if ca and cb:
            if ca.is_in_kev != cb.is_in_kev:
                diffs.append({"field": f"{cve_id} KEV 状态", "old": "已收录" if ca.is_in_kev else "未收录", "new": "已收录" if cb.is_in_kev else "未收录"})
            if ca.cvss_v3_score != cb.cvss_v3_score:
                diffs.append({"field": f"{cve_id} CVSS", "old": str(ca.cvss_v3_score), "new": str(cb.cvss_v3_score)})
            if ca.epss_score != cb.epss_score:
                diffs.append({"field": f"{cve_id} EPSS", "old": str(ca.epss_score), "new": str(cb.epss_score)})
        elif ca and not cb:
            diffs.append({"field": f"{cve_id}", "old": "存在", "new": "不存在"})
        elif cb and not ca:
            diffs.append({"field": f"{cve_id}", "old": "不存在", "new": "存在"})

    # IOC count
    iocs_a = (await db.execute(
        select(func.count()).select_from(IOC).where(IOC.analysis_id == analysis_id)
    )).scalar() or 0
    iocs_b = (await db.execute(
        select(func.count()).select_from(IOC).where(IOC.analysis_id == compare_id)
    )).scalar() or 0
    if iocs_a != iocs_b:
        diffs.append({"field": "IOC 数量", "old": str(iocs_a), "new": str(iocs_b)})

    # ATT&CK count
    tech_a = (await db.execute(
        select(func.count()).select_from(AttackTechnique).where(AttackTechnique.analysis_id == analysis_id)
    )).scalar() or 0
    tech_b = (await db.execute(
        select(func.count()).select_from(AttackTechnique).where(AttackTechnique.analysis_id == compare_id)
    )).scalar() or 0
    if tech_a != tech_b:
        diffs.append({"field": "ATT&CK 技术数", "old": str(tech_a), "new": str(tech_b)})

    # Token usage
    if a.token_input != b.token_input or a.token_output != b.token_output:
        diffs.append({
            "field": "令牌消耗",
            "old": f"{a.token_input}入/{a.token_output}出",
            "new": f"{b.token_input}入/{b.token_output}出",
        })

    # Cost
    if a.cost_usd != b.cost_usd:
        diffs.append({"field": "费用", "old": f"${a.cost_usd:.4f}", "new": f"${b.cost_usd:.4f}"})

    # Duration
    if a.duration_s != b.duration_s:
        diffs.append({"field": "耗时", "old": f"{a.duration_s}秒", "new": f"{b.duration_s}秒"})

    return {
        "analysis_a": {"id": a.id, "query": a.query, "created_at": a.created_at},
        "analysis_b": {"id": b.id, "query": b.query, "created_at": b.created_at},
        "diffs": diffs,
        "diff_count": len(diffs),
    }
