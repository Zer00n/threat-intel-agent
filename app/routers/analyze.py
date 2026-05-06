from __future__ import annotations

import asyncio
import re
import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.llm_client import LLMClient
from app.agents.orchestrator import run_analysis
from app.config import settings
from app.deps import get_db
from app.db.models import AgentLog, Analysis
from app.schemas.analyze import AnalyzeRequest, AnalyzeResponse, StopResponse, SwitchIntentRequest
from app.task_manager import task_manager
from app.utils.time import now_iso

logger = structlog.get_logger()

router = APIRouter(tags=["analyze"])

# Injection detection patterns
_INJECTION_PATTERNS = re.compile(
    r"ignore\s+(previous|all)\s+instructions|system\s*prompt|忽略指令|ignore\s+instructions",
    re.IGNORECASE,
)
_ALLOWED_INTENTS = {
    "cve",
    "attack_technique",
    "threat_actor",
    "malware",
    "ioc_hash",
    "ioc_ip",
    "ioc_domain",
    "generic",
    "vulnerability_generic",
    "incident_description",
}


@router.post("/analyze", response_model=AnalyzeResponse)
async def start_analysis(req: AnalyzeRequest, db: AsyncSession = Depends(get_db)):
    # Check concurrent task
    if task_manager.has_active_task():
        raise HTTPException(status_code=409, detail="Another analysis is already running")

    # Check monthly budget (PRD §FR-41: return 402 when exceeded)
    from app.db.repositories.settings import get_setting
    from sqlalchemy import select, func
    from app.db.models import TokenUsageMonthly
    from datetime import datetime, timezone

    monthly_budget = float(await get_setting(db, "monthly_budget_usd") or settings.monthly_budget_usd)
    current_month = datetime.now(timezone.utc).strftime("%Y-%m")
    result = await db.execute(
        select(TokenUsageMonthly).where(TokenUsageMonthly.year_month == current_month)
    )
    monthly_usage = result.scalar_one_or_none()
    if monthly_usage and monthly_usage.total_cost_usd >= monthly_budget:
        raise HTTPException(
            status_code=402,
            detail=f"Monthly budget exceeded: ${monthly_usage.total_cost_usd:.2f} / ${monthly_budget:.2f}"
        )

    # Sanitize query
    query = _sanitize_query(req.query)

    # Detect injection
    injection_detected = bool(_INJECTION_PATTERNS.search(query))
    if injection_detected:
        logger.warning("injection_detected", query=query[:100])

    task_id = str(uuid.uuid4())
    now = now_iso()

    analysis = Analysis(
        id=task_id,
        query=query,
        intent=None,
        status="running",
        tlp=req.tlp,
        created_at=now,
        updated_at=now,
    )
    db.add(analysis)
    await db.commit()

    # Create SSE queue for this task
    from app.routers.stream import create_task_queue
    create_task_queue(task_id)

    # Start background analysis
    llm = LLMClient()
    _collected_events: list[dict] = []  # collect events for AgentLog persistence

    async def emit_fn(event_type: str, data: dict):
        from app.routers.stream import push_event
        await push_event(task_id, event_type, data)
        _collected_events.append({"event_type": event_type, "data": data})
        await persist_agent_event(task_id, len(_collected_events), event_type, data)

    task = asyncio.create_task(
        _run_analysis_wrapper(task_id, query, llm, emit_fn, req.tlp, req.force_intent, db, _collected_events),
        name=f"analysis-{task_id}",
    )
    task_manager.register(task_id, task)

    # Audit log (PRD §14.4)
    from app.db.repositories.audit import log_event
    await log_event(db, "analysis_started", {"task_id": task_id, "query": query[:100]})
    if injection_detected:
        await log_event(db, "injection_detected", {"task_id": task_id, "query": query[:100]})

    return AnalyzeResponse(task_id=task_id, status="running")


@router.post("/analyze/{task_id}/stop", response_model=StopResponse)
async def stop_analysis(task_id: str, db: AsyncSession = Depends(get_db)):
    if not task_manager.is_running(task_id):
        result = await db.execute(select(Analysis).where(Analysis.id == task_id))
        analysis = result.scalar_one_or_none()
        if not analysis:
            raise HTTPException(status_code=404, detail="Task not found")
        raise HTTPException(status_code=400, detail="Task is not running")

    cancelled = await task_manager.cancel(task_id)
    if cancelled:
        now = now_iso()
        from sqlalchemy import update
        await db.execute(
            update(Analysis).where(Analysis.id == task_id).values(status="stopped", updated_at=now)
        )
        await db.commit()
        # Audit log (PRD §14.4)
        from app.db.repositories.audit import log_event
        await log_event(db, "analysis_stopped", {"task_id": task_id})

    return StopResponse(task_id=task_id, status="stopped")


@router.post("/analyze/{task_id}/switch_intent")
async def switch_intent(task_id: str, req: SwitchIntentRequest):
    if req.intent not in _ALLOWED_INTENTS:
        raise HTTPException(status_code=422, detail=f"Unsupported intent: {req.intent}")
    if not task_manager.is_running(task_id):
        raise HTTPException(status_code=409, detail="Task not in decision window")
    if not task_manager.set_intent_override(task_id, req.intent):
        raise HTTPException(status_code=409, detail="Intent decision window is closed")
    return {"task_id": task_id, "intent": req.intent}


@router.post("/analyze/{task_id}/refresh", response_model=AnalyzeResponse)
async def refresh_analysis(task_id: str, db: AsyncSession = Depends(get_db)):
    """Create a new analysis based on existing one (PRD §FR-35)."""
    # Check concurrent task
    if task_manager.has_active_task():
        raise HTTPException(status_code=409, detail="Another analysis is already running")

    # Get original analysis
    result = await db.execute(select(Analysis).where(Analysis.id == task_id))
    original = result.scalar_one_or_none()
    if not original:
        raise HTTPException(status_code=404, detail="Original analysis not found")

    # Create new analysis with parent_id
    new_task_id = str(uuid.uuid4())
    now = now_iso()

    # Build refresh query: include old report for diff context
    refresh_query = f"{original.query}"

    analysis = Analysis(
        id=new_task_id,
        parent_id=task_id,
        query=refresh_query,
        intent=original.intent,
        status="running",
        tlp=original.tlp,
        created_at=now,
        updated_at=now,
    )
    db.add(analysis)
    await db.commit()

    # Create SSE queue
    from app.routers.stream import create_task_queue
    create_task_queue(new_task_id)

    # Start background analysis with old report context
    llm = LLMClient()
    _collected_events: list[dict] = []

    async def emit_fn(event_type: str, data: dict):
        from app.routers.stream import push_event
        await push_event(new_task_id, event_type, data)
        _collected_events.append({"event_type": event_type, "data": data})
        await persist_agent_event(new_task_id, len(_collected_events), event_type, data)

    task = asyncio.create_task(
        _run_analysis_wrapper(new_task_id, refresh_query, llm, emit_fn, original.tlp, None, db, _collected_events),
        name=f"analysis-{new_task_id}",
    )
    task_manager.register(new_task_id, task)

    # Audit log (PRD §14.4)
    from app.db.repositories.audit import log_event
    await log_event(db, "analysis_refreshed", {"original_id": task_id, "new_id": new_task_id})

    return AnalyzeResponse(task_id=new_task_id, status="running", intent_preview=original.intent)


async def _run_analysis_wrapper(
    task_id: str,
    query: str,
    llm: LLMClient,
    emit_fn,
    tlp: str,
    force_intent: str | None,
    db: AsyncSession,
    collected_events: list[dict] | None = None,
):
    try:
        try:
            from app.workers.health_check import check_all_sources
            await asyncio.wait_for(check_all_sources(), timeout=20)
        except Exception as e:
            logger.warning("pre_analysis_health_check_failed", task_id=task_id, error=str(e))

        result = await run_analysis(
            task_id=task_id,
            query=query,
            llm=llm,
            emit=emit_fn,
            tlp=tlp,
            force_intent=force_intent,
            db=db,
            agent_logs=None,
        )

        # Update final status (persistence module handles detailed data)
        from sqlalchemy import update
        now = now_iso()
        await db.execute(
            update(Analysis).where(Analysis.id == task_id).values(
                status=result.get("status", "completed"),
                updated_at=now,
            )
        )
        await db.commit()
    except Exception as e:
        logger.exception("analysis_wrapper_error", task_id=task_id)
        from sqlalchemy import update
        await db.execute(
            update(Analysis).where(Analysis.id == task_id).values(
                status="failed",
                error_message=str(e),
                updated_at=now_iso(),
            )
        )
        await db.commit()
    finally:
        task_manager.unregister(task_id)


def _sanitize_query(query: str) -> str:
    # Strip control characters except \n\r\t
    query = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", query)
    # Strip zero-width characters
    query = re.sub(r"[​-‍﻿]", "", query)
    return query.strip()


async def persist_agent_event(task_id: str, sequence: int, event_type: str, data: dict) -> None:
    """Persist event stream immediately so interrupted tasks retain their timeline."""
    import json
    from app.db.engine import async_session_factory

    async with async_session_factory() as event_db:
        event_db.add(AgentLog(
            analysis_id=task_id,
            sequence=sequence,
            event_type=event_type,
            agent_name=_extract_agent_name(event_type, data),
            payload=json.dumps(data, ensure_ascii=False) if data else None,
            created_at=now_iso(),
        ))
        await event_db.commit()


def _extract_agent_name(event_type: str, data: dict) -> str | None:
    agent_id = data.get("agent_id") or data.get("agent_name")
    if agent_id:
        return str(agent_id)
    return {
        "intent_classified": "IntentClassifier",
        "intent_switched": "IntentClassifier",
        "plan_result": "PlannerAgent",
        "data_source_query": "EnrichmentAgent",
        "data_source_hit": "EnrichmentAgent",
        "data_source_miss": "EnrichmentAgent",
        "data_source_error": "EnrichmentAgent",
        "enrichment_done": "EnrichmentAgent",
        "ioc_extracted": "IOCExtractorAgent",
        "critic_done": "CriticAgent",
        "synthesizing": "SynthesisAgent",
        "report_chunk": "SynthesisAgent",
        "done": "Orchestrator",
        "error": "Orchestrator",
        "stopped": "Orchestrator",
        "timeout": "Orchestrator",
        "budget_exceeded": "Orchestrator",
    }.get(event_type)
