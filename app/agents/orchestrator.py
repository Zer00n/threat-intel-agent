from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog

from app.agents.base import EmitFn
from app.agents.intent_classifier import IntentClassifier
from app.agents.planner import PlannerAgent
from app.agents.enrichment_agent import EnrichmentAgent
from app.agents.researcher import ResearchAgent
from app.agents.ioc_extractor import IOCExtractorAgent
from app.agents.critic import CriticAgent
from app.agents.synthesis import SynthesisAgent
from app.agents.llm_client import BudgetExceededError, LLMClient
from app.agents.memory import Memory
from app.config import settings
from app.utils.time import now_iso

logger = structlog.get_logger()


async def run_analysis(
    task_id: str,
    query: str,
    llm: LLMClient,
    emit: EmitFn,
    tlp: str = "GREEN",
    force_intent: str | None = None,
    db=None,
) -> dict[str, Any]:
    memory = Memory()
    memory.extra["query"] = query
    memory.extra["task_id"] = task_id
    memory.extra["tlp"] = tlp

    start_time = __import__("time").monotonic()

    try:
        # Wrap entire analysis in global timeout (PRD §FR-13: 8 minutes)
        result = await asyncio.wait_for(
            _run_pipeline(task_id, memory, llm, emit, force_intent),
            timeout=settings.analysis_timeout_s,
        )

        duration = __import__("time").monotonic() - start_time

        await emit("done", {
            "analysis_id": task_id,
            "duration_s": round(duration, 1),
            "token_usage": {
                "input": llm.total_usage.input_tokens,
                "output": llm.total_usage.output_tokens,
            },
            "cost_usd": round(llm.total_usage.cost_usd, 4),
        })

        # Persist results to database
        if db:
            try:
                from app.agents.persistence import persist_analysis_results
                await persist_analysis_results(
                    db=db,
                    task_id=task_id,
                    memory=memory,
                    token_input=llm.total_usage.input_tokens,
                    token_output=llm.total_usage.output_tokens,
                    cost_usd=llm.total_usage.cost_usd,
                    duration_s=duration,
                )
            except Exception as e:
                logger.warning("persist_failed", task_id=task_id, error=str(e))

        return {
            "task_id": task_id,
            "status": "completed",
            "report_md": memory.report_md,
            "memory": memory,
            "duration_s": round(duration, 1),
            "token_input": llm.total_usage.input_tokens,
            "token_output": llm.total_usage.output_tokens,
            "cost_usd": llm.total_usage.cost_usd,
        }

    except asyncio.TimeoutError:
        duration = __import__("time").monotonic() - start_time
        logger.warning("analysis_timeout", task_id=task_id, duration=duration)
        await emit("timeout", {"message": f"Analysis timed out after {settings.analysis_timeout_s}s"})

        # Persist partial results
        if db:
            try:
                from app.agents.persistence import persist_analysis_results
                await persist_analysis_results(
                    db=db, task_id=task_id, memory=memory,
                    token_input=llm.total_usage.input_tokens,
                    token_output=llm.total_usage.output_tokens,
                    cost_usd=llm.total_usage.cost_usd,
                    duration_s=duration,
                )
            except Exception:
                pass

        return {"task_id": task_id, "status": "timeout", "memory": memory}

    except asyncio.CancelledError:
        await emit("stopped", {"partial_completed": True})

        # Persist partial results
        if db:
            try:
                from app.agents.persistence import persist_analysis_results
                await persist_analysis_results(
                    db=db, task_id=task_id, memory=memory,
                    token_input=llm.total_usage.input_tokens,
                    token_output=llm.total_usage.output_tokens,
                    cost_usd=llm.total_usage.cost_usd,
                )
            except Exception:
                pass

        return {"task_id": task_id, "status": "stopped", "memory": memory}

    except BudgetExceededError as e:
        logger.warning("budget_exceeded", task_id=task_id, error=str(e))
        await emit("budget_exceeded", {
            "reason": str(e),
            "used_token": llm.total_usage.input_tokens + llm.total_usage.output_tokens,
            "limit_token": settings.single_task_token_limit,
        })

        # Persist partial results
        if db:
            try:
                from app.agents.persistence import persist_analysis_results
                await persist_analysis_results(
                    db=db, task_id=task_id, memory=memory,
                    token_input=llm.total_usage.input_tokens,
                    token_output=llm.total_usage.output_tokens,
                    cost_usd=llm.total_usage.cost_usd,
                )
            except Exception:
                pass

        return {"task_id": task_id, "status": "budget_exceeded", "memory": memory}

    except Exception as e:
        logger.exception("analysis_failed", task_id=task_id)
        await emit("error", {"message": str(e), "error_code": "ANALYSIS_FAILED"})
        return {"task_id": task_id, "status": "failed", "error": str(e)}


async def _run_pipeline(
    task_id: str,
    memory: Memory,
    llm: LLMClient,
    emit: EmitFn,
    force_intent: str | None,
) -> None:
    """Execute the 7-agent pipeline with per-step timeouts."""

    # 1. Intent Classification
    classifier = IntentClassifier(llm=llm, emit=emit)
    await classifier.run(memory)
    if force_intent:
        memory.intent.intent = force_intent

    # 2. Planning
    planner = PlannerAgent(llm=llm, emit=emit)
    await planner.run(memory)

    # 3. Enrichment (parallel data source calls, per-source timeout 15s)
    enricher = EnrichmentAgent(emit=emit)
    try:
        await asyncio.wait_for(enricher.run(memory), timeout=settings.enrichment_timeout_s)
    except asyncio.TimeoutError:
        logger.warning("enrichment_timeout", task_id=task_id)
        # Continue with partial enrichment

    # 4. Research (parallel agents, per-agent timeout 30s per round)
    researcher_count = min(
        settings.researcher_count_default,
        len(memory.plan.research_questions),
    )
    researcher_tasks = []
    for i in range(researcher_count):
        question = memory.plan.research_questions[i] if i < len(memory.plan.research_questions) else ""
        agent = ResearchAgent(agent_id=f"R{i+1}", llm=llm, emit=emit)
        researcher_tasks.append(agent.run(memory, question=question))

    await asyncio.gather(*researcher_tasks, return_exceptions=True)

    # 5. IOC Extraction
    ioc_extractor = IOCExtractorAgent(llm=llm, emit=emit)
    await ioc_extractor.run(memory)

    # 6. Critic Review
    critic = CriticAgent(llm=llm, emit=emit)
    await critic.run(memory)

    # 7. Synthesis (streaming, timeout 120s)
    synthesizer = SynthesisAgent(llm=llm, emit=emit)
    try:
        await asyncio.wait_for(synthesizer.run(memory), timeout=settings.synthesis_timeout_s)
    except asyncio.TimeoutError:
        logger.warning("synthesis_timeout", task_id=task_id)
        # Use partial report if available
        if not memory.report_md:
            memory.report_md = synthesizer._fallback_report(memory)
