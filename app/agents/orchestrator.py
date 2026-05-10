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
from app.agents.sigma_generator import SigmaGeneratorAgent
from app.agents.synthesis import SynthesisAgent
from app.agents.llm_client import BudgetExceededError, LLMClient
from app.agents.memory import Memory
from app.agents.search_cache import SearchCache
from app.config import settings
from app.utils.time import now_iso

logger = structlog.get_logger()

# Per-agent timeouts tuned for slow third-party APIs (~30-60s per LLM call)
_INTENT_TIMEOUT = 60
_PLANNER_TIMEOUT = 60
_RESEARCHER_TIMEOUT = 180  # 2-3 rounds × ~60s per call
_IOC_TIMEOUT = 60
_CRITIC_TIMEOUT = 90


async def run_analysis(
    task_id: str,
    query: str,
    llm: LLMClient,
    emit: EmitFn,
    tlp: str = "GREEN",
    force_intent: str | None = None,
    db=None,
    agent_logs: list[dict] | None = None,
) -> dict[str, Any]:
    memory = Memory()
    memory.extra["query"] = query
    memory.extra["task_id"] = task_id
    memory.extra["tlp"] = tlp

    start_time = __import__("time").monotonic()

    try:
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
                    agent_events=agent_logs,
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

        if db:
            try:
                from app.agents.persistence import persist_analysis_results
                await persist_analysis_results(
                    db=db, task_id=task_id, memory=memory,
                    token_input=llm.total_usage.input_tokens,
                    token_output=llm.total_usage.output_tokens,
                    cost_usd=llm.total_usage.cost_usd,
                    duration_s=duration,
                    agent_events=agent_logs,
                )
            except Exception:
                pass

        return {"task_id": task_id, "status": "timeout", "memory": memory}

    except asyncio.CancelledError:
        await emit("stopped", {"partial_completed": True})

        if db:
            try:
                from app.agents.persistence import persist_analysis_results
                await persist_analysis_results(
                    db=db, task_id=task_id, memory=memory,
                    token_input=llm.total_usage.input_tokens,
                    token_output=llm.total_usage.output_tokens,
                    cost_usd=llm.total_usage.cost_usd,
                    agent_events=agent_logs,
                )
            except Exception:
                pass

        return {"task_id": task_id, "status": "stopped", "memory": memory}

    except BudgetExceededError as e:
        logger.warning("budget_exceeded", task_id=task_id, error=str(e))
        await emit("budget_exceeded", {
            "message": str(e),
            "used_token": llm.total_usage.input_tokens + llm.total_usage.output_tokens,
            "limit_token": settings.single_task_token_limit,
        })

        if db:
            try:
                from app.agents.persistence import persist_analysis_results
                await persist_analysis_results(
                    db=db, task_id=task_id, memory=memory,
                    token_input=llm.total_usage.input_tokens,
                    token_output=llm.total_usage.output_tokens,
                    cost_usd=llm.total_usage.cost_usd,
                    agent_events=agent_logs,
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
    try:
        await asyncio.wait_for(classifier.run(memory), timeout=_INTENT_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning("intent_classifier_timeout", task_id=task_id)
        await emit("agent_timeout", {"agent_id": "classifier", "timeout_s": _INTENT_TIMEOUT})
    if force_intent:
        memory.intent.intent = force_intent
    else:
        from app.task_manager import task_manager
        override = await task_manager.wait_for_intent_override(task_id, timeout=5)
        if override:
            memory.intent.intent = override
            await emit("intent_switched", {
                "intent": override,
                "message": "User selected a different research path",
            })

    # 2. Planning
    planner = PlannerAgent(llm=llm, emit=emit)
    try:
        await asyncio.wait_for(planner.run(memory), timeout=_PLANNER_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning("planner_timeout", task_id=task_id)
        await emit("agent_timeout", {"agent_id": "planner", "timeout_s": _PLANNER_TIMEOUT})

    # 3. Enrichment (parallel data source calls, per-source timeout 15s)
    enricher = EnrichmentAgent(emit=emit)
    try:
        await asyncio.wait_for(enricher.run(memory), timeout=settings.enrichment_timeout_s)
    except asyncio.TimeoutError:
        logger.warning("enrichment_timeout", task_id=task_id)

    # 4. Research (parallel agents)
    researcher_count = min(
        settings.researcher_count_default,
        len(memory.plan.research_questions),
    )
    researcher_tasks = []
    shared_search_cache = SearchCache()
    for i in range(researcher_count):
        question = memory.plan.research_questions[i] if i < len(memory.plan.research_questions) else ""
        agent = ResearchAgent(agent_id=f"R{i+1}", llm=llm, emit=emit, search_cache=shared_search_cache)
        researcher_tasks.append(
            asyncio.wait_for(agent.run(memory, question=question), timeout=_RESEARCHER_TIMEOUT)
        )

    results = await asyncio.gather(*researcher_tasks, return_exceptions=True)
    for i, r in enumerate(results):
        if isinstance(r, (asyncio.TimeoutError, Exception)):
            logger.warning("researcher_failed", agent_id=f"R{i+1}", error=str(r)[:200])
            await emit("agent_timeout", {"agent_id": f"R{i+1}", "error": str(r)[:100]})

    # 5. IOC Extraction
    ioc_extractor = IOCExtractorAgent(llm=llm, emit=emit)
    try:
        await asyncio.wait_for(ioc_extractor.run(memory), timeout=_IOC_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning("ioc_extractor_timeout", task_id=task_id)

    # 6. Critic Review
    critic = CriticAgent(llm=llm, emit=emit)
    try:
        await asyncio.wait_for(critic.run(memory), timeout=_CRITIC_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning("critic_timeout", task_id=task_id)

    # 6.5 Sigma Rule Generation
    sigma_gen = SigmaGeneratorAgent(llm=llm, emit=emit)
    try:
        await asyncio.wait_for(sigma_gen.run(memory), timeout=60)
    except asyncio.TimeoutError:
        logger.warning("sigma_generator_timeout", task_id=task_id)

    # 7. Synthesis (streaming)
    synthesizer = SynthesisAgent(llm=llm, emit=emit)
    try:
        await asyncio.wait_for(synthesizer.run(memory), timeout=settings.synthesis_timeout_s)
    except asyncio.TimeoutError:
        logger.warning("synthesis_timeout", task_id=task_id)
        if not memory.report_md:
            memory.report_md = synthesizer._fallback_report(memory)
