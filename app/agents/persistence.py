"""Persist agent pipeline results to database after analysis completes."""
from __future__ import annotations

import json
import re
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.memory import AttckMapping, IOC as MemoryIOC, Memory
from app.db.models import (
    AgentLog,
    Analysis,
    AttackTechnique,
    CVERef,
    Finding,
    IOC,
    SourceUsed,
    TokenUsageMonthly,
)
from app.utils.time import now_iso
from app.utils.attck_loader import get_technique, validate_technique_id
from app.utils.defang import defang
from app.utils.ioc_regex import extract_all_iocs

logger = structlog.get_logger()


async def persist_analysis_results(
    db: AsyncSession,
    task_id: str,
    memory: Memory,
    token_input: int = 0,
    token_output: int = 0,
    cost_usd: float = 0.0,
    duration_s: float = 0.0,
    agent_events: list[dict] | None = None,
) -> None:
    """Write all pipeline outputs to database tables."""
    now = now_iso()

    # 0. Pre-process: extract structured objects from all available text/data.
    _extract_iocs_from_text(memory)
    _extract_attck_from_enrichment(memory)
    _extract_attck_from_text(memory)

    # 1. Update analyses table
    from sqlalchemy import update
    await db.execute(
        update(Analysis).where(Analysis.id == task_id).values(
            intent=memory.intent.intent,
            intent_entities=json.dumps(memory.intent.entities, ensure_ascii=False),
            report_md=memory.report_md,
            overall_confidence=memory.critic_result.overall_assessment if memory.critic_result else None,
            token_input=token_input,
            token_output=token_output,
            cost_usd=cost_usd,
            duration_s=int(duration_s),
            updated_at=now,
        )
    )

    # 1.5. Update monthly token usage in real-time
    current_month = now[:7]  # "2026-05"
    existing_monthly = await db.get(TokenUsageMonthly, current_month)
    if existing_monthly:
        existing_monthly.total_input += token_input
        existing_monthly.total_output += token_output
        existing_monthly.total_cost_usd += cost_usd
        existing_monthly.analysis_count += 1
        existing_monthly.updated_at = now
    else:
        db.add(TokenUsageMonthly(
            year_month=current_month,
            total_input=token_input,
            total_output=token_output,
            total_cost_usd=cost_usd,
            analysis_count=1,
            updated_at=now,
        ))

    # 2. Persist findings
    for f in memory.findings:
        db.add(Finding(
            id=f.id,
            analysis_id=task_id,
            agent_name="ResearchAgent",
            claim=f.claim,
            detail=f.detail,
            source_type=f.source_type,
            source_url=f.source_url,
            source_name=f.source_name,
            confidence=f.confidence,
            created_at=now,
        ))

    # 3. Persist IOCs
    for ioc in memory.iocs:
        db.add(IOC(
            id=ioc.id,
            analysis_id=task_id,
            ioc_type=ioc.ioc_type,
            value=ioc.value,
            value_defanged=ioc.value_defanged,
            context=ioc.context,
            source_finding_id=ioc.source_finding_id or None,
            confidence=ioc.confidence,
            is_extracted_by=ioc.is_extracted_by,
            created_at=now,
        ))

    # 4. Persist CVE refs
    for cve in memory.cve_refs:
        db.add(CVERef(
            id=cve.id,
            analysis_id=task_id,
            cve_id=cve.cve_id,
            cvss_v3_score=cve.cvss_v3_score,
            cvss_v3_vector=cve.cvss_v3_vector,
            cwe_ids=json.dumps(cve.cwe_ids),
            cpe_matches=json.dumps(cve.cpe_matches),
            description=cve.description,
            is_in_kev=cve.is_in_kev,
            kev_added_date=cve.kev_added_date,
            epss_score=cve.epss_score,
            epss_percentile=cve.epss_percentile,
            epss_date=cve.epss_date,
            source_payload=json.dumps(cve.source_payload, ensure_ascii=False) if cve.source_payload else None,
            created_at=now,
        ))

    # 5. Persist ATT&CK techniques
    for tech in memory.attck_techniques:
        db.add(AttackTechnique(
            analysis_id=task_id,
            technique_id=tech.technique_id,
            technique_name=tech.technique_name,
            tactic=tech.tactic,
            confidence=tech.confidence,
            rationale=tech.rationale,
            created_at=now,
        ))

    # 6. Persist sources used
    for url in memory.sources_used:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc if urlparse(url).netloc else url[:64]
        db.add(SourceUsed(
            analysis_id=task_id,
            url=url,
            domain=domain,
            source_type="open",
            is_trusted=False,
            accessed_at=now,
        ))

    # 7. Persist AgentLogs from SSE events
    if agent_events:
        for seq, ev in enumerate(agent_events, 1):
            db.add(AgentLog(
                analysis_id=task_id,
                sequence=seq,
                event_type=ev.get("event_type", "unknown"),
                agent_name=_extract_agent_name(ev),
                payload=json.dumps(ev.get("data", {}), ensure_ascii=False) if ev.get("data") else None,
                created_at=now,
            ))

    await db.commit()
    logger.info("analysis_persisted", task_id=task_id,
                findings=len(memory.findings),
                iocs=len(memory.iocs),
                cves=len(memory.cve_refs),
                techniques=len(memory.attck_techniques),
                logs=len(agent_events) if agent_events else 0)


def _extract_agent_name(event: dict) -> str | None:
    """Extract agent name from event data for the agent_name column."""
    data = event.get("data", {})
    agent_id = data.get("agent_id") or data.get("agent_name")
    if agent_id:
        return str(agent_id)
    # Map event types to agent names
    event_type = event.get("event_type", "")
    _EVENT_AGENT_MAP = {
        "intent_classified": "IntentClassifier",
        "plan_result": "PlannerAgent",
        "data_source_query": "EnrichmentAgent",
        "data_source_hit": "EnrichmentAgent",
        "data_source_miss": "EnrichmentAgent",
        "data_source_error": "EnrichmentAgent",
        "enrichment_done": "EnrichmentAgent",
        "ioc_extracting": "IOCExtractorAgent",
        "ioc_extracted": "IOCExtractorAgent",
        "critic_review": "CriticAgent",
        "critic_done": "CriticAgent",
        "synthesizing": "SynthesisAgent",
        "done": "Orchestrator",
        "error": "Orchestrator",
        "stopped": "Orchestrator",
    }
    return _EVENT_AGENT_MAP.get(event_type)


def _extract_attck_from_enrichment(memory: Memory) -> None:
    """Extract ATT&CK techniques from enrichment data if not already populated."""
    if memory.attck_techniques:
        return  # already populated by an agent

    attck_data = memory.enrichment.get("attck")
    if not attck_data or not isinstance(attck_data, dict):
        return

    # Handle technique objects from ATT&CK enrichment
    if attck_data.get("found") is False:
        return

    technique_id = attck_data.get("external_references", [{}])[0].get("external_id", "") if attck_data.get("external_references") else ""
    if not technique_id:
        # Try alternative fields
        technique_id = attck_data.get("id", "")

    technique_name = attck_data.get("name", "")
    tactics = attck_data.get("tactic", []) or attck_data.get("kill_chain_phases", [])

    if technique_id:
        tactic_name = ""
        if isinstance(tactics, list) and tactics:
            if isinstance(tactics[0], dict):
                tactic_name = tactics[0].get("phase_name", "") or tactics[0].get("tactic", "")
            else:
                tactic_name = str(tactics[0])
        elif isinstance(tactics, str):
            tactic_name = tactics

        memory.attck_techniques.append(AttckMapping(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic_name,
            confidence="Medium",
            rationale="Extracted from ATT&CK enrichment data",
        ))

    # Also handle group/software objects that may reference techniques
    for ref in attck_data.get("external_references", []):
        ref_id = ref.get("external_id", "")
        if ref_id.startswith("T") and ref_id != technique_id:
            memory.attck_techniques.append(AttckMapping(
                technique_id=ref_id,
                technique_name=ref.get("source_name", ""),
                tactic="",
                confidence="Low",
                rationale="Referenced in enrichment context",
            ))


def _extract_iocs_from_text(memory: Memory) -> None:
    """Backfill IOCs from final report/findings so history tabs reflect report content."""
    text = _analysis_text(memory)
    if not text:
        return

    existing = {(ioc.ioc_type, ioc.value.lower()) for ioc in memory.iocs}
    for item in extract_all_iocs(text):
        ioc_type = item["type"]
        value = item["value"]
        key = (ioc_type, value.lower())
        if key in existing:
            continue
        memory.iocs.append(MemoryIOC(
            id=__import__("uuid").uuid4().hex,
            ioc_type=ioc_type,
            value=value,
            value_defanged=defang(value, ioc_type),
            context=_find_context(text, value),
            confidence="Medium",
            is_extracted_by="regex",
        ))
        existing.add(key)


def _extract_attck_from_text(memory: Memory) -> None:
    """Backfill ATT&CK mappings from report/findings when synthesis mentions techniques."""
    text = _analysis_text(memory)
    if not text:
        return

    existing = {tech.technique_id for tech in memory.attck_techniques}
    for technique_id in sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text))):
        if technique_id in existing:
            continue
        if not validate_technique_id(technique_id):
            continue
        technique = get_technique(technique_id) or {}
        tactics = technique.get("kill_chain_phases", [])
        tactic = ""
        if tactics:
            first = tactics[0]
            tactic = first.get("phase_name", "") if isinstance(first, dict) else str(first)
        memory.attck_techniques.append(AttckMapping(
            technique_id=technique_id,
            technique_name=technique.get("name", technique_id),
            tactic=tactic,
            confidence="Medium",
            rationale="Extracted from final report or findings text",
        ))
        existing.add(technique_id)


def _analysis_text(memory: Memory) -> str:
    parts = []
    if memory.report_md:
        parts.append(memory.report_md)
    for finding in memory.findings:
        parts.append(finding.claim)
        if finding.detail:
            parts.append(finding.detail)
    return "\n".join(parts)


def _find_context(text: str, value: str) -> str:
    idx = text.lower().find(value.lower())
    if idx == -1:
        return ""
    start = max(0, idx - 80)
    end = min(len(text), idx + len(value) + 80)
    return text[start:end].strip()
