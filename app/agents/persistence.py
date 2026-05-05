"""Persist agent pipeline results to database after analysis completes."""
from __future__ import annotations

import json

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.memory import Memory
from app.db.models import (
    AgentLog,
    Analysis,
    AttackTechnique,
    CVERef,
    Finding,
    IOC,
    SourceUsed,
)
from app.utils.time import now_iso

logger = structlog.get_logger()


async def persist_analysis_results(
    db: AsyncSession,
    task_id: str,
    memory: Memory,
    token_input: int = 0,
    token_output: int = 0,
    cost_usd: float = 0.0,
    duration_s: float = 0.0,
) -> None:
    """Write all pipeline outputs to database tables."""
    now = now_iso()

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

    await db.commit()
    logger.info("analysis_persisted", task_id=task_id,
                findings=len(memory.findings),
                iocs=len(memory.iocs),
                cves=len(memory.cve_refs),
                techniques=len(memory.attck_techniques))
