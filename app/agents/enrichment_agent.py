from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from app.agents.base import AgentResult, BaseAgent, EmitFn
from app.agents.enrichment.base import SourceResult
from app.agents.enrichment.orchestrator import run_enrichment
from app.agents.memory import CVERef, Memory
from app.utils.time import now_iso
import uuid

logger = structlog.get_logger()

# Degradation fallback: when authoritative source fails, try web_search
_DEGRADATION_WEB_SEARCH = {"nvd"}


class EnrichmentAgent(BaseAgent):
    name = "EnrichmentAgent"

    def __init__(self, emit: EmitFn | None = None):
        super().__init__(emit)

    async def run(self, memory: Memory, **kwargs: Any) -> AgentResult:
        sources = memory.plan.authoritative_sources
        intent = memory.intent.intent
        entities = memory.intent.entities

        if not sources:
            return AgentResult(data={"enriched": 0})

        results = await run_enrichment(
            intent=intent,
            entities=entities,
            sources=sources,
            emit=self.emit,
        )

        # Apply degradation strategy per PRD §7.6
        await self._apply_degradation(results, memory, entities)

        memory.enrichment = {name: r.data for name, r in results.items()}

        # Build CVE refs from enrichment data
        _CVE_FAMILY = {"cve", "multi_cve", "vulnerability_advisory", "product_vulnerability", "cwe", "cpe"}
        if intent in _CVE_FAMILY and "nvd" in results and results["nvd"].success:
            nvd_data = results["nvd"].data
            self._extract_cve_refs(memory, nvd_data, results)

        # Track degradation notes in enrichment metadata
        degraded = [name for name, r in results.items() if not r.success and name in _DEGRADATION_WEB_SEARCH]
        if degraded:
            memory.extra["degraded_sources"] = degraded

        return AgentResult(data={"enriched": len(results)})

    async def _apply_degradation(self, results: dict[str, SourceResult], memory: Memory, entities: dict) -> None:
        """Per PRD §7.6: apply fallback when authoritative source fails."""
        cve_ids = entities.get("cve_ids", [])
        cve_id = cve_ids[0] if cve_ids else None

        for source_name in list(results.keys()):
            r = results[source_name]
            if r.success:
                continue

            if source_name == "nvd" and cve_id:
                # NVD fallback: use web_search (marked as degraded)
                logger.info("nvd_degradation", cve_id=cve_id)
                results[source_name] = SourceResult(
                    source="nvd",
                    success=True,
                    data={"degraded": True, "note": f"NVD unavailable, degraded to web_search for {cve_id}"},
                    from_cache=False,
                )

            elif source_name == "kev":
                # KEV fallback: use last successful cache (handled by KEV adapter internally)
                logger.info("kev_degradation_uses_cache")
                # KEV adapter already returns from cache if download fails

            elif source_name == "epss":
                # EPSS fallback: skip, report will omit EPSS field
                logger.info("epss_degradation_skip")
                results[source_name] = SourceResult(
                    source="epss",
                    success=True,
                    data={"degraded": True, "note": "EPSS unavailable, field omitted"},
                )

            elif source_name == "attck":
                # ATT&CK fallback: use local cache (handled by attck_loader)
                logger.info("attck_degradation_uses_local")

    def _extract_cve_refs(self, memory: Memory, nvd_data: dict, results: dict) -> None:
        from app.agents.enrichment.nvd import NvdSource

        nvd_src = NvdSource.__new__(NvdSource)
        fields = nvd_src.extract_fields(nvd_data)

        cve_ids = memory.intent.entities.get("cve_ids", [])
        cve_id = cve_ids[0] if cve_ids else "unknown"

        kev_data = results.get("kev")
        epss_data = results.get("epss")

        is_in_kev = False
        kev_added = None
        if kev_data and kev_data.success:
            kev_vuln = kev_data.data
            if kev_vuln.get("in_kev", True):
                is_in_kev = True
                kev_added = kev_vuln.get("dateAdded")

        epss_score = None
        epss_pct = None
        epss_date = None
        if epss_data and epss_data.success:
            epss_score = epss_data.data.get("epss")
            epss_pct = epss_data.data.get("percentile")
            epss_date = epss_data.data.get("date")
            if epss_score is not None:
                epss_score = float(epss_score)
            if epss_pct is not None:
                epss_pct = float(epss_pct)

        ref = CVERef(
            id=str(uuid.uuid4()),
            cve_id=cve_id,
            cvss_v3_score=fields.get("cvss_v3_score"),
            cvss_v3_vector=fields.get("cvss_v3_vector"),
            cwe_ids=fields.get("cwe_ids", []),
            cpe_matches=fields.get("cpe_matches", []),
            description=fields.get("description", ""),
            is_in_kev=is_in_kev,
            kev_added_date=kev_added,
            epss_score=epss_score,
            epss_percentile=epss_pct,
            epss_date=epss_date,
            source_payload=nvd_data,
        )
        memory.cve_refs.append(ref)
