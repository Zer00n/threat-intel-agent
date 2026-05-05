from __future__ import annotations

import asyncio
import json
from typing import Any, Callable

import httpx
import structlog

from app.agents.enrichment.base import EnrichmentSource, SourceResult
from app.agents.enrichment.nvd import NvdSource
from app.agents.enrichment.kev import KevSource
from app.agents.enrichment.epss import EpssSource
from app.agents.enrichment.attck import AttckSource
from app.agents.enrichment.ghsa import GhsaSource

logger = structlog.get_logger()

SOURCE_MAP: dict[str, type[EnrichmentSource]] = {
    "nvd": NvdSource,
    "kev": KevSource,
    "epss": EpssSource,
    "attck": AttckSource,
    "ghsa": GhsaSource,
}


async def run_enrichment(
    intent: str,
    entities: dict[str, Any],
    sources: list[str],
    emit: Callable | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, SourceResult]:
    """Run enrichment from multiple sources concurrently."""
    results: dict[str, SourceResult] = {}

    entity = _get_primary_entity(intent, entities)
    if not entity:
        logger.warning("no_entity_for_enrichment", intent=intent)
        return results

    source_instances: dict[str, EnrichmentSource] = {}
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=15)

    try:
        for src_name in sources:
            cls = SOURCE_MAP.get(src_name)
            if cls:
                source_instances[src_name] = cls(client=client)

        tasks = {}
        for src_name, src in source_instances.items():
            if emit:
                await emit("data_source_query", {"source": src_name, "entity": entity})
            tasks[src_name] = src.fetch(entity)

        done_results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for src_name, result in zip(tasks.keys(), done_results):
            if isinstance(result, Exception):
                logger.warning("enrichment_source_error", source=src_name, error=str(result))
                results[src_name] = SourceResult(source=src_name, success=False, error=str(result))
                if emit:
                    await emit("data_source_error", {"source": src_name, "error": str(result)})
            else:
                results[src_name] = result
                event = "data_source_hit" if result.success else "data_source_miss"
                if emit:
                    await emit(event, {"source": src_name, "entity": entity, "from_cache": result.from_cache})

        if emit:
            await emit("enrichment_done", {"summary": _make_summary(results)})

    finally:
        for src in source_instances.values():
            await src.close()
        if owns_client:
            await client.aclose()

    return results


def _get_primary_entity(intent: str, entities: dict[str, Any]) -> str | None:
    if intent == "cve":
        ids = entities.get("cve_ids", [])
        return ids[0] if ids else None
    if intent == "attack_technique":
        ids = entities.get("technique_ids", [])
        return ids[0] if ids else None
    if intent == "threat_actor":
        names = entities.get("actor_names", [])
        return names[0] if names else None
    if intent == "malware":
        names = entities.get("malware_names", [])
        return names[0] if names else None
    return entities.get("cve_ids", [None])[0] if entities.get("cve_ids") else None


def _make_summary(results: dict[str, SourceResult]) -> dict[str, str]:
    return {name: "ok" if r.success else f"error: {r.error}" for name, r in results.items()}
