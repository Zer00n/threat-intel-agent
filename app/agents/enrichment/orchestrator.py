from __future__ import annotations

import asyncio
import json
import hashlib
from typing import Any, Callable

import httpx
import structlog

from app.agents.enrichment.base import EnrichmentSource, SourceResult, make_proxied_client
from app.agents.enrichment.nvd import NvdSource
from app.agents.enrichment.kev import KevSource
from app.agents.enrichment.epss import EpssSource
from app.agents.enrichment.attck import AttckSource
from app.agents.enrichment.ghsa import GhsaSource
from app.db.engine import async_session_factory
from app.db.repositories.cache import get_cached, set_cached

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
        client = make_proxied_client(timeout=15)

    try:
        for src_name in sources:
            cls = SOURCE_MAP.get(src_name)
            if cls:
                source_instances[src_name] = cls(client=client)

        tasks = {}
        for src_name, src in source_instances.items():
            if emit:
                await emit("data_source_query", {"source": src_name, "entity": entity})
            tasks[src_name] = _fetch_with_cache(src_name, src, entity)

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


async def _fetch_with_cache(src_name: str, src: EnrichmentSource, entity: str) -> SourceResult:
    cache_key = _cache_key(src_name, entity)
    async with async_session_factory() as db:
        cached = await get_cached(db, cache_key)
        if cached is not None:
            return SourceResult(
                source=src_name,
                success=True,
                data=cached,
                from_cache=True,
            )

    result = await src.fetch(entity)
    if result.success:
        async with async_session_factory() as db:
            await set_cached(db, cache_key, src_name, result.data, src.cache_ttl)
    return result


def _cache_key(src_name: str, entity: str) -> str:
    raw = f"{src_name}:{entity.strip().lower()}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"{src_name}:{digest[:48]}"


def _get_primary_entity(intent: str, entities: dict[str, Any]) -> str | None:
    """Extract the primary entity string for enrichment source queries."""
    # CVE-family intents
    if intent in ("cve", "multi_cve", "product_vulnerability", "cwe", "cpe"):
        ids = entities.get("cve_ids", [])
        if ids:
            return ids[0]
        # Fall back to advisory IDs for non-CVE vulnerability queries
        advisory = entities.get("advisory_ids", [])
        if advisory:
            return advisory[0]
        # Fall back to first keyword
        kw = entities.get("keywords", [])
        return kw[0] if kw else None

    if intent == "vulnerability_advisory":
        advisory = entities.get("advisory_ids", [])
        if advisory:
            return advisory[0]
        ids = entities.get("cve_ids", [])
        return ids[0] if ids else None

    if intent in ("attack_technique", "tool_or_ttp"):
        ids = entities.get("technique_ids", [])
        if ids:
            return ids[0]
        tools = entities.get("tool_names", [])
        return tools[0] if tools else None

    if intent in ("threat_actor", "campaign"):
        names = entities.get("actor_names", [])
        if names:
            return names[0]
        campaigns = entities.get("campaign_names", [])
        return campaigns[0] if campaigns else None

    if intent in ("malware", "malware_artifact"):
        names = entities.get("malware_names", [])
        return names[0] if names else None

    if intent in ("ioc_ip", "ioc_domain", "ioc_hash", "ioc_email", "ioc_filepath"):
        iocs = entities.get("iocs", [])
        if iocs:
            return iocs[0].get("value") if isinstance(iocs[0], dict) else str(iocs[0])
        # Legacy flat list
        flat = entities.get("iocs", [])
        return flat[0] if flat else None

    # Legacy / generic fallback
    if intent in ("vulnerability_generic", "incident_description", "incident_analysis",
                  "threat_activity", "misconfiguration", "generic"):
        ids = entities.get("cve_ids", [])
        if ids:
            return ids[0]
        kw = entities.get("keywords", [])
        return kw[0] if kw else None

    # Last resort: any cve_ids present
    return entities.get("cve_ids", [None])[0] if entities.get("cve_ids") else None


def _make_summary(results: dict[str, SourceResult]) -> dict[str, str]:
    return {name: "ok" if r.success else f"error: {r.error}" for name, r in results.items()}
