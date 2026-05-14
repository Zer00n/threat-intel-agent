from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import structlog

from app.agents.base import AgentResult, BaseAgent, EmitFn
from app.agents.llm_client import LLMClient
from app.agents.memory import Finding, Memory
from app.agents.search_cache import SearchCache
from app.config import settings

logger = structlog.get_logger()

_PROMPT_FILE = Path(__file__).parent / "prompts" / "researcher.md"


def _load_prompt() -> str:
    if _PROMPT_FILE.exists():
        return _PROMPT_FILE.read_text(encoding="utf-8")
    logger.warning("researcher_prompt_file_missing", path=str(_PROMPT_FILE))
    return (
        "You are a threat intelligence researcher. Investigate the given research question. "
        "Use web_search to find authoritative information. "
        "Each finding MUST have a source_url. "
        "Assign confidence: High (official source), Medium (single credible source), Low (unverified). "
        "You have at most {max_rounds} search rounds. Call submit_findings when done."
    )

SUBMIT_TOOL = {
    "name": "submit_findings",
    "description": "Submit the research findings with sources and confidence levels.",
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "claim": {"type": "string"},
                        "detail": {"type": "string"},
                        "source_url": {"type": "string"},
                        "source_name": {"type": "string"},
                        "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
                    },
                    "required": ["claim", "source_url", "confidence"],
                },
            },
            "info_gaps": {"type": "array", "items": {"type": "string"}},
            "rounds_used": {"type": "integer"},
        },
        "required": ["findings", "rounds_used"],
    },
}

SEARCH_TOOL = {
    "name": "web_search",
    "description": "Search the web for information about a specific topic.",
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
        },
        "required": ["query"],
    },
}

_SYSTEM_PROMPT = ""  # kept for backward-compat; actual prompt loaded from file


class ResearchAgent(BaseAgent):
    name = "ResearchAgent"

    def __init__(
        self,
        agent_id: str = "",
        llm: LLMClient | None = None,
        emit: EmitFn | None = None,
        search_cache: SearchCache | None = None,
    ):
        super().__init__(emit)
        self._agent_id = agent_id or str(uuid.uuid4())[:8]
        self._llm = llm
        self._search_cache = search_cache or SearchCache()
        self._base_prompt = _load_prompt()

    async def run(self, memory: Memory, question: str = "", **kwargs: Any) -> AgentResult:
        await self.emit("agent_start", {"agent_id": self._agent_id, "question": question})

        if not self._llm:
            return AgentResult(success=False, error="no LLM client")

        # Inject max_rounds into prompt (placeholder substitution)
        system = self._base_prompt.replace("{max_rounds}", str(settings.researcher_max_rounds))

        # Append enrichment context so researcher knows what NOT to re-search
        if memory.enrichment:
            system += "\n\n---\n## Authoritative Data Already Collected (Do NOT re-search these fields)\n"
            for src, data in memory.enrichment.items():
                if isinstance(data, dict):
                    system += f"\n### {src}\n{str(data)[:600]}\n"

        messages: list[dict[str, Any]] = [
            {"role": "user", "content": f"Research question: {question}"}
        ]

        findings: list[Finding] = []
        rounds_used = 0

        for round_num in range(1, settings.researcher_max_rounds + 1):
            rounds_used = round_num
            await self.emit("thinking", {"agent_id": self._agent_id, "content": f"Research round {round_num}"})

            try:
                resp = await self._llm.complete(
                    system=system,
                    messages=messages,
                    tools=[SEARCH_TOOL, SUBMIT_TOOL],
                    max_tokens=4096,
                )
            except Exception as e:
                await self.emit("agent_error", {"agent_id": self._agent_id, "message": str(e)})
                break

            if resp.tool_name == "submit_findings":
                for f in resp.tool_use.get("findings", []):
                    source_url = f.get("source_url", "")
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        claim=f.get("claim", ""),
                        detail=f.get("detail", ""),
                        source_url=source_url,
                        source_name=f.get("source_name", ""),
                        source_type="open",
                        confidence=f.get("confidence", "Medium"),
                    ))
                    # Track source URL for sources_used table (PRD §FR-20)
                    if source_url and source_url.startswith("http"):
                        memory.sources_used.add(source_url)
                await self.emit("agent_done", {
                    "agent_id": self._agent_id,
                    "rounds": rounds_used,
                    "findings_count": len(findings),
                })
                break

            if resp.tool_name == "web_search":
                query = resp.tool_use.get("query", "")
                await self.emit("searching", {
                    "agent_id": self._agent_id,
                    "query": query,
                    "round": round_num,
                    "cache_hit": self._search_cache.get(query) is not None,
                })

                results = await self._search_cache.get_or_fetch(query, self._mock_search)

                await self.emit("found", {
                    "agent_id": self._agent_id,
                    "source_count": len(results),
                    "round": round_num,
                })

                messages.append({"role": "assistant", "content": resp.content or f"Searching for: {query}"})
                messages.append({
                    "role": "user",
                    "content": f"Search results for '{query}':\n" + _format_results(results),
                })
            else:
                messages.append({"role": "assistant", "content": resp.content or ""})

        memory.findings.extend(findings)

        if not findings:
            # Fallback: ask LLM to submit findings from what it gathered
            try:
                messages.append({"role": "user", "content": "You have used all search rounds. Now call submit_findings with whatever information you have gathered. Even partial findings are better than none."})
                resp = await self._llm.complete(
                    system=system,
                    messages=messages,
                    tools=[SUBMIT_TOOL],
                    max_tokens=2048,
                )
                if resp.tool_name == "submit_findings":
                    for f in resp.tool_use.get("findings", []):
                        source_url = f.get("source_url", "")
                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            claim=f.get("claim", ""),
                            detail=f.get("detail", ""),
                            source_url=source_url,
                            source_name=f.get("source_name", ""),
                            source_type="open",
                            confidence=f.get("confidence", "Medium"),
                        ))
                        if source_url and source_url.startswith("http"):
                            memory.sources_used.add(source_url)
                    memory.findings.extend(findings)
            except Exception as e:
                await self.emit("agent_error", {"agent_id": self._agent_id, "message": str(e)})

        if not findings:
            await self.emit("agent_done", {
                "agent_id": self._agent_id,
                "rounds": rounds_used,
                "findings_count": 0,
            })

        return AgentResult(data={"findings": len(findings), "rounds": rounds_used})

    async def _mock_search(self, query: str) -> list[dict[str, Any]]:
        """Real web search using DuckDuckGo."""
        from app.agents.web_search import web_search
        results = await web_search(query, max_results=5)
        if results:
            return results
        # Fallback: use LLM knowledge if search fails
        return [{"title": f"Search unavailable for: {query}", "url": "", "snippet": "Web search returned no results. Use your training knowledge to answer."}]


def _format_results(results: list[dict[str, Any]]) -> str:
    lines = []
    for i, r in enumerate(results[:5], 1):
        lines.append(f"{i}. {r.get('title', 'N/A')}\n   URL: {r.get('url', '')}\n   {r.get('snippet', '')}")
    return "\n".join(lines) if lines else "No results found."
