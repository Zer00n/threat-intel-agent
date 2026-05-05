from __future__ import annotations

import uuid
from typing import Any

from app.agents.base import AgentResult, BaseAgent, EmitFn
from app.agents.llm_client import LLMClient
from app.agents.memory import IOC, Memory
from app.utils.defang import defang
from app.utils.ioc_regex import extract_all_iocs

LLM_IOC_TOOL = {
    "name": "extract_iocs",
    "description": "Extract IOCs mentioned in the text, including semantic ones like 'C2 server: x.x.x.x'.",
    "input_schema": {
        "type": "object",
        "properties": {
            "iocs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "enum": ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "filepath"]},
                        "value": {"type": "string"},
                        "context": {"type": "string"},
                        "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
                    },
                    "required": ["type", "value"],
                },
            },
        },
        "required": ["iocs"],
    },
}

_SYSTEM_PROMPT = """Extract IOCs (Indicators of Compromise) from the text.
Look for:
- IP addresses, domains, URLs
- File hashes (MD5, SHA1, SHA256)
- Email addresses, file paths
- Semantic mentions like "C2 server: ...", "delivery domain: ..."
Do NOT include example.com, localhost, RFC1918 addresses, or version numbers."""


class IOCExtractorAgent(BaseAgent):
    name = "IOCExtractorAgent"

    def __init__(self, llm: LLMClient | None = None, emit: EmitFn | None = None):
        super().__init__(emit)
        self._llm = llm

    async def run(self, memory: Memory, **kwargs: Any) -> AgentResult:
        await self.emit("ioc_extracting", {"content": "Extracting IOCs from findings..."})

        text = self._build_text(memory)
        iocs: list[IOC] = []

        # Regex extraction
        regex_iocs = extract_all_iocs(text)
        for r in regex_iocs:
            iocs.append(IOC(
                id=str(uuid.uuid4()),
                ioc_type=r["type"],
                value=r["value"],
                value_defanged=defang(r["value"], r["type"]),
                context=self._find_context(text, r["value"]),
                confidence="Medium",
                is_extracted_by="regex",
            ))

        # LLM extraction
        if self._llm:
            try:
                llm_iocs = await self._llm_extract(text)
                for lioc in llm_iocs:
                    value = lioc.get("value", "")
                    ioc_type = lioc.get("type", "domain")
                    # Deduplicate
                    if not any(i.value == value and i.ioc_type == ioc_type for i in iocs):
                        iocs.append(IOC(
                            id=str(uuid.uuid4()),
                            ioc_type=ioc_type,
                            value=value,
                            value_defanged=defang(value, ioc_type),
                            context=lioc.get("context", ""),
                            confidence=lioc.get("confidence", "Medium"),
                            is_extracted_by="llm",
                        ))
            except Exception as e:
                await self.emit("agent_error", {"agent_id": self.name, "message": str(e)})

        memory.iocs.extend(iocs)

        by_type: dict[str, int] = {}
        for ioc in iocs:
            by_type[ioc.ioc_type] = by_type.get(ioc.ioc_type, 0) + 1

        await self.emit("ioc_extracted", {"ioc_count": len(iocs), "by_type": by_type})
        return AgentResult(data={"ioc_count": len(iocs)})

    async def _llm_extract(self, text: str) -> list[dict]:
        resp = await self._llm.complete(
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Extract IOCs from:\n\n{text[:8000]}"}],
            tools=[LLM_IOC_TOOL],
            max_tokens=2048,
        )
        if resp.tool_use:
            return resp.tool_use.get("iocs", [])
        return []

    def _build_text(self, memory: Memory) -> str:
        parts = []
        for f in memory.findings:
            parts.append(f.claim)
            if f.detail:
                parts.append(f.detail)
        for cve in memory.cve_refs:
            if cve.description:
                parts.append(cve.description)
        return "\n".join(parts)

    def _find_context(self, text: str, value: str) -> str:
        idx = text.find(value)
        if idx == -1:
            return ""
        start = max(0, idx - 80)
        end = min(len(text), idx + len(value) + 80)
        return text[start:end].strip()
