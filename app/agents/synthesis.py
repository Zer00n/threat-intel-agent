from __future__ import annotations

from pathlib import Path
from typing import Any, AsyncGenerator

from app.agents.base import AgentResult, BaseAgent, EmitFn
from app.agents.llm_client import LLMClient
from app.agents.memory import Memory

# Load prompt from markdown file
_PROMPT_FILE = Path(__file__).parent / "prompts" / "synthesis.md"


def _load_prompt() -> str:
    if _PROMPT_FILE.exists():
        return _PROMPT_FILE.read_text(encoding="utf-8")
    # Fallback if file not found
    return """You are a senior threat intelligence analyst.
Synthesize the research data into a structured report in Chinese.
Output must follow the 15-section structure defined in the prompt file."""


class SynthesisAgent(BaseAgent):
    name = "SynthesisAgent"

    def __init__(self, llm: LLMClient | None = None, emit: EmitFn | None = None):
        super().__init__(emit)
        self._llm = llm
        self._base_prompt = _load_prompt()

    async def run(self, memory: Memory, **kwargs: Any) -> AgentResult:
        await self.emit("synthesizing", {"content": "Generating final report..."})

        context = memory.to_synthesis_context()
        confidence = memory.critic_result.overall_assessment if memory.critic_result else "Medium"
        tlp = memory.extra.get("tlp", "GREEN")

        # Build system prompt with dynamic values
        system = f"""{self._base_prompt}

---
# Current Analysis Context

- TLP: {tlp}
- Overall Confidence: {confidence}
- Intent: {memory.intent.intent}

Use the TLP value above in the 元信息 section.
"""

        if not self._llm:
            memory.report_md = self._fallback_report(memory)
            return AgentResult(data={"report_length": len(memory.report_md)})

        full_text = ""
        try:
            async for chunk in self._llm.stream(
                system=system,
                messages=[{"role": "user", "content": f"Generate the threat intelligence report based on:\n\n{context}"}],
                max_tokens=8192,
            ):
                full_text += chunk
                await self.emit("report_chunk", {"content": chunk})
        except Exception as e:
            await self.emit("agent_error", {"agent_id": self.name, "message": str(e)})

        memory.report_md = full_text
        return AgentResult(data={"report_length": len(full_text)})

    def _fallback_report(self, memory: Memory) -> str:
        parts = ["# Threat Intelligence Report\n"]
        parts.append(f"**Query:** {memory.extra.get('query', 'N/A')}")
        parts.append(f"**Intent:** {memory.intent.intent}")
        parts.append(f"**TLP:** {memory.extra.get('tlp', 'GREEN')}")
        parts.append(f"**Confidence:** {memory.critic_result.overall_assessment if memory.critic_result else 'N/A'}\n")

        if memory.cve_refs:
            parts.append("## Key Facts")
            for cve in memory.cve_refs:
                parts.append(f"- **{cve.cve_id}**")
                parts.append(f"  - CVSS 3.1: {cve.cvss_v3_score}")
                parts.append(f"  - KEV: {'Yes' if cve.is_in_kev else 'No'}")
                if cve.epss_score is not None:
                    parts.append(f"  - EPSS: {cve.epss_score} ({cve.epss_percentile} percentile)")
                if cve.description:
                    parts.append(f"  - {cve.description[:200]}")

        if memory.findings:
            parts.append("\n## Findings")
            for f in memory.findings:
                parts.append(f"- [{f.confidence}] {f.claim}")
                if f.source_url:
                    parts.append(f"  - Source: {f.source_url}")

        if memory.iocs:
            parts.append(f"\n## IOCs ({len(memory.iocs)})")
            for ioc in memory.iocs[:10]:
                parts.append(f"- {ioc.ioc_type}: {ioc.value_defanged}")

        if memory.attck_techniques:
            parts.append("\n## ATT&CK Mapping")
            parts.append("| Technique | Name | Tactic |")
            parts.append("|-----------|------|--------|")
            for t in memory.attck_techniques:
                parts.append(f"| {t.technique_id} | {t.technique_name} | {t.tactic} |")

        return "\n".join(parts)
