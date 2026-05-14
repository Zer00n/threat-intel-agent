"""Sigma Rule Generator Agent - uses LLM to generate detection rules from findings."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

from app.agents.base import AgentResult, BaseAgent, EmitFn
from app.agents.llm_client import LLMClient
from app.agents.memory import Memory

logger = structlog.get_logger()

_PROMPT_FILE = Path(__file__).parent / "prompts" / "sigma_generator.md"


def _load_prompt() -> str:
    if _PROMPT_FILE.exists():
        return _PROMPT_FILE.read_text(encoding="utf-8")
    # Fallback if file not found
    logger.warning("sigma_generator_prompt_file_missing", path=str(_PROMPT_FILE))
    return (
        "You are a Sigma rule generator for threat detection. "
        "Generate 1-3 Sigma detection rules in YAML format based on the provided findings, IOCs, and ATT&CK techniques. "
        "The description MUST start with 'AI-GENERATED DRAFT - REQUIRES HUMAN REVIEW.' "
        "Output ONLY the YAML rules separated by ---."
    )

SIGMA_TOOL = {
    "name": "submit_sigma_rules",
    "description": "Submit generated Sigma detection rules as YAML text.",
    "input_schema": {
        "type": "object",
        "properties": {
            "rules_yaml": {
                "type": "string",
                "description": "Complete Sigma rules in YAML format, separated by ---",
            },
        },
        "required": ["rules_yaml"],
    },
}


class SigmaGeneratorAgent(BaseAgent):
    name = "SigmaGeneratorAgent"

    def __init__(self, llm: LLMClient | None = None, emit: EmitFn | None = None):
        super().__init__(emit)
        self._llm = llm
        self._system_prompt = _load_prompt()

    async def run(self, memory: Memory, **kwargs: Any) -> AgentResult:
        if not self._llm or not memory.findings:
            memory.sigma_rules = ""
            return AgentResult(data={"rules_count": 0})

        await self.emit("sigma_generating", {"content": "Generating Sigma detection rules..."})

        context = self._build_context(memory)

        try:
            resp = await self._llm.complete(
                system=self._system_prompt,
                messages=[{"role": "user", "content": context}],
                tools=[SIGMA_TOOL],
                max_tokens=4096,
            )

            if resp.tool_use:
                rules_yaml = resp.tool_use.get("rules_yaml", "")
                memory.sigma_rules = rules_yaml
                rule_count = rules_yaml.count("---") + 1 if rules_yaml.strip() else 0
                await self.emit("sigma_generated", {"rules_count": rule_count})
                return AgentResult(data={"rules_count": rule_count})

            # Fallback: use content if tool wasn't called
            if resp.content:
                memory.sigma_rules = resp.content
                rule_count = resp.content.count("---") + 1
                await self.emit("sigma_generated", {"rules_count": rule_count})
                return AgentResult(data={"rules_count": rule_count})

        except Exception as e:
            logger.warning("sigma_generation_failed", error=str(e))
            await self.emit("agent_error", {"agent_id": self.name, "message": str(e)})

        memory.sigma_rules = ""
        return AgentResult(data={"rules_count": 0})

    def _build_context(self, memory: Memory) -> str:
        parts = ["Generate Sigma detection rules for this threat intelligence analysis.\n"]

        parts.append("## Findings")
        for f in memory.findings[:10]:
            parts.append(f"- [{f.confidence}] {f.claim}")
            if f.detail:
                parts.append(f"  Detail: {f.detail[:200]}")

        if memory.iocs:
            parts.append(f"\n## IOCs ({len(memory.iocs)})")
            for ioc in memory.iocs[:15]:
                parts.append(f"- {ioc.ioc_type}: {ioc.value_defanged} [{ioc.confidence}]")

        if memory.attck_techniques:
            parts.append("\n## ATT&CK Techniques")
            for t in memory.attck_techniques:
                parts.append(f"- {t.technique_id} ({t.technique_name}) - {t.tactic} [{t.confidence}]")

        if memory.cve_refs:
            parts.append("\n## CVE References")
            for cve in memory.cve_refs:
                parts.append(f"- {cve.cve_id}: CVSS={cve.cvss_v3_score}, KEV={cve.is_in_kev}")

        return "\n".join(parts)
