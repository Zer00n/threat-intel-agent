from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

from app.agents.base import AgentResult, BaseAgent, EmitFn
from app.agents.llm_client import LLMClient
from app.agents.memory import CriticResult, Memory
from app.utils.attck_loader import validate_technique_id

logger = structlog.get_logger()

_PROMPT_FILE = Path(__file__).parent / "prompts" / "critic.md"


def _load_prompt() -> str:
    if _PROMPT_FILE.exists():
        return _PROMPT_FILE.read_text(encoding="utf-8")
    logger.warning("critic_prompt_file_missing", path=str(_PROMPT_FILE))
    return (
        "You are a quality assurance reviewer for threat intelligence reports. "
        "Review findings for: missing sources, conflicting facts, invalid ATT&CK IDs, low confidence. "
        "Provide an overall quality assessment: High, Medium, or Low. "
        "Call the submit_review tool with your result."
    )

CRITIC_TOOL = {
    "name": "submit_review",
    "description": "Submit the critic review with issues and recommended actions.",
    "input_schema": {
        "type": "object",
        "properties": {
            "issues": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": [
                                "missing_source",
                                "conflict",
                                "invalid_attck",
                                "low_confidence",
                                "overclaim",
                                "fabricated_ioc",
                                "invalid_cve_format",
                                "missing_field",
                                "prompt_injection",
                                "victim_asset_leak",
                            ],
                        },
                        "finding_id": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    "required": ["type", "description"],
                },
            },
            "actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "drop",
                                "downgrade_confidence",
                                "flag_in_report",
                                "override_with_source",
                                "trigger_research_iteration",
                                "require_human_review",
                            ],
                        },
                        "target_id": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                    "required": ["action", "reason"],
                },
            },
            "overall_assessment": {"type": "string", "enum": ["High", "Medium", "Low"]},
        },
        "required": ["overall_assessment"],
    },
}

_SYSTEM_PROMPT = ""  # kept for backward-compat; actual prompt loaded from file


class CriticAgent(BaseAgent):
    name = "CriticAgent"

    def __init__(self, llm: LLMClient | None = None, emit: EmitFn | None = None):
        super().__init__(emit)
        self._llm = llm
        self._system_prompt = _load_prompt()

    async def run(self, memory: Memory, **kwargs: Any) -> AgentResult:
        await self.emit("critic_review", {"content": "Reviewing findings quality..."})

        # Rule-based checks first
        issues = self._rule_based_checks(memory)

        # Validate ATT&CK technique IDs
        for tech in memory.attck_techniques:
            if not validate_technique_id(tech.technique_id):
                issues.append({
                    "type": "invalid_attck",
                    "description": f"Technique {tech.technique_id} not found in ATT&CK bundle",
                })

        # LLM-based review (optional)
        assessment = "Medium"
        if self._llm and memory.findings:
            try:
                llm_result = await self._llm_review(memory)
                issues.extend(llm_result.get("issues", []))
                assessment = llm_result.get("overall_assessment", "Medium")
            except Exception:
                pass
        else:
            # Simple rule-based assessment
            high_count = sum(1 for f in memory.findings if f.confidence == "High")
            total = len(memory.findings) or 1
            if high_count / total > 0.7:
                assessment = "High"
            elif high_count / total < 0.3:
                assessment = "Low"

        memory.critic_result = CriticResult(
            issues=issues,
            overall_assessment=assessment,
        )

        await self.emit("critic_done", {
            "issues_count": len(issues),
            "overall_confidence": assessment,
        })
        return AgentResult(data={"issues": len(issues), "assessment": assessment})

    def _rule_based_checks(self, memory: Memory) -> list[dict[str, Any]]:
        issues = []

        for f in memory.findings:
            if not f.source_url:
                issues.append({
                    "type": "missing_source",
                    "finding_id": f.id,
                    "description": f"Finding '{f.claim[:60]}...' has no source URL",
                })
            if f.confidence == "Low":
                issues.append({
                    "type": "low_confidence",
                    "finding_id": f.id,
                    "description": f"Low confidence finding: {f.claim[:60]}",
                })

        return issues

    async def _llm_review(self, memory: Memory) -> dict:
        findings_text = "\n".join(
            f"- [{f.confidence}] {f.claim} (source: {f.source_url or 'MISSING'})"
            for f in memory.findings
        )
        context = f"Findings to review:\n{findings_text}"

        if memory.cve_refs:
            context += "\n\nAuthoritative data:"
            for cve in memory.cve_refs:
                context += f"\n- {cve.cve_id}: CVSS={cve.cvss_v3_score}, KEV={cve.is_in_kev}"

        resp = await self._llm.complete(
            system=self._system_prompt,
            messages=[{"role": "user", "content": context}],
            tools=[CRITIC_TOOL],
            max_tokens=2048,
        )
        if resp.tool_use:
            return resp.tool_use
        return {"overall_assessment": "Medium", "issues": []}
