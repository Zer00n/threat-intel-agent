from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.agents.base import AgentResult, BaseAgent, EmitFn
from app.agents.llm_client import LLMClient
from app.agents.memory import Memory, ResearchPlan

PLANS_DIR = Path(__file__).parent / "plans"

PLANNER_TOOL = {
    "name": "create_research_plan",
    "description": "Create a research plan with questions to investigate and authoritative sources to query.",
    "input_schema": {
        "type": "object",
        "properties": {
            "research_questions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of specific research questions to investigate (2-5 questions)",
            },
            "authoritative_sources": {
                "type": "array",
                "items": {"type": "string", "enum": ["nvd", "kev", "epss", "ghsa", "attck"]},
            },
            "rationale": {"type": "string"},
        },
        "required": ["research_questions", "authoritative_sources", "rationale"],
    },
}

_SYSTEM_PROMPT = """You are a threat intelligence research planner.
Given the classified intent and extracted entities, create a research plan.
- Select 2-5 specific research questions to investigate
- Choose which authoritative sources to query (nvd, kev, epss, ghsa, attck)
- The plan should cover different aspects: technical details, exploitation status, mitigation, related threats"""


class PlannerAgent(BaseAgent):
    name = "PlannerAgent"

    def __init__(self, llm: LLMClient | None = None, emit: EmitFn | None = None):
        super().__init__(emit)
        self._llm = llm

    async def run(self, memory: Memory, **kwargs: Any) -> AgentResult:
        await self.emit("planning", {"content": "Creating research plan..."})

        intent = memory.intent.intent
        entities = memory.intent.entities

        # Try template first
        template = self._load_template(intent)
        if template:
            plan = self._apply_template(template, entities)
            memory.plan = plan
            await self.emit("plan_result", {
                "research_questions": plan.research_questions,
                "authoritative_sources": plan.authoritative_sources,
            })
            return AgentResult(data={"questions": len(plan.research_questions)})

        # LLM-based planning
        if not self._llm:
            plan = self._default_plan(intent, entities)
            memory.plan = plan
            return AgentResult(data={"questions": len(plan.research_questions)})

        try:
            context = f"Intent: {intent}\nEntities: {json.dumps(entities)}\nQuery: {memory.extra.get('query', '')}"
            resp = await self._llm.complete(
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": context}],
                tools=[PLANNER_TOOL],
                max_tokens=1024,
            )
            if resp.tool_use:
                plan = ResearchPlan(
                    research_questions=resp.tool_use.get("research_questions", []),
                    authoritative_sources=resp.tool_use.get("authoritative_sources", []),
                    rationale=resp.tool_use.get("rationale", ""),
                )
                memory.plan = plan
                await self.emit("plan_result", {
                    "research_questions": plan.research_questions,
                    "authoritative_sources": plan.authoritative_sources,
                })
                return AgentResult(data={"questions": len(plan.research_questions)})
        except Exception as e:
            await self.emit("agent_error", {"agent_id": self.name, "message": str(e)})

        plan = self._default_plan(intent, entities)
        memory.plan = plan
        return AgentResult(data={"questions": len(plan.research_questions)})

    def _load_template(self, intent: str) -> dict | None:
        path = PLANS_DIR / f"{intent}.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return None

    def _apply_template(self, template: dict, entities: dict) -> ResearchPlan:
        questions = template.get("research_questions", [])
        # Substitute entities into questions
        cve_ids = entities.get("cve_ids", [])
        technique_ids = entities.get("technique_ids", [])
        actor_names = entities.get("actor_names", [])
        malware_names = entities.get("malware_names", [])

        substituted = []
        for q in questions:
            q = q.replace("{cve_id}", cve_ids[0] if cve_ids else "N/A")
            q = q.replace("{technique_id}", technique_ids[0] if technique_ids else "N/A")
            q = q.replace("{actor_name}", actor_names[0] if actor_names else "N/A")
            q = q.replace("{malware_name}", malware_names[0] if malware_names else "N/A")
            substituted.append(q)

        return ResearchPlan(
            research_questions=substituted,
            authoritative_sources=template.get("authoritative_sources", []),
            rationale=template.get("rationale", "template-based plan"),
        )

    def _default_plan(self, intent: str, entities: dict) -> ResearchPlan:
        return ResearchPlan(
            research_questions=[f"Research details about {intent} query"],
            authoritative_sources=["nvd", "kev", "epss"] if intent == "cve" else ["attck"],
            rationale="default plan (no template, no LLM)",
        )
