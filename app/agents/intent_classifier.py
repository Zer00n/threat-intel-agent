from __future__ import annotations

import json
import re
from typing import Any

from app.agents.base import AgentResult, BaseAgent, EmitFn
from app.agents.llm_client import LLMClient
from app.agents.memory import IntentResult, Memory

INTENT_TOOL = {
    "name": "classify_intent",
    "description": "Classify the user's threat intelligence query into an intent category with extracted entities.",
    "input_schema": {
        "type": "object",
        "properties": {
            "intent": {
                "type": "string",
                "enum": ["cve", "attack_technique", "threat_actor", "malware", "vulnerability_generic", "incident_description", "generic"],
            },
            "entities": {
                "type": "object",
                "properties": {
                    "cve_ids": {"type": "array", "items": {"type": "string"}},
                    "technique_ids": {"type": "array", "items": {"type": "string"}},
                    "actor_names": {"type": "array", "items": {"type": "string"}},
                    "malware_names": {"type": "array", "items": {"type": "string"}},
                    "keywords": {"type": "array", "items": {"type": "string"}},
                },
            },
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "reasoning_brief": {"type": "string"},
        },
        "required": ["intent", "entities", "confidence", "reasoning_brief"],
    },
}

# Regex patterns for fast-path classification
_PATTERNS = {
    "cve": re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    "attack_technique": re.compile(r"T\d{4}(?:\.\d{3})?"),
    "cwe": re.compile(r"CWE-\d{1,4}", re.IGNORECASE),
    "ioc_hash_md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "ioc_hash_sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "ioc_hash_sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "ioc_ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    ),
    "ioc_domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "cpe": re.compile(r"cpe:2\.3:", re.IGNORECASE),
}

_SYSTEM_PROMPT = """You are an intent classifier for a threat intelligence research system.
Classify the user's query into one of: cve, attack_technique, threat_actor, malware, vulnerability_generic, incident_description, generic.
Extract relevant entities (CVE IDs, technique IDs, actor names, malware names, keywords).
Assign a confidence score (0-1) and provide a brief reasoning."""


class IntentClassifier(BaseAgent):
    name = "IntentClassifier"

    def __init__(self, llm: LLMClient | None = None, emit: EmitFn | None = None):
        super().__init__(emit)
        self._llm = llm

    async def run(self, memory: Memory, **kwargs: Any) -> AgentResult:
        query = memory.extra.get("query", "")
        await self.emit("intent_classifying", {"content": f"Classifying intent for: {query[:100]}"})

        # Fast path: regex matching
        regex_result = self._regex_match(query)
        if regex_result:
            memory.intent = regex_result
            await self.emit("intent_classified", {
                "intent": regex_result.intent,
                "entities": regex_result.entities,
                "confidence": regex_result.confidence,
                "reasoning_brief": regex_result.reasoning_brief,
            })
            return AgentResult(data={"intent": regex_result.intent})

        # Slow path: LLM classification
        if not self._llm:
            memory.intent = IntentResult(intent="generic", confidence=0.5, reasoning_brief="no LLM client")
            return AgentResult(data={"intent": "generic"})

        try:
            resp = await self._llm.complete(
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": query}],
                tools=[INTENT_TOOL],
                max_tokens=1024,
            )
            if resp.tool_use:
                intent = resp.tool_use.get("intent", "generic")
                entities = resp.tool_use.get("entities", {})
                confidence = resp.tool_use.get("confidence", 0.5)
                reasoning = resp.tool_use.get("reasoning_brief", "")
                memory.intent = IntentResult(
                    intent=intent, entities=entities, confidence=confidence, reasoning_brief=reasoning,
                )
                await self.emit("intent_classified", {
                    "intent": intent, "entities": entities,
                    "confidence": confidence, "reasoning_brief": reasoning,
                })
                return AgentResult(data={"intent": intent})
        except Exception as e:
            await self.emit("agent_error", {"agent_id": self.name, "message": str(e)})

        memory.intent = IntentResult(intent="generic", confidence=0.3, reasoning_brief="classification failed")
        return AgentResult(data={"intent": "generic"})

    def _regex_match(self, query: str) -> IntentResult | None:
        # Priority order as per PRD
        m = _PATTERNS["cve"].search(query)
        if m:
            return IntentResult(
                intent="cve",
                entities={"cve_ids": [m.group().upper()]},
                confidence=1.0,
                reasoning_brief="regex match",
            )

        m = _PATTERNS["attack_technique"].search(query)
        if m:
            return IntentResult(
                intent="attack_technique",
                entities={"technique_ids": [m.group()]},
                confidence=1.0,
                reasoning_brief="regex match",
            )

        m = _PATTERNS["cwe"].search(query)
        if m:
            return IntentResult(
                intent="cve",
                entities={"cve_ids": [], "keywords": [m.group()]},
                confidence=0.8,
                reasoning_brief="CWE reference treated as vulnerability query",
            )

        for hash_type in ["ioc_hash_sha256", "ioc_hash_sha1", "ioc_hash_md5"]:
            m = _PATTERNS[hash_type].search(query)
            if m:
                return IntentResult(
                    intent="ioc_hash",
                    entities={"iocs": [m.group()]},
                    confidence=1.0,
                    reasoning_brief="regex match",
                )

        m = _PATTERNS["ioc_ip"].search(query)
        if m:
            return IntentResult(
                intent="ioc_ip",
                entities={"iocs": [m.group()]},
                confidence=1.0,
                reasoning_brief="regex match",
            )

        m = _PATTERNS["cpe"].search(query)
        if m:
            return IntentResult(
                intent="cve",
                entities={"cpe": query.strip()},
                confidence=0.9,
                reasoning_brief="CPE reference",
            )

        return None
