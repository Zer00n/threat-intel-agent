import pytest

from app.agents.llm_client import LLMResponse
from app.agents.researcher import ResearchAgent
from app.agents.memory import Memory


class FakeLLM:
    def __init__(self):
        self.calls = 0

    async def complete(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return LLMResponse(
                content="",
                tool_name="web_search",
                tool_use={"query": "CVE-2024-21413 exploitation"},
            )
        return LLMResponse(
            content="",
            tool_name="submit_findings",
            tool_use={
                "findings": [
                    {
                        "claim": "CVE-2024-21413 has public exploitation reporting.",
                        "detail": "Observed in public reporting.",
                        "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        "source_name": "CISA KEV",
                        "confidence": "High",
                    }
                ],
                "rounds_used": 2,
            },
        )


@pytest.mark.asyncio
async def test_researcher_emits_structured_agent_trace(monkeypatch):
    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    async def fake_search(self, query):
        return [
            {
                "title": "CISA KEV",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "snippet": "Known exploited vulnerabilities catalog entry.",
            }
        ]

    monkeypatch.setattr(ResearchAgent, "_mock_search", fake_search)

    agent = ResearchAgent(agent_id="R1", llm=FakeLLM(), emit=emit)
    result = await agent.run(Memory(), question="Check exploitation status")

    assert result.success is True
    trace_actions = [
        data["action"]
        for event_type, data in events
        if event_type == "agent_trace"
    ]
    assert "round_start" in trace_actions
    assert "llm_call" in trace_actions
    assert "tool_call" in trace_actions
    assert "tool_result" in trace_actions
    assert "submit_findings" in trace_actions

    tool_result = next(
        data
        for event_type, data in events
        if event_type == "agent_trace" and data["action"] == "tool_result"
    )
    assert tool_result["details"]["source_count"] == 1
    assert tool_result["details"]["results"][0]["title"] == "CISA KEV"
