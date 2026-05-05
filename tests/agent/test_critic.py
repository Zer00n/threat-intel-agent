import pytest

from app.agents.critic import CriticAgent
from app.agents.memory import AttckMapping, Finding, Memory


class TestCriticAgent:
    def setup_method(self):
        self.agent = CriticAgent()
        self.memory = Memory()

    @pytest.mark.asyncio
    async def test_missing_source_detection(self):
        self.memory.findings = [
            Finding(id="f1", claim="Test finding", source_url="", confidence="Medium"),
            Finding(id="f2", claim="Good finding", source_url="https://example.com", confidence="High"),
        ]
        result = await self.agent.run(self.memory)
        assert result.success is True
        issues = self.memory.critic_result.issues
        assert any(i["type"] == "missing_source" for i in issues)

    @pytest.mark.asyncio
    async def test_low_confidence_detection(self):
        self.memory.findings = [
            Finding(id="f1", claim="Low confidence", source_url="https://x.com", confidence="Low"),
        ]
        await self.agent.run(self.memory)
        issues = self.memory.critic_result.issues
        assert any(i["type"] == "low_confidence" for i in issues)

    @pytest.mark.asyncio
    async def test_invalid_attck_detection(self):
        self.memory.attck_techniques = [
            AttckMapping(technique_id="T9999", technique_name="Fake", confidence="Medium"),
        ]
        await self.agent.run(self.memory)
        issues = self.memory.critic_result.issues
        assert any(i["type"] == "invalid_attck" for i in issues)

    @pytest.mark.asyncio
    async def test_assessment_high(self):
        self.memory.findings = [
            Finding(id="f1", claim="Fact 1", source_url="https://nvd.nist.gov", confidence="High"),
            Finding(id="f2", claim="Fact 2", source_url="https://cisa.gov", confidence="High"),
            Finding(id="f3", claim="Fact 3", source_url="https://microsoft.com", confidence="High"),
        ]
        await self.agent.run(self.memory)
        assert self.memory.critic_result.overall_assessment == "High"

    @pytest.mark.asyncio
    async def test_assessment_low(self):
        self.memory.findings = [
            Finding(id="f1", claim="Guess", source_url="", confidence="Low"),
            Finding(id="f2", claim="Another guess", source_url="", confidence="Low"),
        ]
        await self.agent.run(self.memory)
        assert self.memory.critic_result.overall_assessment == "Low"
