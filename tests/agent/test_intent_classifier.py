import pytest

from app.agents.intent_classifier import IntentClassifier
from app.agents.memory import Memory


class TestIntentClassifier:
    def setup_method(self):
        self.classifier = IntentClassifier()
        self.memory = Memory()

    @pytest.mark.asyncio
    async def test_cve_regex(self):
        self.memory.extra["query"] = "Tell me about CVE-2024-21413"
        await self.classifier.run(self.memory)
        assert self.memory.intent.intent == "cve"
        assert "CVE-2024-21413" in self.memory.intent.entities.get("cve_ids", [])
        assert self.memory.intent.confidence == 1.0

    @pytest.mark.asyncio
    async def test_technique_regex(self):
        self.memory.extra["query"] = "Explain T1059.001"
        await self.classifier.run(self.memory)
        assert self.memory.intent.intent == "attack_technique"
        assert "T1059.001" in self.memory.intent.entities.get("technique_ids", [])

    @pytest.mark.asyncio
    async def test_cwe_regex(self):
        self.memory.extra["query"] = "What is CWE-79?"
        await self.classifier.run(self.memory)
        assert self.memory.intent.intent == "cve"
        assert "CWE-79" in self.memory.intent.entities.get("keywords", [])

    @pytest.mark.asyncio
    async def test_ip_regex(self):
        self.memory.extra["query"] = "Check reputation of 192.168.1.100"
        await self.classifier.run(self.memory)
        assert self.memory.intent.intent == "ioc_ip"

    @pytest.mark.asyncio
    async def test_hash_regex(self):
        self.memory.extra["query"] = "Analyze 5d41402abc4b2a76b9719d911017c592"
        await self.classifier.run(self.memory)
        assert self.memory.intent.intent == "ioc_hash"

    @pytest.mark.asyncio
    async def test_sha256_regex(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.memory.extra["query"] = f"Hash: {sha256}"
        await self.classifier.run(self.memory)
        assert self.memory.intent.intent == "ioc_hash"

    @pytest.mark.asyncio
    async def test_generic_fallback(self):
        self.memory.extra["query"] = "What's the latest in cybersecurity?"
        await self.classifier.run(self.memory)
        assert self.memory.intent.intent == "generic"
