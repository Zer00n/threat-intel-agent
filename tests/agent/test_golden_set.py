"""Golden test set for prompt quality regression.

5 representative CVE cases with expected key fields.
These tests verify that the intent classifier and pipeline produce
the correct intent/entities for each input type.
"""
import pytest
import pytest_asyncio
from app.agents.intent_classifier import IntentClassifier
from app.agents.memory import Memory


# Golden test cases: (input_query, expected_intent, expected_entity_key, expected_entity_value)
GOLDEN_CASES = [
    {
        "id": "CVE-正则",
        "query": "分析 CVE-2024-21413 这个漏洞",
        "expected_intent": "cve",
        "expected_entities": {"cve_ids": ["CVE-2024-21413"]},
    },
    {
        "id": "ATT&CK-正则",
        "query": "T1059.001 PowerShell 攻击技术详解",
        "expected_intent": "attack_technique",
        "expected_entities": {"technique_ids": ["T1059.001"]},
    },
    {
        "id": "MD5-哈希",
        "query": "5d41402abc4b2a76b9719d911017c592 是什么",
        "expected_intent": "ioc_hash",
    },
    {
        "id": "IPv4-地址",
        "query": "查询 192.0.2.1 的威胁情报",
        "expected_intent": "ioc_ip",
    },
    {
        "id": "通用-文本",
        "query": "最近的供应链攻击趋势分析",
        "expected_intent": "generic",
    },
]


class TestGoldenIntentClassifier:
    """Verify intent classification for golden test set."""

    def setup_method(self):
        self.classifier = IntentClassifier()

    @pytest.mark.parametrize(
        "case",
        GOLDEN_CASES,
        ids=[c["id"] for c in GOLDEN_CASES],
    )
    @pytest.mark.asyncio
    async def test_golden_intent(self, case):
        memory = Memory()
        memory.extra["query"] = case["query"]

        await self.classifier.run(memory)

        assert memory.intent.intent == case["expected_intent"], (
            f"Query: '{case['query']}' → expected intent={case['expected_intent']}, "
            f"got intent={memory.intent.intent}"
        )

        if "expected_entities" in case:
            for key, expected_val in case["expected_entities"].items():
                actual = memory.intent.entities.get(key, [])
                if isinstance(expected_val, list):
                    for v in expected_val:
                        assert v in actual, f"Expected {v} in {key}, got {actual}"
