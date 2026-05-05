import pytest

from app.agents.llm_client import BudgetExceededError, LLMClient, TokenUsage


class TestBudgetCheck:
    def test_within_budget(self):
        client = LLMClient.__new__(LLMClient)
        client._total_usage = TokenUsage(input_tokens=10000, output_tokens=5000)
        # Should not raise
        client.check_budget()

    def test_exceeds_budget(self):
        client = LLMClient.__new__(LLMClient)
        client._total_usage = TokenUsage(input_tokens=150000, output_tokens=60000)
        with pytest.raises(BudgetExceededError):
            client.check_budget()


class TestDefangRefang:
    def test_roundtrip(self):
        from app.utils.defang import defang, refang
        original = "1.2.3.4 evil.com http://test.com/path"
        defanged = defang(original)
        refanged = refang(defanged)
        assert "1.2.3.4" in refanged
        assert "evil.com" in refanged
