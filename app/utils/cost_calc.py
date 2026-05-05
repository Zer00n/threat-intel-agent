from __future__ import annotations

MODEL_PRICING = {
    "claude-opus-4-7": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5": {"input": 0.25, "output": 1.25},
}


def calc_cost(input_tokens: int, output_tokens: int, model: str) -> float:
    pricing = MODEL_PRICING.get(model, {"input": 3.0, "output": 15.0})
    return (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000


def estimate_task_cost(model: str = "claude-opus-4-7") -> dict[str, float]:
    return {
        "planner": calc_cost(2000, 1000, model),
        "researcher_per_agent": calc_cost(2000, 1000, model),
        "ioc_extractor": calc_cost(3000, 1000, model),
        "critic": calc_cost(6000, 1000, model),
        "synthesis": calc_cost(12000, 4000, model),
    }
