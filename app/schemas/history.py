from __future__ import annotations

from pydantic import BaseModel


class HistoryItem(BaseModel):
    id: str
    query: str
    intent: str | None = None
    status: str
    tlp: str
    overall_confidence: str | None = None
    token_input: int = 0
    token_output: int = 0
    cost_usd: float = 0.0
    duration_s: int | None = None
    created_at: str
    updated_at: str


class HistoryListResponse(BaseModel):
    total: int
    items: list[HistoryItem]
