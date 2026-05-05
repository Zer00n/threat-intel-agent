from __future__ import annotations

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=1000)
    tlp: str = Field(default="GREEN", pattern=r"^(WHITE|GREEN|AMBER|AMBER\+STRICT|RED)$")
    force_intent: str | None = None


class AnalyzeResponse(BaseModel):
    task_id: str
    status: str = "running"
    intent_preview: str | None = None


class StopResponse(BaseModel):
    task_id: str
    status: str


class SwitchIntentRequest(BaseModel):
    intent: str
