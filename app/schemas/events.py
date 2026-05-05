from __future__ import annotations

from pydantic import BaseModel


class SSEEvent(BaseModel):
    id: int
    event: str
    data: dict
