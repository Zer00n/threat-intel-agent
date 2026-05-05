from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

import structlog

from app.agents.memory import Memory

logger = structlog.get_logger()

EmitFn = Callable[[str, dict[str, Any]], Coroutine[Any, Any, None]]


@dataclass
class AgentResult:
    success: bool = True
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class BaseAgent(ABC):
    name: str = "base"

    def __init__(self, emit: EmitFn | None = None):
        self._emit = emit or self._noop_emit

    @abstractmethod
    async def run(self, memory: Memory, **kwargs: Any) -> AgentResult:
        ...

    async def emit(self, event_type: str, data: dict[str, Any]) -> None:
        await self._emit(event_type, data)

    @staticmethod
    async def _noop_emit(event_type: str, data: dict[str, Any]) -> None:
        pass
