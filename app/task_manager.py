from __future__ import annotations

import asyncio
from typing import Any


class TaskManager:
    """In-process registry of active analysis tasks."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task] = {}
        self._results: dict[str, dict[str, Any]] = {}
        self._intent_overrides: dict[str, str] = {}
        self._intent_events: dict[str, asyncio.Event] = {}

    def register(self, task_id: str, task: asyncio.Task) -> None:
        self._tasks[task_id] = task
        self._intent_events[task_id] = asyncio.Event()

    def unregister(self, task_id: str) -> None:
        self._tasks.pop(task_id, None)
        self._intent_events.pop(task_id, None)
        self._intent_overrides.pop(task_id, None)

    def is_running(self, task_id: str) -> bool:
        t = self._tasks.get(task_id)
        return t is not None and not t.done()

    def has_active_task(self) -> bool:
        return any(not t.done() for t in self._tasks.values())

    def get_task(self, task_id: str) -> asyncio.Task | None:
        return self._tasks.get(task_id)

    async def cancel(self, task_id: str) -> bool:
        t = self._tasks.get(task_id)
        if t and not t.done():
            t.cancel()
            return True
        return False

    def set_intent_override(self, task_id: str, intent: str) -> bool:
        event = self._intent_events.get(task_id)
        if event is None:
            return False
        self._intent_overrides[task_id] = intent
        event.set()
        return True

    async def wait_for_intent_override(self, task_id: str, timeout: float) -> str | None:
        event = self._intent_events.get(task_id)
        if event is None:
            return None
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        return self._intent_overrides.get(task_id)


task_manager = TaskManager()
