from __future__ import annotations

import asyncio
import json
from collections import defaultdict

import structlog
from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

logger = structlog.get_logger()

router = APIRouter(tags=["stream"])

# Per-task event queues and history
_task_queues: dict[str, list[asyncio.Queue]] = defaultdict(list)
_task_events: dict[str, list[dict]] = defaultdict(list)
_task_sequences: dict[str, int] = defaultdict(int)


def create_task_queue(task_id: str) -> None:
    _task_queues[task_id] = []
    _task_events[task_id] = []
    _task_sequences[task_id] = 0


async def push_event(task_id: str, event_type: str, data: dict) -> None:
    seq = _task_sequences[task_id] + 1
    _task_sequences[task_id] = seq

    event = {"id": seq, "event": event_type, "data": data}
    _task_events[task_id].append(event)

    for q in _task_queues.get(task_id, []):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


@router.get("/stream/{task_id}")
async def stream_events(
    task_id: str,
    request: Request,
    last_event_id: int | None = Query(None, alias="last_event_id"),
):
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    _task_queues[task_id].append(queue)

    async def event_generator():
        # Replay historical events if reconnection
        if last_event_id is not None:
            for event in _task_events.get(task_id, []):
                if event["id"] > last_event_id:
                    yield _format_sse(event)
            # If task is already done, close immediately
            from app.db.models import Analysis
            from app.db.engine import async_session_factory
            async with async_session_factory() as db:
                from sqlalchemy import select
                result = await db.execute(select(Analysis).where(Analysis.id == task_id))
                analysis = result.scalar_one_or_none()
                if analysis and analysis.status != "running":
                    return

        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30)
                    yield _format_sse(event)
                    if event["event"] in ("done", "error", "stopped", "timeout", "budget_exceeded"):
                        break
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield ": keepalive\n\n"
        finally:
            if queue in _task_queues.get(task_id, []):
                _task_queues[task_id].remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def _format_sse(event: dict) -> str:
    return f"id: {event['id']}\nevent: {event['event']}\ndata: {json.dumps(event['data'], ensure_ascii=False)}\n\n"
