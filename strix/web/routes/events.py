"""Server-Sent Events endpoint for real-time scan monitoring."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse


router = APIRouter()


@router.get("/api/scans/{run_name}/events/stream")
async def stream_events(request: Request, run_name: str) -> StreamingResponse:
    run_store = request.app.state.run_store
    events_path = run_store.get_events_path(run_name)

    async def event_generator() -> AsyncGenerator[str, None]:
        if events_path is None:
            yield "event: error\ndata: {\"message\": \"No events file found\"}\n\n"
            return

        offset = 0
        done = False

        while not done:
            if await request.is_disconnected():
                break

            try:
                file_size = events_path.stat().st_size
            except OSError:
                await asyncio.sleep(1)
                continue

            if file_size > offset:
                with events_path.open(encoding="utf-8") as f:
                    f.seek(offset)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                            evt_type = evt.get("event_type", "unknown")
                            yield f"event: {evt_type}\ndata: {line}\n\n"

                            if evt_type == "run.completed":
                                done = True
                                break
                        except json.JSONDecodeError:
                            continue
                    offset = f.tell()

            if not done:
                await asyncio.sleep(0.5)

        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
