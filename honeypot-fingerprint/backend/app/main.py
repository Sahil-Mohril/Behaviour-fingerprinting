"""FastAPI app: REST API (/api, OpenAPI at /docs) and the live WebSocket (/ws)."""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .api import data, replay
from .config import STATE_DIR
from .db import Persistence
from .runtime import Runtime


@asynccontextmanager
async def lifespan(app: FastAPI):
    persist = None if os.environ.get("HFP_NO_DB") else Persistence(STATE_DIR / "honeypot.db")
    runtime = Runtime(persist)
    app.state.runtime = runtime
    runtime.start(asyncio.get_running_loop())
    yield
    runtime.shutdown()


app = FastAPI(
    title="Honeypot Behaviour Fingerprinting",
    version="1.0.0",
    description="Replays honeypot logs and labelled flow datasets, fingerprints behaviours, detects returning "
                "attackers and generates firewall rules (text only; enforcement is simulated in-app).",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(replay.router)
app.include_router(data.router)


@app.get("/api/health", tags=["meta"])
def health():
    return {"ok": True}


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    runtime: Runtime = websocket.app.state.runtime
    q = runtime.subscribe()
    try:
        await websocket.send_json({"type": "hello", "status": runtime.status()})
        while True:
            msg = await q.get()
            await websocket.send_json(msg)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        runtime.unsubscribe(q)
