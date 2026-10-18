"""Background replay thread + WebSocket fan-out.

The replay runs in its own thread so API handlers stay responsive. All pipeline access
goes through `runtime.lock`. Every ~250 ms a batched "tick" message is pushed to every
WebSocket subscriber (UI updates are batched, never per event).
"""
from __future__ import annotations

import asyncio
import threading
import time
from typing import Optional

from .adapters.catalog import Catalog
from .config import DATA_DIR, FIXTURE_DIR, STATE_DIR, Settings
from .db import Persistence
from .pipeline import Pipeline

TICK_SECONDS = 0.25
STEP_BUDGET = 0.12  # max real seconds of pipeline work per loop iteration
MAX_LAG = 5.0  # replay seconds; beyond this the clock slips (effective speed drops)


class Runtime:
    def __init__(self, persist: Optional[Persistence] = None, data_dirs=None, state_dir=STATE_DIR):
        self.settings = Settings()
        self.persist = persist
        self.pipeline = Pipeline(self.settings, persist, state_dir)
        self.pipeline.load_persisted()
        self.catalog = Catalog(data_dirs or [DATA_DIR, FIXTURE_DIR], state_dir / "catalog.json")
        self.lock = threading.RLock()
        self.subscribers: set[asyncio.Queue] = set()
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.effective_speed = 0.0
        self._debt = 0.0

    # ------------------------------------------------------------- lifecycle
    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        threading.Thread(target=self.catalog.refresh, daemon=True, name="catalog").start()
        self._thread = threading.Thread(target=self._run, daemon=True, name="replay")
        self._thread.start()

    def shutdown(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        with self.lock:
            if self.persist:
                self.pipeline.flush_persist()
                self.persist.flush_all()

    def _run(self) -> None:
        last = time.monotonic()
        last_tick = last
        replay_mark, real_mark = 0.0, last
        while not self._stop.is_set():
            now = time.monotonic()
            dt = now - last
            last = now
            with self.lock:
                eng = self.pipeline.engine
                if eng.state == "running":
                    plan = eng.plan
                    t0 = time.monotonic()
                    if plan and eng.t < plan.fast_until:
                        while eng.state == "running" and eng.t < plan.fast_until and time.monotonic() - t0 < STEP_BUDGET:
                            self.pipeline.step()
                        self._debt = 0.0
                    else:
                        self._debt = min(self._debt + dt * eng.speed, MAX_LAG)
                        while self._debt >= eng.STEP and eng.state == "running" and time.monotonic() - t0 < STEP_BUDGET:
                            self.pipeline.step()
                            self._debt -= eng.STEP
                if eng.t < replay_mark:  # a new plan restarted the replay clock
                    replay_mark, real_mark = eng.t, now
                if now - real_mark >= 1.0:
                    self.effective_speed = round((eng.t - replay_mark) / (now - real_mark), 2)
                    replay_mark, real_mark = eng.t, now
            if now - last_tick >= TICK_SECONDS:
                last_tick = now
                self._broadcast(self.tick_message())
            time.sleep(0.01)

    # ----------------------------------------------------------------- ws hub
    def tick_message(self) -> dict:
        with self.lock:
            p = self.pipeline
            out = p.drain()
            return {
                "type": "tick",
                "status": self.status(),
                "kpis": p.kpis(),
                "series": p.series_list(8),
                "events": out["events"][-150:],
                "alerts": list(out["alerts"].values()),
                "fingerprints": list(out["fingerprints"].values()),
                "rules": list(out["rules"].values()),
                "narration": out["narration"],
                "markers": out["markers"],
            }

    def status(self) -> dict:
        st = self.pipeline.engine.status()
        st["effective_speed"] = self.effective_speed
        st["catalog_status"] = self.catalog.status
        return st

    def _broadcast(self, msg: dict) -> None:
        if not self.loop or not self.subscribers:
            return
        for q in list(self.subscribers):
            self.loop.call_soon_threadsafe(_offer, q, msg)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=50)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)


def _offer(q: asyncio.Queue, msg: dict) -> None:
    if q.full():
        try:
            q.get_nowait()  # drop the oldest tick for slow clients
        except asyncio.QueueEmpty:
            pass
    q.put_nowait(msg)
