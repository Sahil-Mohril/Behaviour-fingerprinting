"""Sources (adapters/catalog) and replay control."""
from __future__ import annotations

import threading
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ..adapters import ADAPTERS
from ..labels import behaviour_table
from ..replay.plans import PlanError, build_custom, build_demo, build_returning

router = APIRouter(prefix="/api", tags=["replay"])


def rt(request: Request):
    return request.app.state.runtime


class SelectionIn(BaseModel):
    source_id: str
    labels: Optional[list[str]] = None
    t_from: Optional[float] = None
    t_to: Optional[float] = None
    offset: float = 0.0
    compress: float = Field(1.0, gt=0)
    max_rows: int = Field(50_000, ge=1, le=500_000)
    sample_every: int = Field(1, ge=1)
    remap_ips: bool = False
    remap_seed: int = 1000
    label_override: Optional[str] = None
    repeat: int = Field(1, ge=1, le=1000)
    repeat_new_ips: bool = False


class CustomIn(BaseModel):
    name: str = "Custom mix"
    selections: list[SelectionIn]
    speed: float = 10.0
    reset_learning: bool = False


class ReturningIn(BaseModel):
    source_id: str
    label: str
    split: float = Field(0.5, ge=0.1, le=0.9)
    target_seconds: float = Field(60.0, gt=5)
    gap: float = Field(30.0, ge=0)
    include_benign: bool = True
    remap_seed: int = 7
    fast_warmup: bool = True
    speed: float = 10.0
    reset_learning: bool = False


class SpeedIn(BaseModel):
    speed: float = Field(..., gt=0, le=1000)


@router.get("/sources")
def sources(request: Request):
    r = rt(request)
    return {"status": r.catalog.status, "sources": r.catalog.list(),
            "data_dirs": [str(p) for p in r.catalog.roots],
            "adapters": [{"name": a.name, "description": a.description} for a in ADAPTERS.values()]}


@router.post("/sources/refresh")
def refresh_sources(request: Request):
    r = rt(request)
    if r.catalog.status != "indexing":
        threading.Thread(target=r.catalog.refresh, daemon=True).start()
    return {"status": "indexing"}


@router.get("/behaviours")
def behaviours():
    return behaviour_table()


def _start(request: Request, plan, speed: float, reset_learning: bool):
    r = rt(request)
    with r.lock:
        try:
            r.pipeline.start(plan, time.time(), reset_learning=reset_learning)
        except (PlanError, ValueError, FileNotFoundError) as exc:
            raise HTTPException(400, str(exc)) from exc
        r.pipeline.engine.speed = speed
        r.pipeline.engine.state = "running"
        return r.status()


@router.post("/replay/custom")
def start_custom(body: CustomIn, request: Request):
    try:
        plan = build_custom(rt(request).catalog, [s.model_dump() for s in body.selections], body.name)
    except PlanError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _start(request, plan, body.speed, body.reset_learning)


@router.post("/replay/returning")
def start_returning(body: ReturningIn, request: Request):
    try:
        plan = build_returning(rt(request).catalog, body.source_id, body.label, body.split, body.target_seconds,
                               body.gap, include_benign=body.include_benign, remap_seed=body.remap_seed,
                               fast_warmup=body.fast_warmup)
    except PlanError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _start(request, plan, body.speed, body.reset_learning)


@router.post("/replay/demo")
def start_demo(request: Request, speed: float = 1.0):
    r = rt(request)
    try:
        plan = build_demo(r.catalog)
    except PlanError as exc:
        raise HTTPException(400, str(exc)) from exc
    with r.lock:
        r.settings.rule_mode = "suggest"
    return _start(request, plan, speed, reset_learning=True)


@router.post("/replay/pause")
def pause(request: Request):
    r = rt(request)
    with r.lock:
        if r.pipeline.engine.state == "running":
            r.pipeline.engine.state = "paused"
        return r.status()


@router.post("/replay/resume")
def resume(request: Request):
    r = rt(request)
    with r.lock:
        if r.pipeline.engine.state == "paused":
            r.pipeline.engine.state = "running"
        return r.status()


@router.post("/replay/stop")
def stop(request: Request):
    r = rt(request)
    with r.lock:
        eng = r.pipeline.engine
        if eng.state in ("running", "paused"):
            eng.state = "finished"
            r.pipeline.flush_persist()
        return r.status()


@router.post("/replay/speed")
def speed(body: SpeedIn, request: Request):
    r = rt(request)
    with r.lock:
        r.pipeline.engine.speed = body.speed
        return r.status()


@router.get("/replay/status")
def status(request: Request):
    r = rt(request)
    with r.lock:
        return r.status()


@router.get("/replay/campaigns")
def campaigns(request: Request):
    r = rt(request)
    with r.lock:
        return r.pipeline.engine.campaign_list()


@router.post("/reset")
def reset(request: Request):
    r = rt(request)
    with r.lock:
        r.pipeline.engine.state = "idle"
        r.pipeline.reset_all()
        (r.pipeline.state_dir / "scaler.joblib").unlink(missing_ok=True)
        return {"ok": True}
