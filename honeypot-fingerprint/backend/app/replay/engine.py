"""Replay engine: streams adapter events in timestamp order on a replay clock.

Replay time `t` is seconds since the replay started. Each selection maps dataset time to
replay time with an offset and an optional compression factor; event timestamps are then
shifted to "now" (`base_epoch + t`). The engine advances on a fixed step grid, so a given
plan always produces the same event sequence regardless of wall-clock speed.
"""
from __future__ import annotations

import hashlib
import heapq
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Callable, Optional

from ..adapters.catalog import load_events
from ..schemas import Event

REMAP_OCTETS = [5, 23, 31, 37, 45, 46, 62, 77, 78, 80, 85, 91, 93, 94, 103, 104, 109, 141, 154, 159,
                176, 178, 185, 188, 193, 194, 195, 212, 213, 217]


def remap_ip(ip: str, seed: int) -> str:
    """Deterministic, consistent IP remapping (same input IP -> same new IP for a seed)."""
    h = hashlib.blake2b(f"{seed}|{ip}".encode(), digest_size=8).digest()
    return f"{REMAP_OCTETS[h[0] % len(REMAP_OCTETS)]}.{h[1]}.{h[2]}.{1 + h[3] % 254}"


@dataclass
class Selection:
    source_id: str
    path: str
    adapter: Optional[str] = None
    labels: Optional[list[str]] = None
    t_from: Optional[float] = None
    t_to: Optional[float] = None
    offset: float = 0.0  # replay second at which this slice starts
    compress: float = 1.0  # dataset seconds per replay second
    max_rows: int = 50_000
    sample_every: int = 1
    remap_ips: bool = False
    remap_seed: int = 0
    label_override: Optional[str] = None
    repeat: int = 1  # loop the slice back-to-back when it is too short
    repeat_new_ips: bool = False  # each loop copy gets fresh (remapped) source IPs
    campaign_id: str = ""
    parent_campaign: Optional[str] = None
    name: str = ""
    # filled when loaded
    loaded: int = 0
    matched: int = 0
    truncated: bool = False
    replay_start: float = 0.0
    replay_end: float = 0.0
    ips: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ips"] = self.ips[:50]
        d["n_ips"] = len(self.ips)
        return d


@dataclass
class ScriptStep:
    t: float
    action: str  # narrate | set_mode | force_cluster | phase
    args: dict = field(default_factory=dict)
    done: bool = False


@dataclass
class ReplayPlan:
    name: str
    mode: str = "custom"  # custom | returning | demo
    selections: list[Selection] = field(default_factory=list)
    script: list[ScriptStep] = field(default_factory=list)
    fast_until: float = 0.0  # run as fast as possible until this replay second (warm-up)
    duration: Optional[float] = None
    note: str = ""


def loop_slice(events: list[Event], repeat: int, new_ips: bool = False) -> list[Event]:
    """Repeat a time-sorted slice back-to-back, shifting each copy by span + mean gap.
    With new_ips, every copy gets its own consistent IP remapping (used for background
    traffic so that looping does not turn a handful of hosts into periodic beacons)."""
    if repeat <= 1 or not events:
        return events
    span = events[-1].timestamp - events[0].timestamp
    period = span + (span / max(1, len(events) - 1) if span > 0 else 1.0)
    out = list(events)
    for k in range(1, repeat):
        out += [replace(e, timestamp=e.timestamp + k * period,
                        src_ip=remap_ip(e.src_ip, 10_000 + k) if new_ips else e.src_ip) for e in events]
    return out


def materialise(sel: Selection, events: list[Event]) -> list[tuple[float, Event]]:
    """Map dataset time -> replay time for a loaded slice; apply remap/override/campaign ids."""
    if not events:
        return []
    t0 = events[0].timestamp
    comp = max(1e-6, sel.compress)
    out = []
    ips = set()
    for e in events:
        rt = sel.offset + (e.timestamp - t0) / comp
        e.orig_timestamp = e.timestamp
        if sel.remap_ips:
            e.src_ip = remap_ip(e.src_ip, sel.remap_seed)
        if sel.label_override:
            e.ground_truth_label = sel.label_override
        lab = e.ground_truth_label or "unlabelled"
        e.campaign_id = sel.campaign_id or f"{sel.name or Path(sel.path).name}:{lab}"
        ips.add(e.src_ip)
        out.append((rt, e))
    sel.replay_start, sel.replay_end = out[0][0], out[-1][0]
    sel.ips = sorted(ips)
    return out


class ReplayEngine:
    STEP = 0.25  # replay seconds per step

    def __init__(self):
        self.plan: Optional[ReplayPlan] = None
        self.queue: list[tuple[float, int, Event]] = []
        self.t = 0.0
        self.end_t = 0.0
        self.state = "idle"  # idle | running | paused | finished
        self.speed = 1.0
        self.base_epoch = 0.0
        self.campaigns: dict[str, dict] = {}
        self.total_events = 0

    def load(self, plan: ReplayPlan, base_epoch: float, loader: Callable = load_events) -> None:
        self.plan = plan
        self.queue = []
        self.campaigns = {}
        n = 0
        for sel in plan.selections:
            evs, info = loader(Path(sel.path), sel.adapter, sel.labels, sel.t_from, sel.t_to,
                               sel.max_rows, sel.sample_every)
            sel.loaded, sel.matched, sel.truncated = info["loaded"], info["matched"], info["truncated"]
            evs = loop_slice(evs, sel.repeat, sel.repeat_new_ips)
            for rt, e in materialise(sel, evs):
                self.queue.append((rt, n, e))
                n += 1
                c = self.campaigns.setdefault(e.campaign_id, {
                    "campaign_id": e.campaign_id, "parent_id": sel.parent_campaign,
                    "label": e.ground_truth_label, "selection": sel.name, "ips": set(),
                    "first_t": rt, "last_t": rt, "events": 0, "remapped": sel.remap_ips})
                c["ips"].add(e.src_ip)
                c["last_t"] = rt
                c["events"] += 1
        heapq.heapify(self.queue)
        self.total_events = n
        last = max((q[0] for q in self.queue), default=0.0)
        self.end_t = max(plan.duration or 0.0, last + 15.0, max((s.t for s in plan.script), default=0.0) + 1)
        self.t = 0.0
        self.base_epoch = base_epoch
        self.state = "paused"

    def campaign_list(self) -> list[dict]:
        return [{**c, "ips": sorted(c["ips"])[:50], "n_ips": len(c["ips"]),
                 "first_ts": self.base_epoch + c["first_t"], "last_ts": self.base_epoch + c["last_t"]}
                for c in self.campaigns.values()]

    @property
    def now(self) -> float:
        return self.base_epoch + self.t

    def step(self, dt: Optional[float] = None) -> tuple[list[Event], list[ScriptStep]]:
        """Advance the clock by one step; return events due in [t, t+dt) and script steps fired."""
        dt = dt or self.STEP
        t1 = self.t + dt
        out: list[Event] = []
        while self.queue and self.queue[0][0] < t1:
            rt, _, e = heapq.heappop(self.queue)
            e.timestamp = self.base_epoch + rt
            out.append(e)
        fired = []
        if self.plan:
            for s in self.plan.script:
                if not s.done and s.t < t1:
                    s.done = True
                    fired.append(s)
        self.t = t1
        if self.t >= self.end_t:
            self.state = "finished"
        return out, fired

    def status(self) -> dict:
        return {
            "state": self.state, "t": round(self.t, 2), "end_t": round(self.end_t, 2), "speed": self.speed,
            "base_epoch": self.base_epoch, "now": self.now, "remaining_events": len(self.queue),
            "total_events": self.total_events, "plan": None if not self.plan else {
                "name": self.plan.name, "mode": self.plan.mode, "note": self.plan.note,
                "fast_until": self.plan.fast_until,
                "selections": [s.to_dict() for s in self.plan.selections],
                "script": [{"t": s.t, "action": s.action, "args": s.args, "done": s.done} for s in self.plan.script],
            },
        }
