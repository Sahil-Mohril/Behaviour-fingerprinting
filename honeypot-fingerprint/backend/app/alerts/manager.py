"""Alert creation, de-duplication and severity escalation."""
from __future__ import annotations

import itertools
from dataclasses import asdict, dataclass, field
from typing import Optional

from ..labels import SEVERITIES, severity_rank

ESCALATE_AT = (10, 50)  # repeated hits that bump severity one and two levels


@dataclass
class Alert:
    id: str
    type: str  # match | returning | anomaly | new_fingerprint
    title: str
    fp_id: Optional[str]
    fp_name: str
    category: str
    severity: str
    base_severity: str
    first_seen: float
    last_seen: float
    count: int = 1
    status: str = "open"  # open | acknowledged | resolved
    ips: list = field(default_factory=list)
    entity: str = ""
    score: float = 0.0
    breakdown: dict = field(default_factory=dict)
    explanation: str = ""
    episode_id: Optional[str] = None
    rule_ids: list = field(default_factory=list)
    escalations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class AlertManager:
    def __init__(self, dedupe_seconds: float):
        self.dedupe_seconds = dedupe_seconds
        self.alerts: dict[str, Alert] = {}
        self._ids = itertools.count(1)
        self._open: dict[tuple, str] = {}
        self.dirty: set[str] = set()

    def load(self, items: list[dict]) -> None:
        for d in items:
            a = Alert(**d)
            self.alerts[a.id] = a
        nums = [int(i.split("-")[1]) for i in self.alerts if i.startswith("AL-")]
        self._ids = itertools.count(max(nums, default=0) + 1)

    def raise_(self, type_: str, title: str, fp_id: Optional[str], fp_name: str, category: str, severity: str,
               now: float, ips: list[str], entity: str = "", score: float = 0.0, breakdown: Optional[dict] = None,
               explanation: str = "", episode_id: Optional[str] = None) -> tuple[Alert, bool]:
        key = (type_, fp_id, episode_id)
        aid = self._open.get(key)
        a = self.alerts.get(aid) if aid else None
        if a and a.status != "resolved" and now - a.last_seen <= self.dedupe_seconds:
            a.count += 1
            a.last_seen = now
            for ip in ips:
                if ip not in a.ips and len(a.ips) < 200:
                    a.ips.append(ip)
            if score >= a.score:
                a.score, a.breakdown, a.explanation, a.entity = score, breakdown or a.breakdown, explanation or a.explanation, entity
            target = severity_rank(a.base_severity) + sum(1 for n in ESCALATE_AT if a.count >= n)
            target = min(target, len(SEVERITIES) - 1)
            if target > severity_rank(a.severity):
                a.escalations.append({"t": now, "from": a.severity, "to": SEVERITIES[target], "count": a.count})
                a.severity = SEVERITIES[target]
            self.dirty.add(a.id)
            return a, False
        a = Alert(id=f"AL-{next(self._ids):05d}", type=type_, title=title, fp_id=fp_id, fp_name=fp_name,
                  category=category, severity=severity, base_severity=severity, first_seen=now, last_seen=now,
                  ips=list(ips)[:200], entity=entity, score=score, breakdown=breakdown or {},
                  explanation=explanation, episode_id=episode_id)
        self.alerts[a.id] = a
        self._open[key] = a.id
        self.dirty.add(a.id)
        return a, True

    def set_status(self, aid: str, status: str) -> Optional[Alert]:
        a = self.alerts.get(aid)
        if a and status in ("open", "acknowledged", "resolved"):
            a.status = status
            self.dirty.add(a.id)
        return a

    def list(self) -> list[Alert]:
        return sorted(self.alerts.values(), key=lambda a: a.last_seen, reverse=True)
