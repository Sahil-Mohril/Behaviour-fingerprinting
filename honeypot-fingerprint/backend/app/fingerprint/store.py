"""Fingerprint model and in-memory store (persisted by the pipeline)."""
from __future__ import annotations

import itertools
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from ..features.extractor import FEATURES
from ..labels import CATEGORY_NAMES, is_benign, severity_of
from . import minhash

TOKEN_CAP = 400
MAX_VERSIONS = 30


def _nan_list(a: np.ndarray) -> list:
    return [None if (v is None or np.isnan(v)) else round(float(v), 5) for v in a]


def _arr(lst: list) -> np.ndarray:
    return np.array([np.nan if v is None else v for v in lst], dtype=float)


@dataclass
class Fingerprint:
    id: str
    name: str
    category: str
    severity: str
    confidence: float
    status: str  # active | candidate | dismissed
    centroid: np.ndarray
    spread: np.ndarray
    n_windows: int
    tokens: dict[str, Counter]
    first_seen: float
    last_seen: float
    origin: str = "cluster"
    category_reasons: list = field(default_factory=list)
    hit_count: int = 0
    ips: Counter = field(default_factory=Counter)
    asns: Counter = field(default_factory=Counter)
    countries: Counter = field(default_factory=Counter)
    episodes: list = field(default_factory=list)
    versions: list = field(default_factory=list)
    timeline: Counter = field(default_factory=Counter)  # 10 s bucket -> hits
    importance: list = field(default_factory=list)
    minhash_sig: list = field(default_factory=list)
    name_locked: bool = False
    category_locked: bool = False
    window_ids: list = field(default_factory=list)  # recent assigned window ids (for split/projection)
    notes: list = field(default_factory=list)

    @property
    def benign(self) -> bool:
        return is_benign(self.category)

    def all_tokens(self) -> list[str]:
        return [f"{f}:{t}" for f, c in self.tokens.items() for t in c]

    def add_tokens(self, toks: dict[str, set], weight: int = 1) -> None:
        for fam, ts in toks.items():
            c = self.tokens.setdefault(fam, Counter())
            for t in ts:
                c[t] += weight
            if len(c) > TOKEN_CAP:
                self.tokens[fam] = Counter(dict(c.most_common(TOKEN_CAP)))

    def refresh_signature(self) -> None:
        self.minhash_sig = [int(v) for v in minhash.signature(self.all_tokens())]

    def snapshot(self, t: float, reason: str) -> None:
        self.versions.append({"version": len(self.versions) + 1, "t": t, "reason": reason,
                              "n_windows": self.n_windows, "category": self.category,
                              "confidence": self.confidence, "centroid": _nan_list(self.centroid)})
        if len(self.versions) > MAX_VERSIONS:
            self.versions = self.versions[:1] + self.versions[-(MAX_VERSIONS - 1):]

    def current_episode(self) -> Optional[dict]:
        return self.episodes[-1] if self.episodes else None

    def summary(self) -> dict:
        ep = self.current_episode()
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "category_name": CATEGORY_NAMES.get(self.category, self.category), "severity": self.severity,
            "confidence": self.confidence, "status": self.status, "benign": self.benign, "origin": self.origin,
            "hit_count": self.hit_count, "n_windows": self.n_windows, "first_seen": self.first_seen,
            "last_seen": self.last_seen, "n_ips": len(self.ips), "episodes": len(self.episodes),
            "version": len(self.versions), "top_ips": [ip for ip, _ in self.ips.most_common(5)],
            "returning": bool(ep and ep.get("returning")),
            "top_features": self.importance[:3],
        }

    def detail(self) -> dict:
        d = self.summary()
        d.update({
            "centroid": dict(zip(FEATURES, _nan_list(self.centroid))),
            "spread": dict(zip(FEATURES, _nan_list(self.spread))),
            "importance": self.importance,
            "category_reasons": self.category_reasons,
            "traits": {f: [{"token": t, "count": n} for t, n in c.most_common(12)] for f, c in self.tokens.items()},
            "ips": [{"ip": ip, "hits": n} for ip, n in self.ips.most_common(50)],
            "asns": [{"asn": a, "hits": n} for a, n in self.asns.most_common(10)],
            "countries": [{"country": c, "hits": n} for c, n in self.countries.most_common(10)],
            "episodes": [{**{k: v for k, v in e.items() if k != "ips"}, "n_ips": len(e["ips"]),
                          "ips": sorted(e["ips"])[:20]} for e in self.episodes],
            "versions": [{k: v for k, v in ver.items() if k != "centroid"} for ver in self.versions],
            "timeline": sorted([[k, v] for k, v in self.timeline.items()])[-300:],
            "notes": self.notes[-20:],
        })
        return d

    def to_state(self) -> dict:
        return {
            "id": self.id, "name": self.name, "category": self.category, "severity": self.severity,
            "confidence": self.confidence, "status": self.status, "centroid": _nan_list(self.centroid),
            "spread": _nan_list(self.spread), "n_windows": self.n_windows,
            "tokens": {f: dict(c) for f, c in self.tokens.items()}, "first_seen": self.first_seen,
            "last_seen": self.last_seen, "origin": self.origin, "category_reasons": self.category_reasons,
            "hit_count": self.hit_count, "ips": dict(self.ips.most_common(500)), "asns": dict(self.asns),
            "countries": dict(self.countries),
            "episodes": [{**e, "ips": sorted(e["ips"])[:500]} for e in self.episodes[-50:]],
            "versions": self.versions, "timeline": {str(k): v for k, v in self.timeline.items()},
            "importance": self.importance, "minhash_sig": self.minhash_sig, "name_locked": self.name_locked,
            "category_locked": self.category_locked, "notes": self.notes[-50:],
        }

    @classmethod
    def from_state(cls, d: dict) -> "Fingerprint":
        fp = cls(id=d["id"], name=d["name"], category=d["category"], severity=d["severity"],
                 confidence=d["confidence"], status=d["status"], centroid=_arr(d["centroid"]),
                 spread=_arr(d["spread"]), n_windows=d["n_windows"],
                 tokens={f: Counter(c) for f, c in d["tokens"].items()}, first_seen=d["first_seen"],
                 last_seen=d["last_seen"], origin=d.get("origin", "cluster"),
                 category_reasons=d.get("category_reasons", []), hit_count=d.get("hit_count", 0),
                 ips=Counter(d.get("ips", {})), asns=Counter(d.get("asns", {})),
                 countries=Counter(d.get("countries", {})), versions=d.get("versions", []),
                 timeline=Counter({float(k): v for k, v in d.get("timeline", {}).items()}),
                 importance=d.get("importance", []), minhash_sig=d.get("minhash_sig", []),
                 name_locked=d.get("name_locked", False),
                 category_locked=d.get("category_locked", False), notes=d.get("notes", []))
        fp.episodes = [{**e, "ips": set(e["ips"])} for e in d.get("episodes", [])]
        return fp


class FingerprintStore:
    def __init__(self):
        self.fps: dict[str, Fingerprint] = {}
        self._ids = itertools.count(1)
        self._name_counter: Counter = Counter()
        self.dirty: set[str] = set()
        self.deleted: set[str] = set()

    def next_id(self) -> str:
        while True:
            fid = f"FP-{next(self._ids):04d}"
            if fid not in self.fps:
                return fid

    def suggest_name(self, category: str) -> str:
        base = CATEGORY_NAMES.get(category, category)
        used = {f.name for f in self.fps.values()}
        n = self._name_counter[category] + 1
        while f"{base} #{n}" in used:
            n += 1
        self._name_counter[category] = n
        return f"{base} #{n}"

    def add(self, fp: Fingerprint) -> None:
        self.fps[fp.id] = fp
        self.dirty.add(fp.id)

    def touch(self, fp: Fingerprint) -> None:
        self.dirty.add(fp.id)

    def remove(self, fid: str) -> None:
        self.fps.pop(fid, None)
        self.dirty.discard(fid)
        self.deleted.add(fid)

    def get(self, fid: str) -> Optional[Fingerprint]:
        return self.fps.get(fid)

    def by_status(self, *statuses: str) -> list[Fingerprint]:
        return [f for f in self.fps.values() if f.status in statuses]

    def load(self, states: list[dict]) -> None:
        for s in states:
            fp = Fingerprint.from_state(s)
            self.fps[fp.id] = fp
        nums = [int(f.split("-")[1]) for f in self.fps if f.startswith("FP-")]
        self._ids = itertools.count(max(nums, default=0) + 1)


def recategorise(fp: Fingerprint, result: dict) -> None:
    fp.category = result["category"]
    fp.confidence = result["confidence"]
    fp.category_reasons = result["reasons"]
    fp.severity = severity_of(fp.category)
