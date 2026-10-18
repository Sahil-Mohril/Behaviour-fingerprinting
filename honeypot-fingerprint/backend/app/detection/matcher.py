"""Live matching of window vectors against fingerprints, anomaly candidates and episodes.

Episodes: consecutive activity of one fingerprint separated by < `episode_gap_seconds`.
A new episode whose source IPs are disjoint from every earlier episode of the same
fingerprint is a *returning behaviour*: the same behaviour is back from new sources.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from ..config import Settings
from ..features.extractor import WindowVector
from ..fingerprint.builder import Buffered, FingerprintEngine
from ..fingerprint.similarity import explain_categorical, numeric_explain
from ..fingerprint.store import Fingerprint
from ..labels import CATEGORY_NAMES, UNKNOWN
from .anomaly import AnomalyModel

MAX_NEW_CANDIDATES_PER_HOP = 3


@dataclass
class Detection:
    window: WindowVector
    kind: str  # match | anomaly | none
    fp: Optional[Fingerprint] = None
    score: float = 0.0
    numeric: float = 0.0
    categorical: Optional[float] = None
    anomaly_score: float = 0.0
    episode: Optional[dict] = None
    new_episode: bool = False
    returning: bool = False
    explanation: dict = field(default_factory=dict)

    @property
    def category(self) -> str:
        if self.kind == "match" and self.fp:
            return self.fp.category
        if self.kind == "anomaly":
            return UNKNOWN
        return "unmatched"


def touch_episode(fp: Fingerprint, ips: set[str], start: float, now: float, gap: float) -> tuple[dict, bool]:
    ep = fp.current_episode()
    if ep and now - ep["end"] <= gap:
        ep["ips"] |= ips
        ep["end"] = now
        ep["hits"] += 1
        return ep, False
    prior: set[str] = set()
    for e in fp.episodes:
        prior |= e["ips"]
    new = {"id": f"{fp.id}/E{len(fp.episodes) + 1}", "start": start, "end": now, "ips": set(ips), "hits": 1,
           "returning": bool(fp.episodes) and not (ips & prior), "repeat_sources": bool(ips & prior)}
    fp.episodes.append(new)
    return new, True


def explain_text(d: Detection, w_num: float, w_cat: float) -> str:
    fp = d.fp
    parts = [f"{d.window.entity} matched {fp.id} '{fp.name}' with score {d.score:.2f}"]
    if d.categorical is None:
        parts.append(f"= cosine {d.numeric:.2f} (no categorical traits observable in this window)")
    else:
        parts.append(f"= {w_num:.2f}x{d.numeric:.2f} (numeric cosine) + {w_cat:.2f}x{d.categorical:.2f} (trait containment)")
    top = d.explanation.get("numeric", {}).get("top_shared", [])[:3]
    if top:
        parts.append("strongest shared features: " + ", ".join(f"{t['feature']} (z {t['live_z']:+.1f} vs {t['fp_z']:+.1f})" for t in top))
    shared = d.explanation.get("categorical", {}).get("shared", [])[:4]
    if shared:
        parts.append("known traits: " + ", ".join(shared))
    return "; ".join(parts) + "."


class LiveMatcher:
    def __init__(self, settings: Settings, engine: FingerprintEngine, anomaly: AnomalyModel):
        self.settings = settings
        self.engine = engine
        self.anomaly = anomaly

    def process(self, windows: list[WindowVector], now: float) -> list[Detection]:
        if not windows:
            return []
        s = self.settings
        eng = self.engine
        Z = eng.scaler.transform(np.vstack([w.x for w in windows]))
        active = eng.store.by_status("active")
        out: list[Detection] = []
        best_idx = best_sc = None
        if active:
            comb, num, cats = eng.score(Z, [w.tokens for w in windows], active)
            best_idx = np.argmax(comb, axis=1)
            best_sc = comb[np.arange(len(windows)), best_idx]
        an_scores = self.anomaly.scores(Z) if self.anomaly.ready else np.zeros(len(windows))
        new_cands = 0
        for i, w in enumerate(windows):
            d = Detection(window=w, kind="none", anomaly_score=float(an_scores[i]))
            if best_idx is not None and best_sc[i] >= s.similarity_threshold:
                j = int(best_idx[i])
                fp = active[j]
                c, per = cats[i][j]
                d.kind, d.fp, d.score, d.numeric, d.categorical = "match", fp, float(best_sc[i]), float(num[i, j]), c
                d.explanation = {
                    "weights": {"numeric": s.weight_numeric, "categorical": s.weight_categorical},
                    "numeric": numeric_explain(Z[i], eng.scaler.transform(fp.centroid[None, :])[0]),
                    "categorical": explain_categorical(w.tokens, fp.tokens, per) if c is not None else None,
                    "threshold": s.similarity_threshold,
                }
                d.explanation["text"] = explain_text(d, s.weight_numeric, s.weight_categorical)
                self._record_hit(d, now)
                eng.remember(Buffered(w, fp=fp.id, score=d.score))
            elif self.anomaly.ready and an_scores[i] < 0:
                d.kind = "anomaly"
                b = Buffered(w, anomaly=True)
                eng.remember(b)
                d.fp, created = self._candidate(b, Z[i], now, allow_new=new_cands < MAX_NEW_CANDIDATES_PER_HOP)
                new_cands += int(created)
                d.explanation = {"text": f"{w.entity} is outside the baseline (isolation score {an_scores[i]:.3f}) "
                                         f"and matches no active fingerprint"
                                         + (f"; grouped into candidate {d.fp.id}" if d.fp else "") + "."}
            else:
                if best_sc is not None:
                    d.score = float(best_sc[i])
                eng.remember(Buffered(w))
            out.append(d)
        return out

    def _record_hit(self, d: Detection, now: float) -> None:
        fp, w = d.fp, d.window
        fp.hit_count += 1
        fp.last_seen = now
        fp.ips.update(w.ips)
        fp.timeline[int(now // 10) * 10] += 1
        if len(fp.ips) > 2000:
            fp.ips = type(fp.ips)(dict(fp.ips.most_common(1000)))
        d.episode, d.new_episode = touch_episode(fp, set(w.ips), w.t_start, now, self.settings.episode_gap_seconds)
        d.returning = d.new_episode and d.episode["returning"]
        self.engine.absorb_live(fp, w)
        self.engine.store.touch(fp)

    def _candidate(self, b: Buffered, z: np.ndarray, now: float, allow_new: bool) -> tuple[Optional[Fingerprint], bool]:
        eng = self.engine
        cands = eng.store.by_status("candidate", "dismissed")
        if cands:
            comb, _, _ = eng.score(z[None, :], [b.w.tokens], cands)
            j = int(np.argmax(comb[0]))
            if comb[0, j] >= self.settings.similarity_threshold - 0.1:
                fp = cands[j]
                if fp.status == "candidate":
                    eng.update(fp, [b], now, "anomalous window added")
                    b.fp = None  # stay available to clustering
                    fp.hit_count += 1
                    fp.ips.update(b.w.ips)
                return fp, False
        if not allow_new:
            return None, False
        fp = eng.create([b], now, "anomaly", "candidate")
        fp.hit_count = 1
        fp.ips.update(b.w.ips)
        fp.name = f"Candidate: {CATEGORY_NAMES.get(fp.category, fp.category)} ({fp.id})"
        b.fp = None
        return fp, True
