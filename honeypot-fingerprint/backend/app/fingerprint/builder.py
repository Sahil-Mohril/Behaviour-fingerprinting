"""Unsupervised fingerprint building (HDBSCAN) plus fingerprint maintenance.

Why HDBSCAN rather than DBSCAN: the behaviours we see have very different densities. A
flood produces many near-identical windows, a brute force a moderate stream, a scan only a
handful. DBSCAN's single global `eps` either merges the sparse groups or shatters the dense
ones. HDBSCAN builds the density hierarchy and keeps the most stable clusters at any
density, needs no `k`, and labels leftovers as noise. Those leftovers stay unassigned
(and can become anomaly candidates) instead of being forced into a cluster.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Optional

import numpy as np
from sklearn.cluster import HDBSCAN, KMeans

from ..config import Settings
from ..features.extractor import FEATURES, WindowVector
from .categorizer import categorize
from .scaler import BaselineScaler
from .similarity import combine, containment, cosine_matrix
from .store import Fingerprint, FingerprintStore, recategorise


@dataclass
class Buffered:
    w: WindowVector
    fp: Optional[str] = None
    anomaly: bool = False
    score: float = 0.0


def _nanmean(X: np.ndarray) -> np.ndarray:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=RuntimeWarning)
        return np.nanmean(X, axis=0)


def _nanstd(X: np.ndarray) -> np.ndarray:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=RuntimeWarning)
        return np.nanstd(X, axis=0)


def _blend(old: np.ndarray, new: np.ndarray, w_old: float, w_new: float) -> np.ndarray:
    out = (old * w_old + new * w_new) / (w_old + w_new)
    out = np.where(np.isnan(old), new, out)
    return np.where(np.isnan(new), old, out)


class FingerprintEngine:
    def __init__(self, settings: Settings, store: FingerprintStore, scaler: BaselineScaler):
        self.settings = settings
        self.store = store
        self.scaler = scaler
        self.buffer: list[Buffered] = []

    # ---------------------------------------------------------------- buffer
    def remember(self, b: Buffered) -> None:
        self.buffer.append(b)
        cap = self.settings.cluster_buffer_size
        if len(self.buffer) > cap:
            # drop the oldest assigned windows first, keep unassigned evidence longer
            excess = len(self.buffer) - cap
            keep = []
            for x in self.buffer:
                if excess and x.fp is not None:
                    excess -= 1
                    continue
                keep.append(x)
            self.buffer = keep[-cap:]

    # ------------------------------------------------------------ similarity
    def fp_matrix(self, fps: list[Fingerprint]) -> np.ndarray:
        return self.scaler.transform(np.vstack([f.centroid for f in fps]))

    def score(self, Z: np.ndarray, windows_tokens: list[dict], fps: list[Fingerprint]) -> tuple:
        """Return (combined, numeric, categorical(list of (score, per_family)) ) matrices."""
        F = self.fp_matrix(fps)
        num = cosine_matrix(Z, F)
        s = self.settings
        comb = np.zeros_like(num)
        cats = []
        for i, toks in enumerate(windows_tokens):
            row = []
            for j, fp in enumerate(fps):
                c, per = containment(toks, fp.tokens)
                row.append((c, per))
                comb[i, j] = combine(num[i, j], c, s.weight_numeric, s.weight_categorical)
            cats.append(row)
        return comb, num, cats

    # ------------------------------------------------------- fp maintenance
    def importance(self, fp: Fingerprint, top: int = 8) -> list[dict]:
        z = self.scaler.baseline_z(fp.centroid)
        base = self.scaler.baseline_mean_ if self.scaler.baseline_mean_ is not None else np.zeros(len(FEATURES))
        order = np.argsort(-np.abs(z))
        return [{"feature": FEATURES[i], "z": round(float(z[i]), 2),
                 "value": None if np.isnan(fp.centroid[i]) else round(float(fp.centroid[i]), 4),
                 "baseline": round(float(base[i]), 4)} for i in order[:top] if abs(z[i]) > 0.3]

    def classify(self, fp: Fingerprint) -> None:
        if not fp.category_locked:
            recategorise(fp, categorize(fp.centroid, self.scaler.baseline_z(fp.centroid)))
        fp.importance = self.importance(fp)

    def create(self, members: list[Buffered], now: float, origin: str, status: str) -> Fingerprint:
        X = np.vstack([m.w.x for m in members])
        fp = Fingerprint(id=self.store.next_id(), name="", category="", severity="info", confidence=0.0,
                         status=status, centroid=_nanmean(X), spread=_nanstd(X), n_windows=len(members),
                         tokens={}, first_seen=min(m.w.t_start for m in members), last_seen=now, origin=origin)
        for m in members:
            fp.add_tokens(m.w.tokens)
            fp.window_ids.append(m.w.id)
        self.classify(fp)
        fp.name = self.store.suggest_name(fp.category)
        fp.refresh_signature()
        fp.snapshot(now, f"created from {len(members)} windows ({origin})")
        self.store.add(fp)
        for m in members:
            m.fp = fp.id
        return fp

    def update(self, fp: Fingerprint, members: list[Buffered], now: float, reason: str) -> None:
        X = np.vstack([m.w.x for m in members])
        w_old = min(fp.n_windows, 200)
        fp.centroid = _blend(fp.centroid, _nanmean(X), w_old, len(members))
        fp.spread = _blend(fp.spread, _nanstd(X), w_old, len(members))
        fp.n_windows += len(members)
        fp.last_seen = max(fp.last_seen, now)
        for m in members:
            fp.add_tokens(m.w.tokens)
            m.fp = fp.id
            fp.window_ids.append(m.w.id)
        fp.window_ids = fp.window_ids[-500:]
        old_cat = fp.category
        self.classify(fp)
        if old_cat != fp.category and not fp.name_locked:
            fp.name = self.store.suggest_name(fp.category)
        fp.refresh_signature()
        fp.snapshot(now, reason)
        self.store.touch(fp)

    def absorb_live(self, fp: Fingerprint, w: WindowVector, alpha: float = 0.02) -> None:
        """A live match nudges the fingerprint (it keeps learning as evidence arrives)."""
        fp.centroid = _blend(fp.centroid, w.x, 1 - alpha, alpha)
        fp.add_tokens(w.tokens)
        fp.window_ids.append(w.id)
        if len(fp.window_ids) > 500:
            fp.window_ids = fp.window_ids[-500:]

    # ------------------------------------------------------------- clustering
    def cluster(self, now: float, force: bool = False) -> list[tuple[Fingerprint, str]]:
        s = self.settings
        changes: list[tuple[Fingerprint, str]] = self._recategorise_drifted(now)
        unassigned = [b for b in self.buffer if b.fp is None]
        if len(unassigned) < s.min_cluster_size:
            return changes
        all_x = np.vstack([b.w.x for b in self.buffer])
        self.scaler.fit_scale(all_x)
        changes += self._absorb_leftovers(unassigned, now)
        unassigned = [b for b in unassigned if b.fp is None]
        if len(unassigned) < s.min_cluster_size:
            return changes
        Z = self.scaler.transform(np.vstack([b.w.x for b in unassigned]))
        labels = HDBSCAN(min_cluster_size=s.min_cluster_size, min_samples=min(s.min_samples, s.min_cluster_size),
                         allow_single_cluster=True).fit_predict(Z)
        for lab in sorted(set(labels) - {-1}):
            members = [unassigned[i] for i in np.where(labels == lab)[0]]
            changes.extend(self._place_cluster(members, now))
        return changes

    def _absorb_leftovers(self, unassigned: list[Buffered], now: float) -> list[tuple[Fingerprint, str]]:
        """Windows seen before a fingerprint existed are re-matched before clustering, so they
        join that fingerprint instead of seeding a mixed cluster with newer behaviour."""
        active = self.store.by_status("active")
        if not active:
            return []
        Z = self.scaler.transform(np.vstack([b.w.x for b in unassigned]))
        comb, _, _ = self.score(Z, [b.w.tokens for b in unassigned], active)
        best = np.argmax(comb, axis=1)
        groups: dict[int, list[Buffered]] = {}
        for i, b in enumerate(unassigned):
            if comb[i, best[i]] >= self.settings.similarity_threshold:
                groups.setdefault(int(best[i]), []).append(b)
        out = []
        for j, members in groups.items():
            self.update(active[j], members, now, f"absorbed {len(members)} earlier unmatched windows")
            out.append((active[j], "updated"))
        return out

    def _recategorise_drifted(self, now: float) -> list[tuple[Fingerprint, str]]:
        out = []
        for fp in self.store.by_status("active", "candidate"):
            old = fp.category
            self.classify(fp)
            if fp.category != old:
                fp.notes.append(f"re-categorised {old} -> {fp.category} as evidence accumulated")
                if not fp.name_locked:
                    fp.name = self.store.suggest_name(fp.category)
                fp.snapshot(now, f"re-categorised from {old}")
                self.store.touch(fp)
                out.append((fp, "updated"))
        return out

    def _place_cluster(self, members: list[Buffered], now: float) -> list[tuple[Fingerprint, str]]:
        s = self.settings
        X = np.vstack([m.w.x for m in members])
        zc = self.scaler.transform(_nanmean(X)[None, :])
        toks: dict[str, set] = {}
        for m in members:
            for f, t in m.w.tokens.items():
                toks.setdefault(f, set()).update(t)
        cands = [f for f in self.store.fps.values() if f.status in ("active", "candidate", "dismissed")]
        if cands:
            comb, _, _ = self.score(zc, [toks], cands)
            j = int(np.argmax(comb[0]))
            best, sc = cands[j], float(comb[0, j])
            if sc >= s.similarity_threshold - 0.05:
                if best.status == "dismissed":
                    for m in members:
                        m.fp = best.id  # suppressed: user dismissed this behaviour
                    return []
                was_candidate = best.status == "candidate"
                if was_candidate and len(members) >= s.min_cluster_size:
                    best.status = "active"
                    best.notes.append(f"auto-promoted: clustering confirmed it with {len(members)} windows")
                self.update(best, members, now, f"clustering added {len(members)} windows (score {sc:.2f})")
                return [(best, "promoted" if was_candidate and best.status == "active" else "updated")]
        fp = self.create(members, now, "cluster", "active")
        return [(fp, "created")]

    # ---------------------------------------------------------- user actions
    def merge(self, ids: list[str], now: float) -> Fingerprint:
        fps = [self.store.get(i) for i in ids]
        if len(fps) < 2 or any(f is None for f in fps):
            raise ValueError("merge needs at least two existing fingerprints")
        target, rest = fps[0], fps[1:]
        for o in rest:
            tot = target.n_windows + o.n_windows
            target.centroid = _blend(target.centroid, o.centroid, target.n_windows, o.n_windows)
            target.spread = _blend(target.spread, o.spread, target.n_windows, o.n_windows)
            target.n_windows = tot
            for f, c in o.tokens.items():
                target.tokens.setdefault(f, Counter()).update(c)
            target.ips.update(o.ips)
            target.asns.update(o.asns)
            target.countries.update(o.countries)
            target.timeline.update(o.timeline)
            target.hit_count += o.hit_count
            target.episodes = sorted(target.episodes + o.episodes, key=lambda e: e["start"])
            target.first_seen = min(target.first_seen, o.first_seen)
            target.last_seen = max(target.last_seen, o.last_seen)
            target.window_ids += o.window_ids
            for b in self.buffer:
                if b.fp == o.id:
                    b.fp = target.id
            self.store.remove(o.id)
        if target.status == "candidate":
            target.status = "active"
        self.classify(target)
        target.refresh_signature()
        target.snapshot(now, f"merged {', '.join(f.id for f in rest)}")
        target.notes.append(f"merged {', '.join(f.id for f in rest)}")
        self.store.touch(target)
        return target

    def split(self, fid: str, now: float) -> list[Fingerprint]:
        fp = self.store.get(fid)
        if fp is None:
            raise ValueError("unknown fingerprint")
        members = [b for b in self.buffer if b.fp == fid]
        if len(members) < 4:
            raise ValueError(f"need at least 4 buffered windows to split (have {len(members)})")
        Z = self.scaler.transform(np.vstack([m.w.x for m in members]))
        lab = KMeans(n_clusters=2, n_init=5, random_state=0).fit_predict(Z)
        a = [m for m, l in zip(members, lab) if l == 0]
        b = [m for m, l in zip(members, lab) if l == 1]
        if not a or not b:
            raise ValueError("windows are not separable")
        X = np.vstack([m.w.x for m in a])
        fp.centroid, fp.spread, fp.n_windows = _nanmean(X), _nanstd(X), len(a)
        fp.tokens = {}
        for m in a:
            fp.add_tokens(m.w.tokens)
        self.classify(fp)
        fp.refresh_signature()
        fp.snapshot(now, "split (kept part 1)")
        self.store.touch(fp)
        new = self.create(b, now, "split", fp.status)
        new.notes.append(f"split from {fid}")
        return [fp, new]

    def forget(self, fid: str) -> None:
        for b in self.buffer:
            if b.fp == fid:
                b.fp = None
        self.store.remove(fid)
