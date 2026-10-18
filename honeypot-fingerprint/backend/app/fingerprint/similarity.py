"""Combined similarity = w1 * cosine(numeric) + w2 * Jaccard-style(categorical), with explanations.

Numeric: cosine similarity in scaled space with one extra constant "anchor" dimension.
Without it, vectors near the baseline origin have arbitrary directions; with it, low-energy
(benign-looking) vectors all point along the anchor and stay similar to each other, while
strong behaviours are compared by the direction of their deviation. Rate changes along the
same direction (a faster or slower replay) keep a high score.

Categorical: for live windows we use Jaccard containment |W n F| / |W| per trait family
(paths, UAs, users, passwords, commands, ports, flag shapes, ...), averaged over the
families the window has. A window holds a small sample of the fingerprint's traits, so plain
Jaccard would punish it for being small. Fingerprint-to-fingerprint comparisons
(compare / merge) use the MinHash Jaccard estimate.
"""
from __future__ import annotations

from collections import Counter
from typing import Optional

import numpy as np

from ..features.extractor import FEATURES
from . import minhash

ANCHOR = 2.0


def _with_anchor(Z: np.ndarray) -> np.ndarray:
    Z = np.atleast_2d(Z)
    return np.hstack([Z, np.full((Z.shape[0], 1), ANCHOR)])


def cosine_matrix(Za: np.ndarray, Zb: np.ndarray) -> np.ndarray:
    A, B = _with_anchor(Za), _with_anchor(Zb)
    A = A / np.linalg.norm(A, axis=1, keepdims=True)
    B = B / np.linalg.norm(B, axis=1, keepdims=True)
    return np.clip(A @ B.T, 0.0, 1.0)


def numeric_explain(za: np.ndarray, zb: np.ndarray, top: int = 5) -> dict:
    a, b = _with_anchor(za)[0], _with_anchor(zb)[0]
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    contrib = (za * zb) / (na * nb)
    order = np.argsort(-contrib)
    diff = np.abs(za - zb)
    dorder = np.argsort(-diff)
    return {
        "cosine": float(max(0.0, a @ b / (na * nb))),
        "anchor_share": float(ANCHOR * ANCHOR / (na * nb)),
        "top_shared": [{"feature": FEATURES[i], "contribution": round(float(contrib[i]), 4),
                        "live_z": round(float(za[i]), 2), "fp_z": round(float(zb[i]), 2)}
                       for i in order[:top] if contrib[i] > 0.001],
        "top_divergent": [{"feature": FEATURES[i], "live_z": round(float(za[i]), 2), "fp_z": round(float(zb[i]), 2)}
                          for i in dorder[:3] if diff[i] > 0.5],
    }


def containment(window_tokens: dict[str, set], fp_tokens: dict[str, Counter]) -> tuple[Optional[float], dict]:
    per = {}
    for fam, toks in window_tokens.items():
        if not toks:
            continue
        known = fp_tokens.get(fam)
        hit = len(toks & known.keys()) if known else 0
        per[fam] = hit / len(toks)
    if not per:
        return None, per
    return float(np.mean(list(per.values()))), per


def combine(num: float, cat: Optional[float], w_num: float, w_cat: float) -> float:
    if cat is None:
        return num
    s = w_num + w_cat
    return (w_num * num + w_cat * cat) / s


def explain_categorical(window_tokens: dict[str, set], fp_tokens: dict[str, Counter], per: dict) -> dict:
    shared, novel = [], []
    for fam, toks in window_tokens.items():
        known = fp_tokens.get(fam, Counter())
        for t in sorted(toks)[:40]:
            (shared if t in known else novel).append(f"{fam}:{t}")
    return {"per_family": {k: round(v, 3) for k, v in per.items()}, "shared": shared[:10], "novel": novel[:8]}


def fp_jaccard(sig_a: list[int], sig_b: list[int]) -> float:
    return minhash.jaccard(np.array(sig_a, dtype=np.uint64), np.array(sig_b, dtype=np.uint64))
