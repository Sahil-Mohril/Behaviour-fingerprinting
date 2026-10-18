"""Small numpy MinHash (no external dependency).

Each of the NUM_PERM hash functions is SplitMix64(token_hash XOR seed_i), a strong 64-bit
mixer, so the per-function minima behave like independent random permutations.
"""
from __future__ import annotations

import hashlib
from typing import Iterable

import numpy as np

NUM_PERM = 128
_SEEDS = np.random.RandomState(1).randint(0, 2**63 - 1, size=NUM_PERM, dtype=np.int64).astype(np.uint64)
EMPTY = np.full(NUM_PERM, np.iinfo(np.uint64).max, dtype=np.uint64)
_M1 = np.uint64(0xBF58476D1CE4E5B9)
_M2 = np.uint64(0x94D049BB133111EB)


def _h(token: str) -> int:
    return int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "little")


def _mix(z: np.ndarray) -> np.ndarray:
    with np.errstate(over="ignore"):
        z = (z ^ (z >> np.uint64(30))) * _M1
        z = (z ^ (z >> np.uint64(27))) * _M2
        return z ^ (z >> np.uint64(31))


def signature(tokens: Iterable[str]) -> np.ndarray:
    hs = np.array([_h(t) for t in set(tokens)], dtype=np.uint64)
    if hs.size == 0:
        return EMPTY.copy()
    return _mix(hs[:, None] ^ _SEEDS[None, :]).min(axis=0)


def jaccard(a: np.ndarray, b: np.ndarray) -> float:
    if np.array_equal(a, EMPTY) and np.array_equal(b, EMPTY):
        return 0.0
    return float(np.mean(a == b))
