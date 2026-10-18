"""Feature scaling: StandardScaler spread, centred on the benign baseline.

`scale_` comes from an sklearn StandardScaler fitted on the recent window buffer (all
observed traffic, unlabelled), floored so near-constant features cannot dominate.
`mean_` is the baseline mean (first `baseline_seconds` of traffic), so normal traffic sits
near the origin and attacks point away from it, which is what makes cosine similarity
(plus the anchor dimension, see similarity.py) meaningful. Missing features (NaN) map to
0 = "no evidence either way".
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler

SCALE_FLOOR = 0.2
Z_CLIP = 8.0


class BaselineScaler:
    def __init__(self, n_features: int):
        self.n = n_features
        self.mean_ = np.zeros(n_features)
        self.scale_ = np.ones(n_features)
        self.baseline_mean_: Optional[np.ndarray] = None
        self.baseline_std_: Optional[np.ndarray] = None
        self.has_baseline = False
        self.fitted = False

    def fit_baseline(self, X: np.ndarray) -> None:
        with np.errstate(all="ignore"):
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=RuntimeWarning)
                m = np.nanmean(X, axis=0)
                s = np.nanstd(X, axis=0)
        self.baseline_mean_ = np.nan_to_num(m, nan=0.0)
        self.baseline_std_ = np.nan_to_num(s, nan=0.0)
        self.mean_ = self.baseline_mean_.copy()
        self.has_baseline = True
        if not self.fitted:
            self.fit_scale(X)

    def fit_scale(self, X: np.ndarray) -> None:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=RuntimeWarning)
            sk = StandardScaler().fit(X)  # sklearn ignores NaN when fitting
        sc = np.nan_to_num(sk.scale_, nan=1.0)
        self.scale_ = np.maximum(sc, SCALE_FLOOR)
        if not self.has_baseline:
            self.mean_ = np.nan_to_num(sk.mean_, nan=0.0)
        self.fitted = True

    def transform(self, X: np.ndarray) -> np.ndarray:
        Z = (np.asarray(X, dtype=float) - self.mean_) / self.scale_
        Z = np.nan_to_num(Z, nan=0.0, posinf=Z_CLIP, neginf=-Z_CLIP)
        return np.clip(Z, -Z_CLIP, Z_CLIP)

    def baseline_z(self, x: np.ndarray) -> np.ndarray:
        """z-score vs the benign baseline (for feature importance)."""
        if self.baseline_mean_ is None:
            return np.zeros_like(x)
        std = np.maximum(self.baseline_std_, SCALE_FLOOR)
        z = (x - self.baseline_mean_) / std
        return np.nan_to_num(z, nan=0.0)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.__dict__, path)

    def load(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            d = joblib.load(path)
        except Exception:  # noqa: BLE001
            return False
        if d.get("n") != self.n:
            return False
        self.__dict__.update(d)
        return True
