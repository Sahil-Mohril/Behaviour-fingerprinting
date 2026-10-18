"""Isolation Forest trained on baseline (presumed-benign) windows."""
from __future__ import annotations

from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyModel:
    MIN_TRAIN = 10

    def __init__(self, contamination: float = 0.03):
        self.contamination = contamination
        self.model: Optional[IsolationForest] = None
        self.trained_on = 0

    def fit(self, Z: np.ndarray) -> bool:
        if len(Z) < self.MIN_TRAIN:
            return False
        self.model = IsolationForest(n_estimators=150, contamination=self.contamination, random_state=0).fit(Z)
        self.trained_on = len(Z)
        return True

    @property
    def ready(self) -> bool:
        return self.model is not None

    def scores(self, Z: np.ndarray) -> np.ndarray:
        """decision_function: < 0 means anomalous."""
        if self.model is None or len(Z) == 0:
            return np.zeros(len(Z))
        return self.model.decision_function(Z)
