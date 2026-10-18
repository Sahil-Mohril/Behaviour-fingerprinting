"""Runtime-tunable settings (persisted in the settings table) and paths."""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
STATE_DIR = Path(os.environ.get("HFP_STATE_DIR", BACKEND_DIR / "state"))
# Dataset files (CIC CSVs, Cowrie/OpenCanary JSON, Zeek conn.log). Never committed.
DATA_DIR = Path(os.environ.get("HFP_DATA_DIR", BACKEND_DIR.parent.parent / "data"))
FIXTURE_DIR = BACKEND_DIR / "tests" / "fixtures"


@dataclass
class Settings:
    # feature extraction
    window_seconds: float = 10.0
    hop_seconds: float = 5.0
    long_horizon_seconds: float = 300.0
    min_events_per_ip: int = 3
    # baseline (scaler centring + Isolation Forest training)
    baseline_seconds: float = 30.0
    # similarity / detection
    similarity_threshold: float = 0.85
    weight_numeric: float = 0.6
    weight_categorical: float = 0.4
    anomaly_contamination: float = 0.03
    episode_gap_seconds: float = 25.0
    alert_dedupe_seconds: float = 120.0
    # clustering
    cluster_interval_seconds: float = 15.0
    min_cluster_size: int = 5
    min_samples: int = 3
    cluster_buffer_size: int = 2500
    # honeypot decoys
    fake_accept_after: int = 0  # 0 = never fake a successful login for unresolved auth attempts
    # rules
    rule_mode: str = "suggest"  # suggest | auto
    rule_expiry_seconds: float = 900.0
    rule_min_severity: str = "medium"
    syn_rate_limit: int = 25
    udp_rate_limit: int = 50
    icmp_rate_limit: int = 10
    http_rate_limit: int = 20
    connlimit: int = 10
    # retention
    max_events_stored: int = 400_000

    def to_dict(self) -> dict:
        return asdict(self)

    def update(self, data: dict) -> list[str]:
        changed = []
        for k, v in data.items():
            if not hasattr(self, k):
                continue
            cur = getattr(self, k)
            if isinstance(cur, bool):
                v = bool(v)
            elif isinstance(cur, int):
                v = int(v)
            elif isinstance(cur, float):
                v = float(v)
            else:
                v = str(v)
            if cur != v:
                setattr(self, k, v)
                changed.append(k)
        if self.rule_mode not in ("suggest", "auto"):
            self.rule_mode = "suggest"
        if self.weight_numeric + self.weight_categorical <= 0:
            self.weight_numeric, self.weight_categorical = 0.6, 0.4
        self.hop_seconds = min(self.hop_seconds, self.window_seconds)
        return changed
