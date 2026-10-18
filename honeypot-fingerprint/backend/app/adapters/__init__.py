"""Input adapters: map external logs/flow files onto the Event schema."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .base import Adapter
from .cicflow import CICFlowAdapter, CICFlowError
from .cowrie import CowrieAdapter
from .opencanary import OpenCanaryAdapter
from .zeek import ZeekConnAdapter

ADAPTERS: dict[str, Adapter] = {a.name: a for a in (CICFlowAdapter(), CowrieAdapter(), OpenCanaryAdapter(), ZeekConnAdapter())}

__all__ = ["ADAPTERS", "Adapter", "CICFlowError", "detect_adapter"]


def detect_adapter(path: Path) -> Optional[Adapter]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(8192)
    except OSError:
        return None
    for name in ("cowrie", "opencanary", "zeek", "cicflow"):
        if ADAPTERS[name].sniff(path, head):
            return ADAPTERS[name]
    return None
