"""Shared adapter helpers: tolerant number/timestamp parsing."""
from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from ..schemas import Event

PROTO_NUM = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMP"}


def to_int(v: Any) -> Optional[int]:
    f = to_float(v)
    return None if f is None else int(f)


def to_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        f = float(v)
    else:
        s = str(v).strip()
        if s in ("", "-", "(empty)", "NaN", "nan", "None"):
            return None
        try:
            f = float(s)
        except ValueError:
            return None
    if math.isnan(f) or math.isinf(f):
        return None
    return f


def to_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return None if s in ("", "-", "(empty)", "nan") else s


def protocol_name(v: Any) -> str:
    n = to_int(v)
    if n is not None:
        return PROTO_NUM.get(n, "TCP" if n == 0 else str(n))
    s = (to_str(v) or "tcp").upper()
    return "ICMP" if s.startswith("ICMP") else s


_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
    "%d/%m/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M:%S %p",
)


def parse_ts(v: Any, cic2017_pm_fix: bool = False) -> Optional[float]:
    """Parse epoch numbers, ISO strings and the CIC day/month formats to epoch seconds (UTC)."""
    f = to_float(v)
    if f is not None:
        return f / 1000.0 if f > 1e12 else f
    s = to_str(v)
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        # CIC-IDS2017 writes afternoon times on a 12-hour clock without AM/PM
        # (capture ran ~08:00-17:30), so hours 1..7 are really 13..19.
        if cic2017_pm_fix and "%p" not in fmt and 1 <= dt.hour <= 7:
            dt = dt.replace(hour=dt.hour + 12)
        return dt.timestamp()
    return None


class Adapter:
    name = "base"
    description = ""
    extensions: tuple[str, ...] = ()

    def sniff(self, path: Path, head: str) -> bool:
        return False

    def iter_events(self, path: Path, **kw) -> Iterator[Event]:
        raise NotImplementedError
