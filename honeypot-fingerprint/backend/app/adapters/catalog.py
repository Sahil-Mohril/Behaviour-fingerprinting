"""Discover input files and index them (label counts, time ranges), with an on-disk cache."""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Iterable, Optional

from ..labels import map_label
from ..schemas import Event
from . import ADAPTERS, detect_adapter

SKIP_SUFFIXES = {".zip", ".gz", ".7z", ".tar", ".pcap", ".pcapng", ".md", ".txt", ".parquet"}


def source_id(path: Path) -> str:
    return hashlib.blake2b(str(path.resolve()).encode(), digest_size=6).hexdigest()


class Catalog:
    def __init__(self, roots: list[Path], cache_file: Path):
        self.roots = roots
        self.cache_file = cache_file
        self.lock = threading.Lock()
        self.sources: dict[str, dict] = {}
        self.status = "idle"
        self._cache: dict = {}
        if cache_file.exists():
            try:
                self._cache = json.loads(cache_file.read_text())
            except (OSError, ValueError):
                self._cache = {}

    def discover(self) -> list[Path]:
        files = []
        for root in self.roots:
            if not root.exists():
                continue
            for p in sorted(root.rglob("*")):
                if p.is_file() and p.suffix.lower() not in SKIP_SUFFIXES and not p.name.startswith("."):
                    files.append(p)
        return files

    def refresh(self) -> None:
        self.status = "indexing"
        try:
            for p in self.discover():
                self._index(p)
        finally:
            self.status = "ready"
            try:
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                self.cache_file.write_text(json.dumps(self._cache))
            except OSError:
                pass

    def _index(self, path: Path) -> None:
        sid = source_id(path)
        st = path.stat()
        key = f"{path.resolve()}|{st.st_size}|{int(st.st_mtime)}"
        adapter = detect_adapter(path)
        entry = {"id": sid, "path": str(path), "name": path.name, "size": st.st_size,
                 "adapter": adapter.name if adapter else None, "status": "unsupported", "labels": {}, "rows": 0,
                 "fixture": "fixtures" in path.parts}
        if adapter is None:
            with self.lock:
                self.sources[sid] = entry
            return
        cached = self._cache.get(key)
        if cached:
            entry.update(cached)
        else:
            entry["status"] = "indexing"
            with self.lock:
                self.sources[sid] = entry
            try:
                if adapter.name == "cicflow":
                    info = adapter.scan(path)  # type: ignore[attr-defined]
                else:
                    info = scan_events(adapter.iter_events(path))
                entry.update(info, status="ready")
                self._cache[key] = {"rows": entry["rows"], "labels": entry["labels"], "status": "ready"}
            except Exception as exc:  # noqa: BLE001 - surfaced in the UI
                entry.update(status="error", error=str(exc))
        for lab, d in entry["labels"].items():
            d["behaviour"] = map_label(lab) or "unlabelled"
        with self.lock:
            self.sources[sid] = entry

    def list(self) -> list[dict]:
        with self.lock:
            return sorted(self.sources.values(), key=lambda s: (s.get("fixture", False), s["name"]))

    def get(self, sid: str) -> Optional[dict]:
        with self.lock:
            return self.sources.get(sid)

    def find(self, pred) -> Optional[dict]:
        for s in self.list():
            if s.get("status") == "ready" and pred(s):
                return s
        return None


def scan_events(events: Iterable[Event]) -> dict:
    labels: dict[str, dict] = {}
    rows = 0
    for e in events:
        rows += 1
        lab = e.ground_truth_label or ""
        d = labels.setdefault(lab, {"count": 0, "t_min": e.timestamp, "t_max": e.timestamp})
        d["count"] += 1
        d["t_min"] = min(d["t_min"], e.timestamp)
        d["t_max"] = max(d["t_max"], e.timestamp)
    return {"rows": rows, "labels": labels}


def load_events(path: Path, adapter_name: Optional[str] = None, labels: Optional[Iterable[str]] = None,
                t_from: Optional[float] = None, t_to: Optional[float] = None,
                max_rows: Optional[int] = None, sample_every: int = 1) -> tuple[list[Event], dict]:
    """Load a slice of a source, sorted by time. Returns (events, info)."""
    adapter = ADAPTERS[adapter_name] if adapter_name else detect_adapter(path)
    if adapter is None:
        raise ValueError(f"no adapter recognises {path.name}")
    lab = set(labels) if labels else None
    out: list[Event] = []
    n = 0
    for e in adapter.iter_events(path, labels=lab, t_from=t_from, t_to=t_to):
        if lab is not None and e.ground_truth_label not in lab:
            continue
        if t_from is not None and e.timestamp < t_from:
            continue
        if t_to is not None and e.timestamp > t_to:
            continue
        n += 1
        if sample_every > 1 and (n - 1) % sample_every:
            continue
        out.append(e)
    out.sort(key=lambda e: e.timestamp)
    info = {"matched": n, "loaded": len(out), "sample_every": sample_every, "truncated": False}
    if max_rows and len(out) > max_rows:
        # keep a contiguous time slice (preserves rates) rather than thinning
        out = out[:max_rows]
        info.update(loaded=len(out), truncated=True)
    return out, info
