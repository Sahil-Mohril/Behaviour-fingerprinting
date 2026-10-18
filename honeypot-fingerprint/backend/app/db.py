"""Buffered SQLite persistence. Event inserts are batched and commits throttled."""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Optional

from sqlalchemy import delete, event, func, insert, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlmodel import SQLModel, create_engine

from .models import AllowRow, EntityRow, EventRow, SettingRow

EVENT_COLS = [c.name for c in EventRow.__table__.columns if c.name != "id"]
FILTERABLE = ("src_ip", "dst_service", "protocol", "action", "ground_truth_label", "event_type", "rule_id", "country")


class Persistence:
    def __init__(self, path: Path, max_events: int = 400_000):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})

        @event.listens_for(self.engine, "connect")
        def _pragmas(dbapi_conn, _):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

        SQLModel.metadata.create_all(self.engine)
        self.max_events = max_events
        self.lock = threading.RLock()
        self.pending_events: list[dict] = []
        self.pending_entities: dict[tuple[str, str], Optional[dict]] = {}
        self.last_events = 0.0
        self.last_commit = 0.0
        self.flushes = 0

    # ----------------------------------------------------------------- writes
    def save_events(self, rows: list[dict]) -> None:
        self.pending_events.extend(rows)

    def flush_events(self, force: bool = False) -> None:
        if not self.pending_events:
            return
        if not force and time.monotonic() - self.last_events < 0.5 and len(self.pending_events) < 20_000:
            return
        rows, self.pending_events = self.pending_events, []
        with self.lock, self.engine.begin() as conn:
            conn.execute(insert(EventRow.__table__), [{k: r.get(k) for k in EVENT_COLS} for r in rows])
            self.flushes += 1
            if self.flushes % 20 == 0:
                top = conn.execute(select(func.max(EventRow.id))).scalar() or 0
                if top > self.max_events:
                    conn.execute(delete(EventRow.__table__).where(EventRow.id <= top - self.max_events))
        self.last_events = time.monotonic()

    def upsert(self, kind: str, id_: str, data: dict) -> None:
        self.pending_entities[(kind, id_)] = data

    def delete(self, kind: str, id_: str) -> None:
        self.pending_entities[(kind, id_)] = None

    def commit(self, force: bool = False) -> None:
        if not self.pending_entities or (not force and time.monotonic() - self.last_commit < 1.0):
            return
        items, self.pending_entities = self.pending_entities, {}
        with self.lock, self.engine.begin() as conn:
            for (kind, id_), data in items.items():
                if data is None:
                    conn.execute(delete(EntityRow.__table__).where(EntityRow.kind == kind, EntityRow.id == id_))
                    continue
                stmt = sqlite_insert(EntityRow.__table__).values(kind=kind, id=id_, data=data)
                conn.execute(stmt.on_conflict_do_update(index_elements=["kind", "id"], set_={"data": data}))
        self.last_commit = time.monotonic()

    def flush_all(self) -> None:
        self.flush_events(force=True)
        self.commit(force=True)

    def save_settings(self, value: dict) -> None:
        with self.lock, self.engine.begin() as conn:
            stmt = sqlite_insert(SettingRow.__table__).values(key="settings", value=value)
            conn.execute(stmt.on_conflict_do_update(index_elements=["key"], set_={"value": value}))

    def save_allowlist(self, entries: list[dict]) -> None:
        with self.lock, self.engine.begin() as conn:
            conn.execute(delete(AllowRow.__table__))
            if entries:
                conn.execute(insert(AllowRow.__table__), [{"cidr": e["cidr"], "note": e.get("note", "")} for e in entries])
            stmt = sqlite_insert(SettingRow.__table__).values(key="allowlist_saved", value={"v": 1})
            conn.execute(stmt.on_conflict_do_update(index_elements=["key"], set_={"value": {"v": 1}}))

    def wipe(self) -> None:
        self.pending_events, self.pending_entities = [], {}
        with self.lock, self.engine.begin() as conn:
            conn.execute(delete(EventRow.__table__))
            conn.execute(delete(EntityRow.__table__))

    # ------------------------------------------------------------------ reads
    def load_all(self, kind: str) -> list[dict]:
        with self.lock, self.engine.connect() as conn:
            return [r[0] for r in conn.execute(select(EntityRow.data).where(EntityRow.kind == kind))]

    def load_settings(self) -> Optional[dict]:
        with self.lock, self.engine.connect() as conn:
            return conn.execute(select(SettingRow.value).where(SettingRow.key == "settings")).scalar()

    def load_allowlist(self) -> Optional[list[tuple[str, str]]]:
        with self.lock, self.engine.connect() as conn:
            saved = conn.execute(select(SettingRow.value).where(SettingRow.key == "allowlist_saved")).scalar()
            if not saved:
                return None
            return [(r.cidr, r.note) for r in conn.execute(select(AllowRow.cidr, AllowRow.note))]

    def query_events(self, page: int = 1, size: int = 100, **filters) -> tuple[list[dict], int]:
        q = select(EventRow)
        cq = select(func.count()).select_from(EventRow)
        for k, v in filters.items():
            if v in (None, "") or k not in FILTERABLE:
                continue
            q = q.where(getattr(EventRow, k) == v)
            cq = cq.where(getattr(EventRow, k) == v)
        q = q.order_by(EventRow.id.desc()).offset((page - 1) * size).limit(size)
        with self.lock, self.engine.connect() as conn:
            total = conn.execute(cq).scalar() or 0
            rows = [dict(r._mapping) for r in conn.execute(q)]
        return [{k: v for k, v in r.items()} for r in rows], total
