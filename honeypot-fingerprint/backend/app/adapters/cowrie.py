"""Cowrie JSON log adapter (cowrie.json: one JSON object per line)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..schemas import Event
from .base import Adapter, parse_ts, to_float, to_int, to_str


def iter_json_records(path: Path) -> Iterator[dict]:
    """JSON-lines, or a single JSON array."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = fh.read(1)
        while first and first.isspace():
            first = fh.read(1)
        fh.seek(0)
        if first == "[":
            for rec in json.load(fh):
                if isinstance(rec, dict):
                    yield rec
            return
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                yield rec


def _service(port, proto) -> str:
    if proto and str(proto).lower() == "telnet":
        return "telnet"
    return "telnet" if port in (23, 2223) else "ssh"


class CowrieAdapter(Adapter):
    name = "cowrie"
    description = "Cowrie SSH/Telnet honeypot JSON log"
    extensions = (".json", ".log", ".jsonl")

    def sniff(self, path: Path, head: str) -> bool:
        return '"eventid"' in head and "cowrie." in head

    def iter_events(self, path: Path, **_) -> Iterator[Event]:
        src = f"cowrie:{path.name}"
        sessions: dict[str, dict] = {}
        for r in iter_json_records(path):
            eid = r.get("eventid", "")
            if not eid.startswith("cowrie."):
                continue
            ts = parse_ts(r.get("timestamp"))
            ip = to_str(r.get("src_ip"))
            if ts is None or not ip:
                continue
            sid = to_str(r.get("session"))
            sess = sessions.setdefault(sid or "", {})
            if eid == "cowrie.session.connect":
                sess.update(src_port=to_int(r.get("src_port")), dst_port=to_int(r.get("dst_port")),
                            dst_ip=to_str(r.get("dst_ip")), proto=r.get("protocol"))
            dport = to_int(r.get("dst_port")) or sess.get("dst_port") or 22
            ev = Event(timestamp=ts, orig_timestamp=ts, src_ip=ip,
                       src_port=to_int(r.get("src_port")) or sess.get("src_port"),
                       dst_ip=to_str(r.get("dst_ip")) or sess.get("dst_ip"),
                       dst_service=_service(dport, r.get("protocol") or sess.get("proto")),
                       dst_port=dport, protocol="TCP", session_id=sid, source=src)
            if eid == "cowrie.session.connect":
                ev.event_type, ev.tcp_flags = "connect", "S"
            elif eid in ("cowrie.login.failed", "cowrie.login.success"):
                ev.event_type, ev.auth_attempt = "login", True
                ev.auth_success = eid.endswith("success")
                ev.username, ev.password = to_str(r.get("username")), to_str(r.get("password"))
                ev.response_code = 200 if ev.auth_success else 401
            elif eid in ("cowrie.command.input", "cowrie.command.failed"):
                ev.event_type, ev.command = "command", to_str(r.get("input"))
                ev.response_code = 127 if eid.endswith("failed") else 0
            elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                ev.event_type = "download"
                ev.payload_snippet = to_str(r.get("url")) or to_str(r.get("filename"))
                ev.command = f"download {ev.payload_snippet or ''}".strip()
            elif eid == "cowrie.session.closed":
                ev.event_type, ev.duration = "session_end", to_float(r.get("duration"))
            elif eid == "cowrie.client.version":
                ev.event_type, ev.payload_snippet = "client", to_str(r.get("version"))
            else:
                ev.event_type = "other"
                ev.payload_snippet = to_str(r.get("message"))
            yield ev
