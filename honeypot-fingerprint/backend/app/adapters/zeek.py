"""Zeek conn.log adapter (TSV with #fields header, or JSON lines).

Also reads IoT-23 style `conn.log.labeled`, whose trailing `label`/`detailed-label`
columns become `ground_truth_label`.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, Optional

from ..schemas import Event, service_for_port
from .base import Adapter, protocol_name, to_float, to_int, to_str


def _history_counts(history: Optional[str]) -> dict:
    h = history or ""
    syn = sum(h.count(c) for c in "SsHh")
    ack = sum(h.count(c) for c in "AaHhDd")
    return {"syn": syn, "ack": ack, "fin": sum(h.count(c) for c in "Ff"), "rst": sum(h.count(c) for c in "Rr")}


def _rows_tsv(path: Path) -> Iterator[dict]:
    sep, fields = "\t", None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n").rstrip("\r")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("#separator"):
                    raw = line.split(" ", 1)[1].strip()
                    sep = raw.encode().decode("unicode_escape") if raw.startswith("\\x") else raw
                elif line.startswith("#fields"):
                    fields = []
                    for f in line.split(sep)[1:]:
                        fields.extend(f.split())  # IoT-23 joins the last fields with spaces
                continue
            if not fields:
                continue
            parts = line.split(sep)
            if len(parts) < len(fields):
                parts = parts[:-1] + parts[-1].split()
            yield dict(zip(fields, parts))


def _rows_json(path: Path) -> Iterator[dict]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


class ZeekConnAdapter(Adapter):
    name = "zeek"
    description = "Zeek conn.log (TSV or JSON)"
    extensions = (".log", ".json", ".labeled", ".tsv")

    def sniff(self, path: Path, head: str) -> bool:
        return ("#fields" in head and "id.orig_h" in head) or ('"id.orig_h"' in head and '"uid"' in head)

    def iter_events(self, path: Path, **_) -> Iterator[Event]:
        src = f"zeek:{path.name}"
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
        rows = _rows_json(path) if head.lstrip().startswith("{") else _rows_tsv(path)
        for r in rows:
            ts = to_float(r.get("ts"))
            ip = to_str(r.get("id.orig_h"))
            if ts is None or not ip:
                continue
            proto = protocol_name(r.get("proto"))
            dport = to_int(r.get("id.resp_p"))
            ob, rb = to_int(r.get("orig_bytes")), to_int(r.get("resp_bytes"))
            op, rp = to_int(r.get("orig_pkts")), to_int(r.get("resp_pkts"))
            oib, rib = to_int(r.get("orig_ip_bytes")), to_int(r.get("resp_ip_bytes"))
            pk = (op or 0) + (rp or 0) if (op is not None or rp is not None) else None
            ipb = (oib or 0) + (rib or 0) if (oib is not None or rib is not None) else None
            nbytes = (ob or 0) + (rb or 0) if (ob is not None or rb is not None) else ipb
            hist = to_str(r.get("history"))
            state = to_str(r.get("conn_state"))
            flags = None
            counts = {"syn": None, "ack": None, "fin": None, "rst": None}
            if proto == "TCP" and hist is not None:
                counts = _history_counts(hist)
                flags = ("S" if counts["syn"] else "") + ("A" if counts["ack"] else "") + \
                        ("R" if counts["rst"] else "") + ("F" if counts["fin"] else "")
            label = to_str(r.get("detailed-label")) or to_str(r.get("label")) or ""
            yield Event(
                timestamp=ts, orig_timestamp=ts, src_ip=ip, src_port=to_int(r.get("id.orig_p")),
                dst_ip=to_str(r.get("id.resp_h")), dst_port=dport,
                dst_service=service_for_port(dport, to_str(r.get("service"))), protocol=proto,
                tcp_flags=flags, packet_size=(ipb / pk) if (ipb is not None and pk) else None,
                bytes=nbytes, duration=to_float(r.get("duration")), packets=pk, fwd_packets=op,
                bwd_packets=rp, syn_count=counts["syn"], ack_count=counts["ack"],
                fin_count=counts["fin"], rst_count=counts["rst"], session_id=to_str(r.get("uid")),
                payload_snippet=f"conn_state={state or '-'} history={hist or '-'}", event_type="flow",
                source=src, ground_truth_label=label,
            )
