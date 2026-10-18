"""OpenCanary JSON log adapter (one JSON object per line)."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..schemas import Event, service_for_port
from .base import Adapter, parse_ts, to_int, to_str
from .cowrie import iter_json_records

LOGTYPE_SERVICE = {
    2000: "ftp", 3000: "http", 3001: "http", 4000: "ssh", 4001: "ssh", 4002: "ssh",
    6001: "telnet", 7001: "http", 8001: "mysql", 9001: "mssql", 9002: "mssql", 10001: "tftp",
    11001: "ntp", 12001: "vnc", 13001: "snmp", 14001: "rdp", 15001: "sip", 16001: "git",
    17001: "redis", 5000: "smb",
}
SCAN_TYPES = {5001: "SYN", 5002: "NMAP-OS", 5003: "NMAP-NULL", 5004: "NMAP-XMAS", 5005: "NMAP-FIN"}
IGNORED = {1000, 1001, 1002, 1003, 1004, 1005}
FLAG_KEYS = (("SYN", "S"), ("ACK", "A"), ("FIN", "F"), ("RST", "R"), ("PSH", "P"), ("URG", "U"))


class OpenCanaryAdapter(Adapter):
    name = "opencanary"
    description = "OpenCanary honeypot JSON log"
    extensions = (".json", ".log", ".jsonl")

    def sniff(self, path: Path, head: str) -> bool:
        return '"logtype"' in head and ('"src_host"' in head or '"dst_host"' in head)

    def iter_events(self, path: Path, **_) -> Iterator[Event]:
        src = f"opencanary:{path.name}"
        for r in iter_json_records(path):
            lt = to_int(r.get("logtype"))
            if lt is None or lt in IGNORED:
                continue
            ts = parse_ts(r.get("utc_time")) or parse_ts(r.get("local_time_adjusted")) or parse_ts(r.get("local_time"))
            ip = to_str(r.get("src_host"))
            if ts is None or not ip:
                continue
            ld = r.get("logdata") or {}
            if not isinstance(ld, dict):
                ld = {"msg": str(ld)}
            dport = to_int(r.get("dst_port"))
            ev = Event(timestamp=ts, orig_timestamp=ts, src_ip=ip, src_port=to_int(r.get("src_port")),
                       dst_ip=to_str(r.get("dst_host")), dst_port=dport,
                       dst_service=LOGTYPE_SERVICE.get(lt) or service_for_port(dport),
                       protocol="TCP", source=src)
            user, pw = to_str(ld.get("USERNAME")), to_str(ld.get("PASSWORD"))
            if lt in SCAN_TYPES:
                ev.event_type = "probe"
                ev.protocol = (to_str(ld.get("PROTO")) or "TCP").upper()
                ev.tcp_flags = "".join(f for k, f in FLAG_KEYS if k in ld) or None
                ev.packet_size = to_int(ld.get("LEN"))
                ev.bytes = ev.packet_size
                ev.packets = 1
                ev.syn_count = 1 if "SYN" in ld else 0
                ev.ack_count = 1 if "ACK" in ld else 0
                ev.fin_count = 1 if "FIN" in ld else 0
                ev.rst_count = 1 if "RST" in ld else 0
                ev.payload_snippet = SCAN_TYPES[lt]
            elif lt in (3000, 3001, 7001):
                ev.event_type = "http"
                ev.http_method = "POST" if lt != 3000 else "GET"
                ev.http_path = to_str(ld.get("PATH")) or "/"
                ev.user_agent = to_str(ld.get("USERAGENT"))
            elif lt in (4000, 4001):
                ev.event_type = "connect"
                ev.payload_snippet = to_str(ld.get("REMOTEVERSION")) or to_str(ld.get("LOCALVERSION"))
            else:
                ev.event_type = "other"
                ev.command = to_str(ld.get("CMD")) or to_str(ld.get("REQUEST"))
                ev.payload_snippet = to_str(ld.get("msg"))
            if user is not None or pw is not None:
                ev.event_type = "login" if ev.event_type != "http" else "http"
                ev.auth_attempt = True
                ev.auth_success = None  # OpenCanary does not log an outcome; the decoy layer decides
                ev.username, ev.password = user, pw
            yield ev
