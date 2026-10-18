"""Core event types.

`Event` is the full record produced by an input adapter, including ground-truth fields
(`ground_truth_label`, `campaign_id`) that only the evaluation layer may read.
`ObservedEvent` is the label-free view handed to the detection pipeline (feature
extraction, fingerprinting, detection, rules). Flow-level sources (CICFlowMeter, Zeek)
fill the flow totals; log sources (Cowrie, OpenCanary) fill the per-request fields.
Anything a source does not provide stays None.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class Event:
    timestamp: float
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_service: str = "other"
    dst_port: Optional[int] = None
    protocol: str = "TCP"
    tcp_flags: Optional[str] = None
    packet_size: Optional[float] = None
    bytes: Optional[int] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    user_agent: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    payload_snippet: Optional[str] = None
    response_code: Optional[int] = None
    session_id: Optional[str] = None
    # flow totals (flow-level sources)
    duration: Optional[float] = None
    packets: Optional[int] = None
    fwd_packets: Optional[int] = None
    bwd_packets: Optional[int] = None
    syn_count: Optional[int] = None
    ack_count: Optional[int] = None
    fin_count: Optional[int] = None
    rst_count: Optional[int] = None
    psh_count: Optional[int] = None
    event_type: str = "flow"  # flow | connect | login | command | download | http | probe | session_end
    auth_attempt: bool = False
    auth_success: Optional[bool] = None
    source: str = ""
    # --- ground truth (evaluation only) ---
    ground_truth_label: str = ""
    campaign_id: str = ""
    # --- set by the replay engine / capture layer ---
    orig_timestamp: float = 0.0
    seq: int = 0
    country: str = ""
    asn: str = ""
    action: str = "accepted"  # accepted | dropped
    rule_id: Optional[str] = None
    honeypot_note: Optional[str] = None

    def observe(self) -> "ObservedEvent":
        return ObservedEvent(
            self.seq, self.timestamp, self.src_ip, self.src_port, self.dst_ip, self.dst_service,
            self.dst_port, self.protocol, self.tcp_flags, self.packet_size, self.bytes,
            self.http_method, self.http_path, self.user_agent, self.username, self.password,
            self.command, self.payload_snippet, self.response_code, self.session_id,
            self.duration, self.packets, self.fwd_packets, self.bwd_packets, self.syn_count,
            self.ack_count, self.fin_count, self.rst_count, self.psh_count, self.event_type,
            self.auth_attempt, self.auth_success,
        )

    def to_row(self) -> dict:
        return {
            "seq": self.seq, "ts": self.timestamp, "src_ip": self.src_ip, "src_port": self.src_port,
            "dst_ip": self.dst_ip, "dst_service": self.dst_service, "dst_port": self.dst_port,
            "protocol": self.protocol, "tcp_flags": self.tcp_flags, "packet_size": self.packet_size,
            "bytes": self.bytes, "packets": self.packets, "duration": self.duration,
            "http_method": self.http_method, "http_path": self.http_path, "user_agent": self.user_agent,
            "username": self.username, "password": self.password, "command": self.command,
            "payload_snippet": self.payload_snippet, "response_code": self.response_code,
            "session_id": self.session_id, "event_type": self.event_type, "source": self.source,
            "ground_truth_label": self.ground_truth_label, "campaign_id": self.campaign_id,
            "country": self.country, "asn": self.asn, "action": self.action, "rule_id": self.rule_id,
            "honeypot_note": self.honeypot_note,
        }


@dataclass(slots=True)
class ObservedEvent:
    """Label-free event view. The detection pipeline only ever sees this type."""

    seq: int
    timestamp: float
    src_ip: str
    src_port: Optional[int]
    dst_ip: Optional[str]
    dst_service: str
    dst_port: Optional[int]
    protocol: str
    tcp_flags: Optional[str]
    packet_size: Optional[float]
    bytes: Optional[int]
    http_method: Optional[str]
    http_path: Optional[str]
    user_agent: Optional[str]
    username: Optional[str]
    password: Optional[str]
    command: Optional[str]
    payload_snippet: Optional[str]
    response_code: Optional[int]
    session_id: Optional[str]
    duration: Optional[float]
    packets: Optional[int]
    fwd_packets: Optional[int]
    bwd_packets: Optional[int]
    syn_count: Optional[int]
    ack_count: Optional[int]
    fin_count: Optional[int]
    rst_count: Optional[int]
    psh_count: Optional[int]
    event_type: str
    auth_attempt: bool
    auth_success: Optional[bool]


SERVICE_PORTS = {
    20: "ftp", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 443: "http",
    8080: "http", 8000: "http", 8443: "http", 3306: "mysql", 123: "ntp", 161: "snmp", 389: "ldap",
    1433: "mssql", 137: "netbios", 138: "netbios", 139: "netbios", 445: "smb", 1900: "ssdp",
    69: "tftp", 111: "portmap", 3389: "rdp", 5900: "vnc", 6379: "redis", 5060: "sip",
}


def service_for_port(port: Optional[int], hint: Optional[str] = None) -> str:
    if hint and hint not in ("-", ""):
        h = hint.lower().split(",")[0]
        return {"https": "http", "ssl": "http"}.get(h, h)
    if port is None:
        return "other"
    return SERVICE_PORTS.get(int(port), "other")
