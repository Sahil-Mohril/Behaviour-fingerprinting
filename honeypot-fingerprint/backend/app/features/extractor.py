"""Sliding-window feature extraction over label-free, flow-level events.

Every `hop` seconds, events from the last `window` seconds are grouped into entities:
  * per source IP, when the IP is active enough (>= min_events_per_ip in the window, or a
    long-horizon history), and
  * per "campaign cluster" group otherwise: sparse sources sharing a traffic shape
    (protocol/service/flag shape/request class) are aggregated, which is how distributed
    or spoofed attacks show up.
Numeric features go into a float vector (NaN = not observable from this source, e.g. no
flag counts in a Cowrie log); categorical/sequence traits go into token sets per family.
"""
from __future__ import annotations

import itertools
import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable, Optional

import numpy as np

from ..config import Settings
from ..honeypot.services import is_sensitive_path
from ..schemas import ObservedEvent

FEATURES: list[str] = [
    # volume
    "log_events_ps", "log_pkts_ps", "log_bytes_ps", "log_conns_ps",
    # protocol mix
    "tcp_ratio", "udp_ratio", "icmp_ratio", "syn_ratio", "log_syn_ack", "rst_ratio", "half_open_ratio",
    # flow shape
    "log_flow_dur", "log_pkts_per_flow", "log_bytes_per_flow", "reply_ratio",
    # packet stats
    "log_size_mean", "log_size_std", "size_entropy",
    # timing
    "log_iat_mean", "log_iat_std", "iat_cv", "burstiness",
    # breadth
    "log_uniq_dst_ports", "log_uniq_dst_ips", "src_port_diversity", "log_uniq_paths", "log_uniq_users",
    "log_uniq_passwords",
    # auth
    "auth_ratio", "log_fail_rate", "fail_ratio", "success_after_fail", "user_diversity",
    # http
    "http_ratio", "http_error_ratio", "ua_diversity", "path_entropy", "sensitive_path_ratio",
    # content
    "log_cmd_count", "cmd_ratio",
    # service mix
    "web_ratio", "ssh_ratio", "ftp_ratio", "dns_ratio",
    # long horizon / breadth of sources
    "log_long_uniq_ports", "log_long_events", "log_long_uniq_dst_ips", "log_n_sources", "log_rate_per_source",
]
FIDX = {f: i for i, f in enumerate(FEATURES)}
FEATURE_GROUPS = {
    "Volume": FEATURES[0:4], "Protocol": FEATURES[4:11], "Flow shape": FEATURES[11:15],
    "Packets": FEATURES[15:18], "Timing": FEATURES[18:22], "Breadth": FEATURES[22:28],
    "Auth": FEATURES[28:33], "HTTP": FEATURES[33:38], "Content": FEATURES[38:40],
    "Service": FEATURES[40:44], "Sources": FEATURES[44:49],
}
TOKEN_FAMILIES = ("svc", "port", "flags", "size", "path", "ua", "user", "pw", "cmd", "payload")
WEB_PORTS = {80, 443, 8080, 8000, 8443}
_ids = itertools.count(1)


@dataclass
class WindowVector:
    id: int
    entity: str
    kind: str  # ip | group
    t_start: float
    t_end: float
    x: np.ndarray
    tokens: dict[str, set]
    seqs: list[int]
    ips: list[str]
    n_ips: int
    n_events: int
    services: dict = field(default_factory=dict)

    def summary(self) -> dict:
        return {"id": self.id, "entity": self.entity, "kind": self.kind, "t_end": self.t_end,
                "n_events": self.n_events, "n_ips": self.n_ips, "ips": self.ips[:10], "services": self.services}


def _entropy(counts: Iterable[int], normalise: bool = True) -> float:
    c = [x for x in counts if x > 0]
    n = sum(c)
    if n == 0 or len(c) <= 1:
        return 0.0
    h = -sum((x / n) * math.log2(x / n) for x in c)
    return h / math.log2(len(c)) if normalise else h


def _l(x: Optional[float]) -> float:
    return float("nan") if x is None else math.log1p(max(0.0, x))


def _flags(e: ObservedEvent) -> tuple[Optional[int], Optional[int], Optional[int]]:
    if e.syn_count is not None or e.ack_count is not None:
        return e.syn_count or 0, e.ack_count or 0, e.rst_count or 0
    if e.tcp_flags is not None and e.protocol == "TCP":
        f = e.tcp_flags
        return int("S" in f), int("A" in f), int("R" in f)
    return None, None, None


def shape_key(e: ObservedEvent) -> str:
    """Traffic-shape key used to aggregate sparse sources into campaign-cluster groups."""
    if e.auth_attempt:
        cls = "auth"
    elif e.http_method:
        cls = f"{e.http_method}:{'sensitive' if is_sensitive_path(e.http_path) else 'page'}"
    elif e.command:
        cls = "cmd"
    else:
        s, a, _ = _flags(e)
        if s is not None:
            cls = "syn-only" if s and not a else ("rst" if e.rst_count else "est")
        else:
            cls = e.event_type
    port = e.dst_port if (e.dst_port is not None and e.dst_port < 1024) or e.dst_service != "other" else "hi"
    return f"{e.protocol}/{e.dst_service}/{port}/{cls}"


def tokens_for(events: list[ObservedEvent]) -> dict[str, set]:
    tok: dict[str, set] = {f: set() for f in TOKEN_FAMILIES}
    ports = Counter()
    sizes = Counter()
    last_cmd: dict[str, str] = {}
    for e in events:
        tok["svc"].add(f"{e.protocol}/{e.dst_service}/{e.event_type}")
        if e.dst_port is not None:
            ports[e.dst_port] += 1
        if e.tcp_flags:
            tok["flags"].add(e.tcp_flags)
        if e.packet_size:
            sizes[int(math.log2(max(1.0, e.packet_size)))] += 1
        if e.http_path:
            tok["path"].add(e.http_path.split("?")[0][:80])
        if e.user_agent:
            tok["ua"].add(e.user_agent[:120])
        if e.username is not None:
            tok["user"].add(e.username[:60])
        if e.password is not None:
            tok["pw"].add(e.password[:60])
        if e.command:
            verb = e.command.strip().split(" ")[0][:40]
            tok["cmd"].add(verb)
            key = e.session_id or e.src_ip
            if key in last_cmd:
                tok["cmd"].add(f"{last_cmd[key]}>{verb}")
            last_cmd[key] = verb
        if e.payload_snippet:
            for t in e.payload_snippet.replace("/", " ").replace("=", "= ").split()[:6]:
                if len(t) >= 3:
                    tok["payload"].add(t[:40].lower())
    for p, _ in ports.most_common(5):
        tok["port"].add(str(p))
    n = len(ports)
    tok["port"].add("nports:" + ("1" if n <= 1 else "2-5" if n <= 5 else "6-50" if n <= 50 else ">50"))
    for s, _ in sizes.most_common(4):
        tok["size"].add(f"2^{s}")
    return {k: v for k, v in tok.items() if v}


def compute_features(events: list[ObservedEvent], window: float, n_sources: int,
                     long_hist: Optional[deque] = None) -> np.ndarray:
    x = np.full(len(FEATURES), np.nan)
    n = len(events)
    if n == 0:
        return x
    W = max(1e-6, window)

    def put(name, v):
        x[FIDX[name]] = v

    pkts_known = [e.packets for e in events if e.packets is not None]
    pkts_total = sum(pkts_known) + (n - len(pkts_known))
    byte_vals = [e.bytes if e.bytes is not None else e.packet_size for e in events]
    byte_known = [b for b in byte_vals if b is not None]
    conns = sum(1 for e in events if e.event_type in ("flow", "connect", "probe"))
    put("log_events_ps", _l(n / W))
    put("log_pkts_ps", _l(pkts_total / W))
    put("log_bytes_ps", _l(sum(byte_known) / W) if byte_known else float("nan"))
    put("log_conns_ps", _l(conns / W))

    protos = Counter(e.protocol for e in events)
    put("tcp_ratio", protos.get("TCP", 0) / n)
    put("udp_ratio", protos.get("UDP", 0) / n)
    put("icmp_ratio", protos.get("ICMP", 0) / n)

    syn = ack = rst = fl_pk = 0
    flag_known = half_open = tcp_n = 0
    for e in events:
        s, a, r = _flags(e)
        if s is None:
            continue
        flag_known += 1
        syn, ack, rst = syn + s, ack + a, rst + r
        fl_pk += e.packets if e.packets else 1
        if e.protocol == "TCP":
            tcp_n += 1
            if s and not a and not (e.bwd_packets or 0):
                half_open += 1
    if flag_known:
        put("syn_ratio", min(1.0, syn / max(1, fl_pk)))
        put("log_syn_ack", _l(syn / (ack + 1)))
        put("rst_ratio", min(1.0, rst / max(1, fl_pk)))
        put("half_open_ratio", half_open / max(1, tcp_n))

    durs = [e.duration for e in events if e.duration is not None and e.event_type in ("flow", "session_end")]
    if durs:
        put("log_flow_dur", _l(float(np.mean(durs))))
    if pkts_known:
        put("log_pkts_per_flow", _l(float(np.mean(pkts_known))))
    fb = [e.bytes for e in events if e.bytes is not None and e.event_type in ("flow", "probe")]
    if fb:
        put("log_bytes_per_flow", _l(float(np.mean(fb))))
    rr = [(e.bwd_packets or 0) / max(1, e.fwd_packets or 0) for e in events
          if e.fwd_packets is not None and e.bwd_packets is not None]
    if rr:
        put("reply_ratio", _l(float(np.mean(rr))))

    sizes = [e.packet_size for e in events if e.packet_size]
    if sizes:
        put("log_size_mean", _l(float(np.mean(sizes))))
        put("log_size_std", _l(float(np.std(sizes))))
        put("size_entropy", _entropy(Counter(int(math.log2(max(1.0, s)) * 2) for s in sizes).values()) if len(sizes) > 1 else 0.0)

    ts = np.array(sorted(e.timestamp for e in events))
    iat = np.diff(ts) if n >= 3 else None
    if iat is None and long_hist is not None and len(long_hist) >= 3:
        iat = np.diff(np.array([h[0] for h in long_hist]))
    if iat is not None and len(iat) >= 2:
        m, s = float(iat.mean()), float(iat.std())
        put("log_iat_mean", _l(m))
        put("log_iat_std", _l(s))
        put("iat_cv", min(5.0, s / m) if m > 0 else 0.0)
        put("burstiness", (s - m) / (s + m) if (s + m) > 0 else 0.0)

    ports = {e.dst_port for e in events if e.dst_port is not None}
    put("log_uniq_dst_ports", _l(len(ports)))
    dips = {e.dst_ip for e in events if e.dst_ip}
    if dips:
        put("log_uniq_dst_ips", _l(len(dips)))
    sp = [e.src_port for e in events if e.src_port is not None]
    if sp:
        put("src_port_diversity", len(set(sp)) / len(sp))
    paths = [e.http_path for e in events if e.http_path]
    users = [e.username for e in events if e.username is not None]
    pws = [e.password for e in events if e.password is not None]
    put("log_uniq_paths", _l(len(set(paths))))
    put("log_uniq_users", _l(len(set(users))))
    put("log_uniq_passwords", _l(len(set(pws))))

    auths = [e for e in events if e.auth_attempt]
    put("auth_ratio", len(auths) / n)
    if auths:
        fails = sum(1 for e in auths if e.auth_success is False)
        put("log_fail_rate", _l(fails / W))
        put("fail_ratio", fails / len(auths))
        seen_fail = False
        saf = 0.0
        for e in sorted(auths, key=lambda e: e.timestamp):
            if e.auth_success is False:
                seen_fail = True
            elif e.auth_success and seen_fail:
                saf = 1.0
        put("success_after_fail", saf)
        put("user_diversity", len(set(users)) / len(auths) if users else float("nan"))
    else:
        put("log_fail_rate", 0.0)

    http = [e for e in events if e.http_method or e.http_path]
    put("http_ratio", len(http) / n)
    if http:
        codes = [e.response_code for e in http if e.response_code is not None]
        if codes:
            put("http_error_ratio", sum(1 for c in codes if c >= 400) / len(codes))
        uas = [e.user_agent for e in http if e.user_agent]
        if uas:
            put("ua_diversity", len(set(uas)) / len(uas))
        if paths:
            put("path_entropy", _entropy(Counter(paths).values()))
            put("sensitive_path_ratio", sum(1 for p in paths if is_sensitive_path(p)) / len(paths))

    cmds = sum(1 for e in events if e.command)
    put("log_cmd_count", _l(cmds))
    put("cmd_ratio", cmds / n)

    svc = Counter()
    for e in events:
        if e.dst_service == "http" or e.dst_port in WEB_PORTS:
            svc["web"] += 1
        elif e.dst_service in ("ssh", "telnet"):
            svc["ssh"] += 1
        elif e.dst_service == "ftp":
            svc["ftp"] += 1
        elif e.dst_service == "dns":
            svc["dns"] += 1
    put("web_ratio", svc["web"] / n)
    put("ssh_ratio", svc["ssh"] / n)
    put("ftp_ratio", svc["ftp"] / n)
    put("dns_ratio", svc["dns"] / n)

    if long_hist is not None:
        put("log_long_uniq_ports", _l(len({h[1] for h in long_hist if h[1] is not None})))
        put("log_long_events", _l(len(long_hist)))
        put("log_long_uniq_dst_ips", _l(len({h[2] for h in long_hist if h[2]})))
    put("log_n_sources", _l(n_sources))
    put("log_rate_per_source", _l(n / W / max(1, n_sources)))
    return x


class FeatureExtractor:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.reset()

    def reset(self) -> None:
        self.recent: deque[ObservedEvent] = deque()
        self.long: dict[str, deque] = defaultdict(lambda: deque(maxlen=3000))
        self.last_window_end: Optional[float] = None

    def add(self, events: Iterable[ObservedEvent]) -> None:
        for e in events:
            self.recent.append(e)
            self.long[e.src_ip].append((e.timestamp, e.dst_port, e.dst_ip))

    def _prune(self, t_end: float) -> None:
        w = self.settings.window_seconds
        while self.recent and self.recent[0].timestamp <= t_end - w:
            self.recent.popleft()
        horizon = t_end - self.settings.long_horizon_seconds
        stale = []
        for ip, h in self.long.items():
            while h and h[0][0] < horizon:
                h.popleft()
            if not h:
                stale.append(ip)
        for ip in stale:
            del self.long[ip]

    def compute(self, t_end: float) -> list[WindowVector]:
        s = self.settings
        self._prune(t_end)
        self.last_window_end = t_end
        t_start = t_end - s.window_seconds
        by_ip: dict[str, list[ObservedEvent]] = defaultdict(list)
        for e in self.recent:
            if e.timestamp <= t_end:
                by_ip[e.src_ip].append(e)
        out: list[WindowVector] = []
        groups: dict[str, list[ObservedEvent]] = defaultdict(list)
        min_long = 4 * s.min_events_per_ip
        for ip, evs in by_ip.items():
            hist = self.long.get(ip)
            if len(evs) >= s.min_events_per_ip or (hist is not None and len(hist) >= min_long):
                x = compute_features(evs, s.window_seconds, 1, hist)
                out.append(self._vec(f"ip:{ip}", "ip", t_start, t_end, x, evs, [ip]))
            else:
                for e in evs:
                    groups[shape_key(e)].append(e)
        for key, evs in groups.items():
            if len(evs) < 3:
                continue
            ips = sorted({e.src_ip for e in evs})
            x = compute_features(evs, s.window_seconds, len(ips), None)
            out.append(self._vec(f"grp:{key}", "group", t_start, t_end, x, evs, ips))
        return out

    @staticmethod
    def _vec(entity, kind, t0, t1, x, evs, ips) -> WindowVector:
        svc = Counter(e.dst_service for e in evs)
        return WindowVector(id=next(_ids), entity=entity, kind=kind, t_start=t0, t_end=t1, x=x,
                            tokens=tokens_for(evs), seqs=[e.seq for e in evs], ips=ips[:200], n_ips=len(ips),
                            n_events=len(evs), services=dict(svc.most_common(3)))
