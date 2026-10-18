"""Explainable rule layer: centroid features -> behaviour category + confidence.

Each rule is a list of conditions on raw (un-scaled) centroid features. The first
condition is the defining one and must hold (as must any condition marked with '*'). Other conditions on features the source
cannot observe (NaN) are skipped; a rule needs at least half of its
conditions observable. Confidence = share of observable conditions met, discounted when
few were observable. The best rule wins if confidence >= 0.75; otherwise the cluster is
"benign" when it sits close to the baseline and "unknown anomaly" when it does not.
"""
from __future__ import annotations

import math
from typing import Callable

import numpy as np

from ..features.extractor import FIDX
from ..labels import UNKNOWN

L = math.log1p  # most volume/breadth features are log1p-transformed

Cond = tuple[str, str, float, str]  # feature, op, threshold (already in feature units), human text

RULES: dict[str, list[list[Cond]]] = {
    "syn_flood": [[("half_open_ratio", ">=", 0.7, "most TCP flows are half-open (SYN, no ACK/reply)"),
                   ("log_events_ps", ">=", L(20), ">= 20 flows/s"),
                   ("log_pkts_per_flow", "<=", L(3), "*<= 3 packets per flow"),
                   ("src_port_diversity", ">=", 0.5, "random source ports")]],
    "port_scan_fast": [[("log_uniq_dst_ports", ">=", L(15), ">= 15 distinct destination ports in a window"),
                        ("log_pkts_per_flow", "<=", L(3), "*<= 3 packets per flow"),
                        ("log_bytes_per_flow", "<=", L(200), "tiny flows (probes, no payload)"),
                        ("log_events_ps", ">=", L(1), ">= 1 probe/s")],
                       [("log_uniq_dst_ips", ">=", L(10), ">= 10 distinct destination hosts (horizontal scan)"),
                        ("log_uniq_dst_ports", "<=", L(3), "few ports"),
                        ("log_bytes_per_flow", "<=", L(200), "*tiny flows (probes, no payload)"),
                        ("half_open_ratio", ">=", 0.6, "mostly unanswered SYNs")]],
    "port_scan_slow": [[("log_long_uniq_ports", ">=", L(10), ">= 10 ports over the long horizon"),
                        ("log_events_ps", "<", L(1), "*< 1 probe/s"),
                        ("log_pkts_per_flow", "<=", L(3), "<= 3 packets per flow"),
                        ("log_bytes_per_flow", "<=", L(200), "*tiny flows (probes, no payload)")]],
    "udp_flood": [[("udp_ratio", ">=", 0.9, ">= 90% UDP"),
                   ("log_events_ps", ">=", L(20), "*>= 20 flows/s"),
                   ("log_size_mean", ">=", L(300), "large packets (>= 300 B)"),
                   ("reply_ratio", "<=", L(0.2), "little or no reply traffic")]],
    "icmp_flood": [[("icmp_ratio", ">=", 0.9, ">= 90% ICMP"), ("log_pkts_ps", ">=", L(10), "*>= 10 packets/s")]],
    "slowloris": [[("web_ratio", ">=", 0.8, "web port"),
                   ("log_rate_per_source", ">=", L(0.3), "each source keeps opening connections"),
                   ("log_flow_dur", ">=", L(5), "*long-held connections (>= 5 s)"),
                   ("log_bytes_per_flow", "<=", L(3000), "few bytes per connection"),
                   ("log_pkts_per_flow", "<=", L(20), "few packets per connection")]],
    "http_flood": [[("web_ratio", ">=", 0.8, "web port"),
                    ("log_rate_per_source", ">=", L(2), "*>= 2 requests/flows per second per source"),
                    ("log_events_ps", ">=", L(5), ">= 5 requests/flows per second"),
                    ("log_uniq_dst_ports", "<=", L(3), "single target service"),
                    ("half_open_ratio", "<", 0.5, "*connections complete (not a SYN flood)"),
                    ("log_flow_dur", "<", L(5), "short connections")]],
    "ssh_bruteforce": [[("ssh_ratio", ">=", 0.8, "SSH/Telnet"), ("fail_ratio", ">=", 0.7, "*>= 70% failed logins"),
                        ("log_uniq_passwords", ">=", L(3), "many passwords tried")],
                       [("ssh_ratio", ">=", 0.8, "SSH/Telnet"), ("log_events_ps", ">=", L(0.5), "*repeated connections"),
                        ("log_pkts_per_flow", ">=", L(8), "auth-sized flows (>= 8 packets)"),
                        ("log_pkts_per_flow", "<=", L(80), "but short (<= 80 packets)"),
                        ("log_uniq_dst_ports", "<=", L(2), "single service")]],
    "ftp_bruteforce": [[("ftp_ratio", ">=", 0.8, "FTP"), ("fail_ratio", ">=", 0.7, "*>= 70% failed logins")],
                       [("ftp_ratio", ">=", 0.8, "FTP"), ("log_events_ps", ">=", L(0.5), "*repeated connections"),
                        ("log_pkts_per_flow", ">=", L(5), "auth-sized flows"),
                        ("log_pkts_per_flow", "<=", L(60), "but short"),
                        ("log_uniq_dst_ports", "<=", L(2), "single service")]],
    "web_bruteforce": [[("web_ratio", ">=", 0.8, "web"), ("auth_ratio", ">=", 0.5, "*mostly login requests"),
                        ("fail_ratio", ">=", 0.7, "*>= 70% failed logins"), ("user_diversity", "<", 0.5, "few usernames")]],
    "credential_stuffing": [[("auth_ratio", ">=", 0.5, "mostly login attempts"), ("fail_ratio", ">=", 0.7, "*mostly failing"),
                             ("user_diversity", ">=", 0.7, "*a different username almost every attempt"),
                             ("log_n_sources", ">=", L(5), "spread over >= 5 sources")]],
    "post_login_shell": [[("log_cmd_count", ">=", L(1), "shell commands after login"), ("cmd_ratio", ">=", 0.2, "command-heavy session")]],
    "web_vuln_probe": [[("sensitive_path_ratio", ">=", 0.3, ">= 30% requests to sensitive paths"),
                        ("http_ratio", ">=", 0.5, "HTTP requests")]],
    "botnet_c2": [[("log_events_ps", "<=", L(3), "low rate (beacons, not a flood)"),
                   ("log_n_sources", "<=", L(1), "*a single host"),
                   ("iat_cv", "<=", 0.35, "*periodic timing (low IAT CV)"),
                   ("log_uniq_dst_ips", "<=", L(2), "one or two peers"), ("log_uniq_dst_ports", "<=", L(2), "fixed port"),
                   ("log_long_events", ">=", L(10), "persistent over the long horizon"),
                   ("ssh_ratio", "<", 0.5, "not a login service"), ("ftp_ratio", "<", 0.5, "not FTP")]],
}

OPS: dict[str, Callable[[float, float], bool]] = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b,
                                                  ">": lambda a, b: a > b, "<": lambda a, b: a < b}


def _score(x: np.ndarray, conds: list[Cond]) -> tuple[float, list[str], list[str]]:
    """The first condition of each variant (and any whose text starts with '*') is required:
    it must be observable and met."""
    met, missed, evaluable = [], [], 0
    for k, (feat, op, thr, text) in enumerate(conds):
        required = k == 0 or text.startswith("*")
        text = text.lstrip("*")
        v = x[FIDX[feat]]
        if v is None or np.isnan(v):
            if required:
                return 0.0, [], []
            continue
        evaluable += 1
        ok = OPS[op](float(v), thr)
        if required and not ok:
            return 0.0, [], []
        (met if ok else missed).append(text)
    if evaluable == 0 or evaluable < len(conds) / 2:
        return 0.0, [], []
    frac = len(met) / evaluable
    coverage = evaluable / len(conds)
    return round(frac * (0.85 + 0.15 * coverage), 4), met, missed


def categorize(x: np.ndarray, baseline_z: np.ndarray) -> dict:
    best = ("", 0.0, [], [])
    for cat, variants in RULES.items():
        for conds in variants:
            s, met, missed = _score(x, conds)
            if s > best[1]:
                best = (cat, s, met, missed)
    cat, conf, met, missed = best
    deviation = float(np.mean(np.abs(baseline_z)))
    if conf >= 0.75:
        return {"category": cat, "confidence": round(conf, 3), "reasons": met, "unmet": missed,
                "deviation": round(deviation, 3)}
    if deviation < 1.0:
        return {"category": "benign", "confidence": round(max(0.5, 1 - deviation / 2), 3),
                "reasons": [f"close to the benign baseline (mean |z| = {deviation:.2f})"], "unmet": [],
                "deviation": round(deviation, 3)}
    return {"category": UNKNOWN, "confidence": round(min(0.9, deviation / 4), 3),
            "reasons": [f"deviates from baseline (mean |z| = {deviation:.2f}) but no behaviour rule fits"
                        + (f"; nearest rule: {cat} ({conf:.2f})" if cat else "")], "unmet": missed,
            "deviation": round(deviation, 3)}
