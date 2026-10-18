"""Simulated firewall: applies *active* rules to replayed events inside the app only.

It never touches the host firewall. Dropped events are counted and not passed to detection.
The allowlist is checked first and can never be blocked.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from typing import Iterable, Optional

from ..schemas import Event


class Allowlist:
    def __init__(self, entries: Iterable[str] = ()):
        self.entries: dict[str, str] = {}
        self._nets: list = []
        for e in entries:
            self.add(e)

    def add(self, cidr: str, note: str = "") -> str:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        self.entries[str(net)] = note
        self._rebuild()
        return str(net)

    def remove(self, cidr: str) -> None:
        try:
            key = str(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            key = cidr
        self.entries.pop(key, None)
        self._rebuild()

    def _rebuild(self) -> None:
        self._nets = [ipaddress.ip_network(c) for c in self.entries]
        self._cache: dict[str, bool] = {}

    def contains(self, ip: str) -> bool:
        if ip in self._cache:
            return self._cache[ip]
        try:
            a = ipaddress.ip_address(ip)
            r = any(a in n for n in self._nets)
        except ValueError:
            r = False
        if len(self._cache) > 100_000:
            self._cache.clear()
        self._cache[ip] = r
        return r

    def list(self) -> list[dict]:
        return [{"cidr": c, "note": n} for c, n in self.entries.items()]


class _Bucket:
    __slots__ = ("rate", "tokens", "t")

    def __init__(self, rate: float):
        self.rate, self.tokens, self.t = rate, rate * 2, None

    def allow(self, now: float) -> bool:
        if self.t is not None:
            self.tokens = min(self.rate * 2, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class SimulatedFirewall:
    def __init__(self, allowlist: Allowlist):
        self.allowlist = allowlist
        self.rules: dict[str, object] = {}
        self.blocked_ips: dict[str, str] = {}
        self.buckets: dict[tuple, _Bucket] = {}
        self.conns: dict[str, deque] = defaultdict(deque)
        self.drops: dict[str, int] = defaultdict(int)

    def set_rules(self, rules: list) -> None:
        self.rules = {r.id: r for r in rules}
        self.blocked_ips = {}
        for r in rules:
            if r.kind in ("ip_block", "ipset_block", "connlimit", "content"):
                for ip in r.params.get("ips", []):
                    if not self.allowlist.contains(ip):
                        self.blocked_ips.setdefault(ip, r.id)
        self.buckets = {k: v for k, v in self.buckets.items() if k[0] in self.rules}

    def check(self, e: Event) -> Optional[str]:
        """Return the id of the rule that drops this event, or None to accept it."""
        if not self.rules or self.allowlist.contains(e.src_ip):
            return None
        rid = self.blocked_ips.get(e.src_ip)
        if rid and self.rules[rid].kind != "connlimit":
            return rid
        for r in self.rules.values():
            k, p = r.kind, r.params
            ports = p.get("ports") or []
            if k == "syn_limit":
                if e.protocol == "TCP" and (e.tcp_flags or "").startswith("S") and "A" not in (e.tcp_flags or "") \
                        and (not ports or e.dst_port in ports):
                    b = self.buckets.setdefault((r.id, "g"), _Bucket(p["rate"] * 10))
                    if not b.allow(e.timestamp):
                        return r.id
            elif k == "udp_limit":
                if e.protocol == "UDP" and (not ports or e.dst_port in ports):
                    b = self.buckets.setdefault((r.id, "g"), _Bucket(p["rate"]))
                    if not b.allow(e.timestamp):
                        return r.id
            elif k == "icmp_limit":
                if e.protocol == "ICMP":
                    b = self.buckets.setdefault((r.id, "g"), _Bucket(p["rate"]))
                    if not b.allow(e.timestamp):
                        return r.id
            elif k == "http_limit":
                if (e.dst_service == "http") and (not ports or e.dst_port in ports):
                    b = self.buckets.setdefault((r.id, e.src_ip), _Bucket(p["rate"]))
                    if not b.allow(e.timestamp):
                        return r.id
            elif k == "connlimit":
                if e.src_ip in p.get("ips", []) or not p.get("ips"):
                    if e.dst_service == "http" or (ports and e.dst_port in ports):
                        q = self.conns[e.src_ip]
                        end = e.timestamp + (e.duration or 0)
                        while q and q[0] < e.timestamp:
                            q.popleft()
                        if len(q) >= p["max"]:
                            return r.id
                        q.append(end)
            elif k == "content":
                pats = p.get("patterns", {})
                for field_name, values in pats.items():
                    v = getattr(e, field_name, None)
                    if v and any(x.lower() in v.lower() for x in values):
                        return r.id
        return None

    def record_drop(self, rid: str) -> None:
        self.drops[rid] += 1
