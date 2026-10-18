"""Turn detections into firewall rule suggestions (one rule per fingerprint episode)."""
from __future__ import annotations

import itertools
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Optional

from ..config import Settings
from ..fingerprint.store import Fingerprint
from ..labels import UNKNOWN, severity_rank
from .firewall import Allowlist
from .templates import render_all

# category -> rule kind
STRATEGY = {
    "syn_flood": "syn_limit",
    "udp_flood": "udp_limit",
    "icmp_flood": "icmp_limit",
    "http_flood": "ipset_block",
    "slowloris": "connlimit",
    "port_scan_fast": "ip_block",
    "port_scan_slow": "ip_block",
    "ssh_bruteforce": "ip_block",
    "ftp_bruteforce": "ip_block",
    "web_bruteforce": "ip_block",
    "credential_stuffing": "ipset_block",
    "post_login_shell": "content",
    "malware_download": "content",
    "infiltration": "ip_block",
    "web_vuln_probe": "content",
    "botnet_c2": "ip_block",
    "scraper": "http_limit",
    UNKNOWN: "ip_block",
}
THRESHOLDS = {"ssh_bruteforce": (5, 60), "ftp_bruteforce": (5, 60), "web_bruteforce": (10, 60),
              "credential_stuffing": (10, 60)}
SUGGEST_ONLY = {UNKNOWN}  # never auto-applied


@dataclass
class Rule:
    id: str
    fp_id: str
    fp_name: str
    category: str
    episode_id: Optional[str]
    kind: str
    params: dict
    reason: str
    created: float
    expires: float
    status: str = "suggested"  # suggested | approved | active | expired | rejected
    history: list = field(default_factory=list)
    hits: int = 0
    rev: int = 1
    alert_id: Optional[str] = None
    formats: dict = field(default_factory=dict)
    edited: bool = False

    def render(self) -> None:
        self.formats = render_all(self)

    def set_status(self, status: str, now: float, by: str) -> None:
        self.status = status
        self.history.append({"t": now, "status": status, "by": by})

    def to_dict(self) -> dict:
        d = asdict(self)
        d["n_ips"] = len(self.params.get("ips", []))
        return d


class RuleGenerator:
    def __init__(self, settings: Settings, allowlist: Allowlist):
        self.settings = settings
        self.allowlist = allowlist
        self.rules: dict[str, Rule] = {}
        self._ids = itertools.count(1)
        self.by_episode: dict[tuple, str] = {}
        self.dirty: set[str] = set()

    def load(self, items: list[dict]) -> None:
        for d in items:
            d = {k: v for k, v in d.items() if k in Rule.__dataclass_fields__}
            r = Rule(**d)
            self.rules[r.id] = r
            self.by_episode[(r.fp_id, r.episode_id)] = r.id
        nums = [int(i.split("-")[1]) for i in self.rules if i.startswith("R-")]
        self._ids = itertools.count(max(nums, default=0) + 1)

    def _params(self, fp: Fingerprint, kind: str, ips: list[str]) -> dict:
        s = self.settings
        ports = [int(t) for t in fp.tokens.get("port", Counter()) if t.isdigit()]
        top_ports = [int(p) for p, _ in Counter({int(t): n for t, n in fp.tokens.get("port", Counter()).items()
                                                 if t.isdigit()}).most_common(3)] if ports else []
        p: dict = {"ips": ips, "timeout": int(s.rule_expiry_seconds), "ports": top_ports}
        if kind == "syn_limit":
            p.update(rate=s.syn_rate_limit, proto="tcp")
        elif kind == "udp_limit":
            p.update(rate=s.udp_rate_limit, proto="udp")
        elif kind == "icmp_limit":
            p.update(rate=s.icmp_rate_limit, proto="icmp")
        elif kind == "http_limit":
            p.update(rate=s.http_rate_limit, proto="tcp")
        elif kind == "connlimit":
            p.update(max=s.connlimit, proto="tcp")
        elif kind == "content":
            pats: dict[str, list] = {}
            for fam, field_name in (("path", "http_path"), ("cmd", "command"), ("ua", "user_agent")):
                toks = [t for t, _ in fp.tokens.get(fam, Counter()).most_common(8) if ">" not in t and len(t) >= 3]
                if fam == "path":
                    from ..honeypot.services import is_sensitive_path
                    toks = [t for t in toks if is_sensitive_path(t)]
                if fam == "cmd":
                    toks = [t for t in toks if t in ("wget", "curl", "tftp", "chmod", "busybox", "nc", "perl", "python", "download")]
                if toks:
                    pats[field_name] = toks[:5]
            p["patterns"] = pats
        if fp.category in THRESHOLDS:
            p["threshold"] = list(THRESHOLDS[fp.category])
        return p

    def _reason(self, fp: Fingerprint, kind: str, returning: bool, n_ips: int) -> str:
        what = {"syn_limit": "rate-limit SYNs", "udp_limit": "rate-limit UDP", "icmp_limit": "rate-limit ICMP echo",
                "http_limit": "rate-limit HTTP per source", "connlimit": "limit concurrent connections and block sources",
                "ipset_block": f"block {n_ips} sources as an IP set", "ip_block": f"block {n_ips} source(s)",
                "content": f"drop payload signatures and block {n_ips} source(s)"}[kind]
        why = "returning behaviour from new sources" if returning else "matched fingerprint"
        return f"{fp.id} '{fp.name}' ({fp.category}, {fp.severity}): {why}; {what}."

    def ensure(self, fp: Fingerprint, episode: Optional[dict], ips: list[str], now: float, returning: bool,
               alert_id: Optional[str]) -> tuple[Optional[Rule], str]:
        """Create or extend the rule for this fingerprint episode. Returns (rule, change)."""
        if fp.benign or severity_rank(fp.severity) < severity_rank(self.settings.rule_min_severity) and not returning:
            return None, ""
        kind = STRATEGY.get(fp.category, "ip_block")
        clean = sorted({ip for ip in ips if not self.allowlist.contains(ip)})
        key = (fp.id, episode["id"] if episode else None)
        rid = self.by_episode.get(key)
        if rid and rid in self.rules:
            r = self.rules[rid]
            if r.status in ("rejected", "expired"):
                return r, ""
            new = [ip for ip in clean if ip not in r.params.get("ips", [])]
            if not new:
                return r, ""
            if not r.edited:
                r.params["ips"] = sorted(set(r.params.get("ips", [])) | set(new))[:2000]
            r.rev += 1
            r.reason = self._reason(fp, kind, returning or "returning" in r.reason, len(r.params["ips"]))
            r.render()
            self.dirty.add(r.id)
            return r, "extended"
        needs_ips = kind in ("ip_block", "ipset_block", "connlimit")
        if needs_ips and not clean:
            return None, "allowlisted"
        if kind == "ip_block" and len(clean) > 20:
            kind = "ipset_block"
        r = Rule(id=f"R-{next(self._ids):04d}", fp_id=fp.id, fp_name=fp.name, category=fp.category,
                 episode_id=key[1], kind=kind, params=self._params(fp, kind, clean),
                 reason=self._reason(fp, kind, returning, len(clean)), created=now,
                 expires=now + self.settings.rule_expiry_seconds, alert_id=alert_id)
        r.history.append({"t": now, "status": "suggested", "by": "generator"})
        r.render()
        self.rules[r.id] = r
        self.by_episode[key] = r.id
        self.dirty.add(r.id)
        return r, "created"

    def auto_apply(self, r: Rule, now: float) -> bool:
        if self.settings.rule_mode != "auto" or r.status != "suggested" or r.category in SUGGEST_ONLY:
            return False
        r.set_status("approved", now, "auto-apply")
        r.set_status("active", now, "auto-apply")
        r.expires = now + self.settings.rule_expiry_seconds
        self.dirty.add(r.id)
        return True

    def approve(self, rid: str, now: float) -> Rule:
        r = self.rules[rid]
        if r.status not in ("suggested", "expired", "rejected"):
            return r
        r.set_status("approved", now, "user")
        r.set_status("active", now, "simulated firewall")
        r.expires = now + self.settings.rule_expiry_seconds
        self.dirty.add(r.id)
        return r

    def reject(self, rid: str, now: float) -> Rule:
        r = self.rules[rid]
        r.set_status("rejected", now, "user")
        self.dirty.add(r.id)
        return r

    def edit(self, rid: str, changes: dict, now: float) -> Rule:
        r = self.rules[rid]
        if "ips" in changes:
            r.params["ips"] = sorted({ip.strip() for ip in changes["ips"] if ip.strip() and not self.allowlist.contains(ip.strip())})
        for k in ("rate", "max", "timeout"):
            if k in changes and changes[k] is not None:
                r.params[k] = int(changes[k])
        if "ports" in changes:
            r.params["ports"] = [int(p) for p in changes["ports"]]
        if "expires_in" in changes and changes["expires_in"]:
            r.expires = now + float(changes["expires_in"])
        r.edited = True
        r.rev += 1
        r.history.append({"t": now, "status": r.status, "by": "user edit"})
        r.render()
        self.dirty.add(r.id)
        return r

    def expire(self, now: float) -> list[Rule]:
        out = []
        for r in self.rules.values():
            if r.status == "active" and r.expires <= now:
                r.set_status("expired", now, "timeout")
                self.dirty.add(r.id)
                out.append(r)
        return out

    def purge_allowlisted(self) -> None:
        for r in self.rules.values():
            ips = r.params.get("ips", [])
            keep = [ip for ip in ips if not self.allowlist.contains(ip)]
            if len(keep) != len(ips):
                r.params["ips"] = keep
                r.render()
                self.dirty.add(r.id)

    def active(self) -> list[Rule]:
        return [r for r in self.rules.values() if r.status == "active"]

    def list(self) -> list[Rule]:
        return sorted(self.rules.values(), key=lambda r: r.created, reverse=True)
