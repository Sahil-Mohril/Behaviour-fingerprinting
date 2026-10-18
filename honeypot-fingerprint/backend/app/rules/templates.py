"""Render rules as nftables / iptables / Suricata text. Text only: nothing here executes."""
from __future__ import annotations

FORMATS = ("nftables", "iptables", "suricata")
SID_BASE = 9_100_000


def _sid(rule) -> int:
    return SID_BASE + int(rule.id.split("-")[1])


def _set_name(rule) -> str:
    return "hfp_" + rule.id.lower().replace("-", "_")


def _comment(rule) -> str:
    return f"{rule.id} {rule.fp_id} {rule.category}".replace('"', "'")


def _proto_ports(rule) -> tuple[str, list[int]]:
    return rule.params.get("proto", "tcp").lower(), [int(p) for p in rule.params.get("ports", []) if p is not None]


def render_nftables(rule) -> str:
    p = rule.params
    k = rule.kind
    timeout = int(p.get("timeout", 900))
    name = _set_name(rule)
    c = _comment(rule)
    lines = [f"# {rule.reason}"]
    if k in ("ip_block", "ipset_block", "connlimit"):
        ips = p.get("ips", [])
        elems = ", ".join(f"{ip} timeout {timeout}s" for ip in ips[:500]) or ""
        lines.append(f"add set inet filter {name} {{ type ipv4_addr; flags timeout; elements = {{ {elems} }} }}")
        lines.append(f'add rule inet filter input ip saddr @{name} drop comment "{c}"')
    if k == "syn_limit":
        proto, ports = _proto_ports(rule)
        pp = f"tcp dport {{ {', '.join(map(str, ports))} }} " if ports else ""
        lines.append(f'add rule inet filter input {pp}tcp flags & (syn|ack) == syn meter {name} {{ ip saddr limit rate over {p["rate"]}/second burst {p["rate"] * 2} packets }} drop comment "{c}"')
        lines.append(f'add rule inet filter input {pp}tcp flags & (syn|ack) == syn limit rate over {p["rate"] * 10}/second drop comment "{c} global"')
    if k == "udp_limit":
        _, ports = _proto_ports(rule)
        pp = f"udp dport {{ {', '.join(map(str, ports))} }} " if ports else "meta l4proto udp "
        lines.append(f'add rule inet filter input {pp}limit rate over {p["rate"]}/second drop comment "{c}"')
    if k == "icmp_limit":
        lines.append(f'add rule inet filter input icmp type echo-request limit rate over {p["rate"]}/second drop comment "{c}"')
    if k == "http_limit":
        _, ports = _proto_ports(rule)
        pp = f"tcp dport {{ {', '.join(map(str, ports or [80, 443]))} }}"
        lines.append(f'add rule inet filter input {pp} ct state new meter {name} {{ ip saddr limit rate over {p["rate"]}/second }} drop comment "{c}"')
    if k == "connlimit":
        _, ports = _proto_ports(rule)
        pp = f"tcp dport {{ {', '.join(map(str, ports or [80, 443]))} }}"
        lines.append(f'add rule inet filter input {pp} ct state new meter {name}_ct {{ ip saddr ct count over {p["max"]} }} reject comment "{c}"')
    if k == "content":
        lines.append("# content signatures are enforced by Suricata (see the suricata format); IP block follows")
        ips = p.get("ips", [])
        if ips:
            elems = ", ".join(f"{ip} timeout {timeout}s" for ip in ips[:500])
            lines.append(f"add set inet filter {name} {{ type ipv4_addr; flags timeout; elements = {{ {elems} }} }}")
            lines.append(f'add rule inet filter input ip saddr @{name} drop comment "{c}"')
    return "\n".join(lines)


def render_iptables(rule) -> str:
    p = rule.params
    k = rule.kind
    timeout = int(p.get("timeout", 900))
    name = _set_name(rule)
    c = _comment(rule)
    lines = [f"# {rule.reason}"]
    ips = p.get("ips", [])
    if k in ("ipset_block", "content") or (k in ("ip_block", "connlimit") and len(ips) > 3):
        lines.append(f"ipset create {name} hash:ip timeout {timeout} -exist")
        lines += [f"ipset add {name} {ip} -exist" for ip in ips[:500]]
        lines.append(f'iptables -I INPUT -m set --match-set {name} src -m comment --comment "{c}" -j DROP')
    elif k in ("ip_block", "connlimit"):
        lines += [f'iptables -I INPUT -s {ip} -m comment --comment "{c}" -j DROP' for ip in ips]
    if k == "syn_limit":
        _, ports = _proto_ports(rule)
        pp = f"-m multiport --dports {','.join(map(str, ports))} " if ports else ""
        lines.append(f'iptables -A INPUT -p tcp --syn {pp}-m hashlimit --hashlimit-above {p["rate"]}/sec '
                     f'--hashlimit-burst {p["rate"] * 2} --hashlimit-mode srcip --hashlimit-name {name} '
                     f'-m comment --comment "{c}" -j DROP')
    if k == "udp_limit":
        _, ports = _proto_ports(rule)
        pp = f"-m multiport --dports {','.join(map(str, ports))} " if ports else ""
        lines.append(f'iptables -A INPUT -p udp {pp}-m limit --limit {p["rate"]}/sec -j ACCEPT')
        lines.append(f'iptables -A INPUT -p udp {pp}-m comment --comment "{c}" -j DROP')
    if k == "icmp_limit":
        lines.append(f'iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit {p["rate"]}/sec -j ACCEPT')
        lines.append(f'iptables -A INPUT -p icmp --icmp-type echo-request -m comment --comment "{c}" -j DROP')
    if k == "http_limit":
        _, ports = _proto_ports(rule)
        lines.append(f'iptables -A INPUT -p tcp -m multiport --dports {",".join(map(str, ports or [80, 443]))} -m conntrack --ctstate NEW '
                     f'-m hashlimit --hashlimit-above {p["rate"]}/sec --hashlimit-mode srcip --hashlimit-name {name} '
                     f'-m comment --comment "{c}" -j DROP')
    if k == "connlimit":
        _, ports = _proto_ports(rule)
        lines.append(f'iptables -A INPUT -p tcp -m multiport --dports {",".join(map(str, ports or [80, 443]))} --syn '
                     f'-m connlimit --connlimit-above {p["max"]} --connlimit-mask 32 -m comment --comment "{c}" -j REJECT --reject-with tcp-reset')
    return "\n".join(lines)


def _sur_ips(ips: list[str]) -> str:
    if not ips:
        return "any"
    if len(ips) == 1:
        return ips[0]
    return "[" + ",".join(ips[:200]) + "]"


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;")[:120]


def render_suricata(rule) -> str:
    p = rule.params
    k = rule.kind
    sid = _sid(rule)
    msg = f"HFP {rule.fp_name} ({rule.category}) {rule.id}".replace('"', "'").replace(";", ",")
    src = _sur_ips(p.get("ips", []))
    _, ports = _proto_ports(rule)
    dport = ports[0] if len(ports) == 1 else ("[" + ",".join(map(str, ports)) + "]" if ports else "any")
    lines = [f"# {rule.reason}"]
    if k == "syn_limit":
        lines.append(f'drop tcp any any -> $HOME_NET {dport} (msg:"{msg}"; flags:S,12; flow:stateless; '
                     f'threshold:type both, track by_dst, count {p["rate"] * 10}, seconds 1; classtype:attempted-dos; sid:{sid}; rev:{rule.rev};)')
    elif k == "udp_limit":
        lines.append(f'drop udp {src} any -> $HOME_NET {dport} (msg:"{msg}"; threshold:type both, track by_dst, '
                     f'count {p["rate"]}, seconds 1; classtype:attempted-dos; sid:{sid}; rev:{rule.rev};)')
    elif k == "icmp_limit":
        lines.append(f'drop icmp any any -> $HOME_NET any (msg:"{msg}"; itype:8; threshold:type both, track by_src, '
                     f'count {p["rate"]}, seconds 1; classtype:attempted-dos; sid:{sid}; rev:{rule.rev};)')
    elif k == "content":
        fields = p.get("patterns", {})
        n = 0
        for field_name, pats in fields.items():
            for pat in pats[:10]:
                buf = {"http_path": "http.uri", "user_agent": "http.user_agent"}.get(field_name)
                proto = "http" if buf else "tcp"
                body = f'{buf}; content:"{_esc(pat)}"; nocase;' if buf else f'flow:to_server,established; content:"{_esc(pat)}"; nocase;'
                lines.append(f'drop {proto} {src} any -> $HOME_NET {dport} (msg:"{msg} {field_name}"; {body} '
                             f'classtype:trojan-activity; sid:{sid * 10 + n}; rev:{rule.rev};)')
                n += 1
        if not n:
            lines.append(f'drop ip {src} any -> $HOME_NET any (msg:"{msg}"; sid:{sid}; rev:{rule.rev};)')
    else:
        thr = p.get("threshold")
        thr_txt = f" threshold:type both, track by_src, count {thr[0]}, seconds {thr[1]};" if thr else ""
        proto = "tcp" if ports else "ip"
        lines.append(f'drop {proto} {src} any -> $HOME_NET {dport if ports else "any"} (msg:"{msg}";'
                     f'{" flow:to_server;" if proto == "tcp" else ""}{thr_txt} classtype:attempted-admin; sid:{sid}; rev:{rule.rev};)')
    return "\n".join(lines)


RENDERERS = {"nftables": render_nftables, "iptables": render_iptables, "suricata": render_suricata}


def render_all(rule) -> dict[str, str]:
    return {f: RENDERERS[f](rule) for f in FORMATS}


def export(rules: list, fmt: str) -> str:
    head = {
        "nftables": "#!/usr/sbin/nft -f\n# Honeypot Fingerprint export - review before loading. Generated text only.\n"
                    "add table inet filter\nadd chain inet filter input { type filter hook input priority 0; policy accept; }\n",
        "iptables": "#!/bin/sh\n# Honeypot Fingerprint export - review before running. Generated text only.\n",
        "suricata": "# Honeypot Fingerprint export (Suricata rules) - generated text only.\n",
    }[fmt]
    return head + "\n\n".join(RENDERERS[fmt](r) for r in rules) + "\n"
