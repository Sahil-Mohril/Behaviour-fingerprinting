from collections import Counter

import numpy as np
import pytest

from app.config import Settings
from app.features.extractor import FEATURES
from app.fingerprint.store import Fingerprint
from app.labels import severity_of
from app.rules.firewall import Allowlist, SimulatedFirewall
from app.rules.generator import STRATEGY, RuleGenerator
from app.rules.templates import FORMATS, export
from app.schemas import Event


def make_fp(category, tokens=None):
    return Fingerprint(id="FP-0042", name=f"{category} #1", category=category, severity=severity_of(category),
                       confidence=0.9, status="active", centroid=np.zeros(len(FEATURES)),
                       spread=np.zeros(len(FEATURES)), n_windows=10,
                       tokens=tokens or {"port": Counter({"22": 30, "nports:1": 30})}, first_seen=0, last_seen=0)


def gen(allow=("10.0.0.0/8",)):
    return RuleGenerator(Settings(), Allowlist(allow))


@pytest.mark.parametrize("category", sorted(set(STRATEGY)))
def test_every_category_renders_all_formats(category):
    tokens = {"port": Counter({"80": 10}), "path": Counter({"/.env": 5, "/wp-admin/": 4}),
              "cmd": Counter({"wget": 3, "chmod": 2}), "ua": Counter({"zgrab": 2})}
    r, change = gen().ensure(make_fp(category, tokens), {"id": "FP-0042/E1"}, ["45.1.2.3", "45.1.2.4"], 100.0,
                             False, "AL-00001")
    if r is None:  # severity below the rule threshold
        assert change == ""
        return
    assert change == "created" and r.status == "suggested"
    for fmt in FORMATS:
        assert r.formats[fmt].strip(), fmt
        assert r.id in r.formats[fmt] or fmt == "suricata"
    if r.kind in ("ip_block", "ipset_block", "connlimit"):
        assert "45.1.2.3" in r.formats["nftables"] and "45.1.2.3" in r.formats["iptables"]
    assert "sid:" in r.formats["suricata"]


def test_specific_templates():
    g = gen()
    syn, _ = g.ensure(make_fp("syn_flood", {"port": Counter({"80": 9})}), {"id": "e"}, ["1.1.1.1"], 0, False, None)
    assert "tcp flags & (syn|ack) == syn" in syn.formats["nftables"]
    assert "--syn" in syn.formats["iptables"] and "hashlimit" in syn.formats["iptables"]
    assert "flags:S" in syn.formats["suricata"]
    probe, _ = g.ensure(make_fp("web_vuln_probe", {"port": Counter({"80": 3}), "path": Counter({"/.env": 4})}),
                        {"id": "e-probe"}, ["2.2.2.2"], 0, False, None)
    assert 'http.uri; content:"/.env"' in probe.formats["suricata"]
    slow, _ = g.ensure(make_fp("slowloris"), {"id": "e-slow"}, ["3.3.3.3"], 0, False, None)
    assert "connlimit-above" in slow.formats["iptables"] and "ct count over" in slow.formats["nftables"]
    many = [f"45.0.0.{i}" for i in range(30)]
    bot, _ = g.ensure(make_fp("http_flood"), {"id": "e-bot"}, many, 0, False, None)
    assert bot.kind == "ipset_block" and "ipset create" in bot.formats["iptables"]
    for fmt in FORMATS:
        text = export([syn, probe, slow, bot], fmt)
        assert text.count("R-000") >= 3


def test_allowlisted_sources_are_never_targeted():
    g = gen(("10.0.0.0/8", "198.51.100.7/32"))
    r, change = g.ensure(make_fp("ssh_bruteforce"), {"id": "e1"}, ["10.1.2.3", "198.51.100.7"], 0, False, None)
    assert r is None and change == "allowlisted"
    r, _ = g.ensure(make_fp("ssh_bruteforce"), {"id": "e2"}, ["10.1.2.3", "45.6.7.8"], 0, False, None)
    assert r.params["ips"] == ["45.6.7.8"]
    r2 = g.edit(r.id, {"ips": ["45.6.7.8", "10.9.9.9"]}, 1)
    assert r2.params["ips"] == ["45.6.7.8"]


def test_simulated_firewall_never_drops_allowlisted_traffic():
    allow = Allowlist(["10.0.0.0/8"])
    g = RuleGenerator(Settings(rule_mode="auto"), allow)
    fw = SimulatedFirewall(allow)
    r, _ = g.ensure(make_fp("syn_flood", {"port": Counter({"80": 9})}), {"id": "e"}, ["45.0.0.1"], 0, False, None)
    blk, _ = g.ensure(make_fp("ssh_bruteforce"), {"id": "e2"}, ["45.0.0.9"], 0, False, None)
    g.approve(r.id, 0)
    g.approve(blk.id, 0)
    # force an allowlisted IP into an active rule (e.g. allowlist added after the rule)
    blk.params["ips"].append("10.0.0.99")
    fw.set_rules(g.active())
    syn = [Event(timestamp=i * 0.001, src_ip="10.0.0.99", dst_port=80, protocol="TCP", tcp_flags="S") for i in range(2000)]
    assert all(fw.check(e) is None for e in syn)
    attacker = [Event(timestamp=i * 0.001, src_ip="45.0.0.1", dst_port=80, protocol="TCP", tcp_flags="S") for i in range(2000)]
    # 1000 SYN/s for 2 s against a 250/s global bucket (burst 500): about half are dropped
    assert sum(1 for e in attacker if fw.check(e)) > 900
    assert fw.check(Event(timestamp=5, src_ip="45.0.0.9", dst_port=22)) == blk.id


def test_modes_and_expiry():
    g = gen()
    fp = make_fp("ssh_bruteforce")
    r, _ = g.ensure(fp, {"id": "e"}, ["45.1.1.1"], 0, False, None)
    assert not g.auto_apply(r, 0)  # suggest mode
    g.settings.rule_mode = "auto"
    assert g.auto_apply(r, 0) and r.status == "active"
    assert [h["status"] for h in r.history] == ["suggested", "approved", "active"]
    r2, change = g.ensure(fp, {"id": "e"}, ["45.1.1.2"], 1, False, None)
    assert change == "extended" and r2 is r and r.params["ips"] == ["45.1.1.1", "45.1.1.2"]
    assert g.expire(r.expires + 1) == [r] and r.status == "expired"
    unk, _ = g.ensure(make_fp("unknown_anomaly"), {"id": "u"}, ["45.2.2.2"], 0, False, None)
    assert not g.auto_apply(unk, 0)  # unknown anomalies are never auto-applied
    benign, _ = g.ensure(make_fp("benign"), {"id": "b"}, ["45.3.3.3"], 0, False, None)
    assert benign is None
