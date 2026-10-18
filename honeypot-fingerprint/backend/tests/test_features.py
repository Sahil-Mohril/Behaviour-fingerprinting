import dataclasses
import math

import numpy as np

from app.config import Settings
from app.features.extractor import FEATURES, FIDX, FeatureExtractor, compute_features
from app.schemas import Event, ObservedEvent


def flow(t, ip, dport=80, proto="TCP", syn=1, ack=1, fwd=5, bwd=5, nbytes=1000, dur=1.0, sport=None, **kw):
    e = Event(timestamp=t, src_ip=ip, src_port=sport if sport is not None else 40000 + int(t * 10) % 20000,
              dst_ip="10.0.0.5", dst_port=dport, dst_service="http" if dport in (80, 443) else "ssh" if dport == 22 else "other",
              protocol=proto, syn_count=syn, ack_count=ack, fwd_packets=fwd, bwd_packets=bwd, packets=fwd + bwd,
              bytes=nbytes, duration=dur, packet_size=nbytes / max(1, fwd + bwd), ground_truth_label="X", **kw)
    return e.observe()


def v(x, name):
    return x[FIDX[name]]


def test_observed_events_carry_no_labels():
    names = {f.name for f in dataclasses.fields(ObservedEvent)}
    assert "ground_truth_label" not in names and "campaign_id" not in names


def test_volume_protocol_and_flow_features():
    evs = [flow(i * 0.5, "1.2.3.4") for i in range(10)] + \
          [flow(i * 0.5 + 0.1, "1.2.3.4", proto="UDP", syn=None, ack=None, dport=53) for i in range(10)]
    x = compute_features(evs, 10.0, 1, None)
    assert math.isclose(v(x, "log_events_ps"), math.log1p(2.0))
    assert math.isclose(v(x, "log_pkts_ps"), math.log1p(200 / 10))
    assert math.isclose(v(x, "log_bytes_ps"), math.log1p(20000 / 10))
    assert v(x, "tcp_ratio") == 0.5 and v(x, "udp_ratio") == 0.5 and v(x, "icmp_ratio") == 0.0
    assert math.isclose(v(x, "syn_ratio"), 10 / 100)  # SYN packets / packets of flag-aware flows
    assert v(x, "half_open_ratio") == 0.0
    assert math.isclose(v(x, "log_pkts_per_flow"), math.log1p(10))
    assert math.isclose(v(x, "reply_ratio"), math.log1p(1.0))
    assert math.isclose(v(x, "log_uniq_dst_ports"), math.log1p(2))
    assert v(x, "web_ratio") == 0.5 and v(x, "dns_ratio") == 0.0  # service from port map (53 -> "other" here)


def test_half_open_syn_flood_shape():
    evs = [flow(i * 0.01, "9.9.9.9", syn=2, ack=0, fwd=2, bwd=0, nbytes=0, dur=0.0, sport=1000 + i) for i in range(300)]
    x = compute_features(evs, 10.0, 1, None)
    assert v(x, "half_open_ratio") == 1.0 and v(x, "syn_ratio") == 1.0
    assert v(x, "src_port_diversity") == 1.0
    assert math.isclose(v(x, "reply_ratio"), 0.0)
    assert v(x, "iat_cv") < 0.01  # perfectly regular


def test_missing_fields_become_nan_not_zero():
    e = Event(timestamp=1.0, src_ip="5.5.5.5", dst_port=22, dst_service="ssh", event_type="login",
              auth_attempt=True, auth_success=False, username="root", password="x").observe()
    x = compute_features([e, dataclasses.replace(e, timestamp=2.0, password="y"),
                          dataclasses.replace(e, timestamp=3.5, password="z")], 10.0, 1, None)
    for name in ("syn_ratio", "half_open_ratio", "log_flow_dur", "log_pkts_per_flow", "reply_ratio", "log_bytes_ps"):
        assert np.isnan(v(x, name)), name
    assert v(x, "fail_ratio") == 1.0 and v(x, "auth_ratio") == 1.0
    assert math.isclose(v(x, "log_uniq_passwords"), math.log1p(3))
    assert math.isclose(v(x, "user_diversity"), 1 / 3)
    assert v(x, "ssh_ratio") == 1.0


def test_http_and_command_features():
    base = Event(timestamp=0.0, src_ip="7.7.7.7", dst_port=80, dst_service="http", event_type="http",
                 http_method="GET", user_agent="ua1", response_code=404)
    paths = ["/.env", "/wp-admin/", "/", "/.git/config"]
    evs = [dataclasses.replace(base, timestamp=i, http_path=p).observe() for i, p in enumerate(paths)]
    x = compute_features(evs, 10.0, 1, None)
    assert v(x, "http_ratio") == 1.0 and v(x, "http_error_ratio") == 1.0
    assert v(x, "sensitive_path_ratio") == 0.75
    assert v(x, "ua_diversity") == 0.25 and math.isclose(v(x, "path_entropy"), 1.0)
    cmd = Event(timestamp=0.0, src_ip="7.7.7.8", dst_service="ssh", dst_port=22, event_type="command",
                session_id="s1")
    cmds = [dataclasses.replace(cmd, timestamp=i, command=c).observe() for i, c in enumerate(["uname -a", "wget x", "chmod +x a"])]
    x2 = compute_features(cmds, 10.0, 1, None)
    assert math.isclose(v(x2, "log_cmd_count"), math.log1p(3)) and v(x2, "cmd_ratio") == 1.0


def test_extractor_groups_sparse_sources():
    s = Settings(window_seconds=10, hop_seconds=5, min_events_per_ip=3)
    fx = FeatureExtractor(s)
    evs = [flow(0.1 + i * 0.2, f"20.0.0.{i}", syn=1, ack=0, fwd=1, bwd=0, nbytes=0) for i in range(40)]  # 40 one-off sources
    evs += [flow(0.1 + i * 0.5, "30.0.0.1", dport=22) for i in range(10)]  # one busy source
    fx.add(evs)
    wins = fx.compute(10.0)
    kinds = {w.entity: w for w in wins}
    assert "ip:30.0.0.1" in kinds and kinds["ip:30.0.0.1"].n_events == 10
    groups = [w for w in wins if w.kind == "group"]
    assert len(groups) == 1 and groups[0].n_ips == 40
    assert math.isclose(v(groups[0].x, "log_n_sources"), math.log1p(40))
    assert sorted(groups[0].seqs) == sorted(e.seq for e in evs[:40])
    assert len(FEATURES) == len(set(FEATURES))
