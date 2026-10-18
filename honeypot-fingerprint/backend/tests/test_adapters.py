from collections import Counter
from datetime import datetime, timezone

from app.adapters import ADAPTERS, detect_adapter
from app.adapters.catalog import load_events


def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc)


def test_detects_every_fixture_format(fixtures_dir):
    expected = {
        "cicids2017_sample.csv": "cicflow", "cicddos2019_sample.csv": "cicflow", "cowrie_sample.json": "cowrie",
        "opencanary_sample.json": "opencanary", "zeek_conn_labeled.log": "zeek", "zeek_conn.json": "zeek",
    }
    for name, adapter in expected.items():
        assert detect_adapter(fixtures_dir / name).name == adapter, name


def test_cicids2017_flows(fixtures_dir):
    evs, info = load_events(fixtures_dir / "cicids2017_sample.csv")
    assert info["loaded"] == 50
    labels = Counter(e.ground_truth_label for e in evs)
    assert labels["BENIGN"] == 20 and labels["SSH-Patator"] == 12 and labels["PortScan"] == 8
    # the dataset label is stored verbatim, including the broken en dash
    assert any(l.startswith("Web Attack") and "Brute Force" in l for l in labels)
    ssh = [e for e in evs if e.ground_truth_label == "SSH-Patator"]
    e = ssh[0]
    assert e.dst_port == 22 and e.dst_service == "ssh" and e.protocol == "TCP" and e.event_type == "flow"
    assert e.packets == e.fwd_packets + e.bwd_packets and e.bytes > 0 and e.duration > 1
    assert e.syn_count == 1 and "S" in e.tcp_flags
    # CIC-IDS2017 12-hour clock: "2:09" is 14:09 on 4 July 2017
    assert utc(min(x.timestamp for x in ssh)).hour == 14
    assert utc(e.timestamp).date().isoformat() == "2017-07-04"
    # minute-resolution timestamps are spread inside the minute (no identical bursts)
    assert len({x.timestamp for x in ssh}) == len(ssh)
    # events come back sorted
    assert [x.timestamp for x in evs] == sorted(x.timestamp for x in evs)


def test_cicids2017_missing_values(fixtures_dir):
    evs, _ = load_events(fixtures_dir / "cicids2017_sample.csv")
    xss = [e for e in evs if "XSS" in e.ground_truth_label][0]
    assert xss.duration is None  # "NaN" in Flow Duration
    udp = [e for e in evs if e.protocol == "UDP"][0]
    assert udp.dst_service == "dns" and udp.tcp_flags is None


def test_cicddos2019_iso_timestamps_and_filters(fixtures_dir):
    path = fixtures_dir / "cicddos2019_sample.csv"
    evs, _ = load_events(path, labels=["Syn"])
    assert len(evs) == 15 and {e.ground_truth_label for e in evs} == {"Syn"}
    assert utc(evs[0].timestamp).year == 2018 and any(e.timestamp % 1 for e in evs)  # sub-second precision kept
    assert all(e.syn_count == 2 and e.bwd_packets == 0 and e.tcp_flags == "S" for e in evs)
    t_mid = evs[7].timestamp
    part, _ = load_events(path, labels=["Syn"], t_to=t_mid)
    assert len(part) == 8
    dns, _ = load_events(path, labels=["DrDoS_DNS"])
    assert all(e.protocol == "UDP" and e.bytes == 2880 for e in dns)
    capped, info = load_events(path, max_rows=5)
    assert len(capped) == 5 and info["truncated"]
    sampled, info = load_events(path, sample_every=4)
    assert len(sampled) == 10 and info["matched"] == 40


def test_cowrie_sessions(fixtures_dir):
    evs, _ = load_events(fixtures_dir / "cowrie_sample.json")
    types = Counter(e.event_type for e in evs)
    assert types["connect"] == 2 and types["login"] == 15 and types["command"] == 6 and types["download"] == 1
    logins = [e for e in evs if e.event_type == "login"]
    assert sum(1 for e in logins if e.auth_success) == 1
    assert all(e.auth_attempt and e.response_code in (200, 401) for e in logins)
    # src_port is filled from the session's connect event
    assert all(e.src_port in (50110, 50111) for e in logins)
    cmd = [e for e in evs if e.event_type == "command"]
    assert cmd[0].command == "uname -a" and cmd[0].dst_service == "ssh" and cmd[0].dst_port == 2222
    assert all(e.ground_truth_label == "" for e in evs)  # Cowrie logs carry no labels
    closed = [e for e in evs if e.event_type == "session_end"]
    assert closed[0].duration == 25.1


def test_opencanary(fixtures_dir):
    evs, _ = load_events(fixtures_dir / "opencanary_sample.json")
    assert len(evs) == 27  # the boot message (logtype 1001) is ignored
    probes = [e for e in evs if e.event_type == "probe"]
    assert len(probes) == 10 and all(e.tcp_flags == "S" and e.syn_count == 1 and e.packet_size == 44 for e in probes)
    ssh = [e for e in evs if e.dst_service == "ssh" and e.auth_attempt]
    assert len(ssh) == 6 and ssh[0].username == "root"
    assert all(e.auth_success is None for e in ssh)  # outcome left to the decoy layer
    http = [e for e in evs if e.event_type == "http"]
    assert {"/wp-admin/", "/.env"} <= {e.http_path for e in http}
    assert any(e.http_method == "POST" and e.auth_attempt for e in http)
    assert any(e.dst_service == "mysql" for e in evs) and any(e.dst_service == "ftp" for e in evs)


def test_zeek_tsv_with_iot23_labels(fixtures_dir):
    evs, _ = load_events(fixtures_dir / "zeek_conn_labeled.log")
    assert len(evs) == 30
    labels = Counter(e.ground_truth_label for e in evs)
    assert labels == {"PartOfAHorizontalPortScan": 18, "C&C-HeartBeat": 6, "Benign": 6}
    scan = [e for e in evs if e.ground_truth_label == "PartOfAHorizontalPortScan"][0]
    assert scan.tcp_flags == "S" and scan.packets == 1 and scan.duration is None and scan.dst_port == 23
    assert "conn_state=S0" in scan.payload_snippet
    cc = [e for e in evs if e.ground_truth_label == "C&C-HeartBeat"][0]
    assert cc.dst_service == "irc" and cc.packets == 11 and cc.bytes == 212 and cc.ack_count > 0


def test_zeek_json(fixtures_dir):
    evs, _ = load_events(fixtures_dir / "zeek_conn.json")
    assert len(evs) == 20
    rej = [e for e in evs if "REJ" in e.payload_snippet]
    assert rej and all(e.rst_count >= 1 and e.duration is None for e in rej)
    ok = [e for e in evs if "SF" in e.payload_snippet]
    assert all(e.dst_service == "http" for e in ok)  # "ssl" service maps to http


def test_adapter_registry_names():
    assert set(ADAPTERS) == {"cicflow", "cowrie", "opencanary", "zeek"}
