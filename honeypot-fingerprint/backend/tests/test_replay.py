from pathlib import Path

from app.replay.engine import ReplayEngine, ReplayPlan, Selection, remap_ip
from app.replay.plans import build_custom, build_returning

from .conftest import BASE


def _drain(engine: ReplayEngine, dt=None):
    out = []
    while engine.state != "finished":
        evs, _ = engine.step(dt)
        out += evs
    return out


def test_mixed_selections_stream_in_timestamp_order(catalog, source_ids):
    plan = build_custom(catalog, [
        {"source_id": source_ids["cicddos2019_sample.csv"], "labels": ["Syn"], "offset": 5},
        {"source_id": source_ids["zeek_conn_labeled.log"], "offset": 0},
        {"source_id": source_ids["cowrie_sample.json"], "offset": 3, "compress": 4},
    ])
    eng = ReplayEngine()
    eng.load(plan, BASE)
    evs = _drain(eng)
    assert len(evs) == 15 + 30 + 28
    ts = [e.timestamp for e in evs]
    assert ts == sorted(ts)
    assert min(ts) >= BASE  # shifted to the replay clock ("now")
    assert {e.source.split(":")[0] for e in evs} == {"cicflow", "zeek", "cowrie"}


def test_replay_is_independent_of_step_size(catalog, source_ids):
    def run(dt):
        plan = build_custom(catalog, [{"source_id": source_ids["zeek_conn_labeled.log"]},
                                      {"source_id": source_ids["opencanary_sample.json"], "offset": 2}])
        eng = ReplayEngine()
        eng.load(plan, BASE)
        return [(round(e.timestamp, 6), e.src_ip, e.dst_port) for e in _drain(eng, dt)]
    assert run(0.1) == run(1.0) == run(5.0)


def test_compression_and_label_filter(catalog, source_ids):
    plan = build_custom(catalog, [{"source_id": source_ids["zeek_conn_labeled.log"],
                                   "labels": ["PartOfAHorizontalPortScan"], "compress": 2.0}])
    eng = ReplayEngine()
    eng.load(plan, BASE)
    evs = _drain(eng)
    assert len(evs) == 18
    orig_span = evs[-1].orig_timestamp - evs[0].orig_timestamp
    assert abs((evs[-1].timestamp - evs[0].timestamp) - orig_span / 2) < 1e-6


def test_ip_remap_is_consistent():
    a = remap_ip("172.16.0.1", 7)
    assert a == remap_ip("172.16.0.1", 7) != remap_ip("172.16.0.1", 8)
    assert a != remap_ip("172.16.0.2", 7)


def test_returning_split(catalog, source_ids):
    plan = build_returning(catalog, source_ids["cicids2017_sample.csv"], "SSH-Patator", split=0.5)
    names = [s.name for s in plan.selections]
    assert names == ["background", "part A", "part B"]
    eng = ReplayEngine()
    eng.load(plan, BASE)
    a, b = plan.selections[1], plan.selections[2]
    assert a.replay_end < b.replay_start  # part B starts after a gap
    assert not set(a.ips) & set(b.ips)  # B comes from remapped IPs
    assert a.ips == ["172.16.0.1"] and len(b.ips) == 1
    assert b.parent_campaign == a.campaign_id
    camps = {c["campaign_id"]: c for c in eng.campaign_list()}
    assert camps[b.campaign_id]["parent_id"] == a.campaign_id and camps[b.campaign_id]["remapped"]
    assert any(s.action == "force_cluster" for s in plan.script)


def test_loop_slice_keeps_or_rotates_ips(fixtures_dir):
    def ips(new_ips):
        sel = Selection(source_id="x", path=str(fixtures_dir / "zeek_conn_labeled.log"), labels=["Benign"],
                        repeat=3, repeat_new_ips=new_ips)
        eng = ReplayEngine()
        eng.load(ReplayPlan(name="t", selections=[sel]), BASE)
        return eng.total_events, set(sel.ips)
    n, same = ips(False)
    assert n == 18 and same == {"192.168.100.103"}
    n, rotated = ips(True)
    assert n == 18 and len(rotated) == 3


def test_pause_does_not_advance(catalog, source_ids):
    plan = build_custom(catalog, [{"source_id": source_ids["zeek_conn.json"]}])
    eng = ReplayEngine()
    eng.load(plan, BASE)
    assert eng.state == "paused" and eng.t == 0
    eng.state = "running"
    eng.step()
    assert eng.t > 0


def test_unknown_source_rejected(catalog):
    import pytest
    from app.replay.plans import PlanError
    with pytest.raises(PlanError):
        build_custom(catalog, [{"source_id": "nope"}])
    assert Path(catalog.list()[0]["path"]).exists()
