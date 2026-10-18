"""Returning attacker: part A builds the fingerprint, part B (new IPs, shifted time) matches it."""
import pytest

from app.pipeline import Pipeline
from app.replay.plans import build_returning

from .conftest import BASE


@pytest.fixture(scope="module", params=[("cicids2017_sample.csv", "SSH-Patator"),
                                        ("zeek_conn_labeled.log", "PartOfAHorizontalPortScan")])
def run(request, catalog, source_ids, tmp_path_factory):
    fname, label = request.param
    plan = build_returning(catalog, source_ids[fname], label, split=0.5, demo_script=True)
    p = Pipeline(state_dir=tmp_path_factory.mktemp("state"))
    p.start(plan, BASE, reset_learning=True)
    p.run_headless()
    return p, plan


def test_part_b_matches_part_a_fingerprint_above_threshold(run):
    p, plan = run
    a, b = plan.selections[-2], plan.selections[-1]
    ret = p.evaluator.metrics()["returning"]
    assert ret["replays"] == 1 and ret["recognised"] == 1 and ret["alerted"] == 1
    fid = ret["details"][0]["shared_fingerprints"][0]
    fp = p.store.get(fid)
    assert len(fp.episodes) >= 2
    first, last = fp.episodes[0], fp.episodes[-1]
    assert set(a.ips) <= first["ips"] and not (last["ips"] & first["ips"])
    assert last["returning"]
    alert = [x for x in p.alerts.list() if x.type == "returning"][0]
    assert alert.fp_id == fid and alert.score >= p.settings.similarity_threshold
    assert set(alert.ips) <= set(b.ips)
    assert "back from" in alert.explanation


def test_returning_rule_is_auto_applied_and_drops_traffic(run):
    p, plan = run
    b = plan.selections[-1]
    active = [r for r in p.rules.list() if r.status == "active"]
    assert active, "the demo script switches to auto-apply before part B"
    r = active[0]
    assert set(r.params["ips"]) & set(b.ips)
    assert r.hits > 0 and p.counters["dropped"] == sum(x.hits for x in p.rules.list())
    assert any(h["by"] == "auto-apply" for h in r.history)
