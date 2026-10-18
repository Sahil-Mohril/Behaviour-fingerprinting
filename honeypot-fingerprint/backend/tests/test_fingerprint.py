"""Clustering, categorisation and similarity on a seeded replay of all fixtures.

The fixtures hold 20-50 records each, so every slice is looped (repeat=N) to give the
window-level pipeline enough volume. Looping repeats the recorded rows; it does not
invent new behaviour.
"""
import numpy as np
import pytest

from app.fingerprint import minhash
from app.fingerprint.similarity import cosine_matrix
from app.labels import is_benign
from app.pipeline import Pipeline
from app.replay.plans import build_custom

from .conftest import BASE


@pytest.fixture(scope="module")
def mixed_run(catalog, source_ids, tmp_path_factory):
    sid = source_ids
    items = [
        dict(source_id=sid["cicids2017_sample.csv"], labels=["BENIGN"], repeat=80, repeat_new_ips=True, compress=7000),
        dict(source_id=sid["cicids2017_sample.csv"], labels=["SSH-Patator"], repeat=8, offset=30, compress=20),
        # CIC-DDoS2019 uses one attacker IP for every attack; remap the SYN slice so its long-horizon
        # history is not mixed with the UDP slice from the same IP
        dict(source_id=sid["cicddos2019_sample.csv"], labels=["Syn"], repeat=200, offset=90, compress=1,
             remap_ips=True),
        dict(source_id=sid["cicddos2019_sample.csv"], labels=["DrDoS_DNS"], repeat=150, offset=40, compress=1),
        dict(source_id=sid["zeek_conn_labeled.log"], labels=["C&C-HeartBeat"], repeat=12, offset=20, compress=1),
        dict(source_id=sid["cowrie_sample.json"], repeat=6, offset=130, compress=6, label_override="ssh_bruteforce"),
        dict(source_id=sid["opencanary_sample.json"], repeat=6, offset=120, compress=4),
    ]
    p = Pipeline(state_dir=tmp_path_factory.mktemp("state"))
    p.start(build_custom(catalog, items, "fixture mix"), BASE, reset_learning=True)
    p.run_headless()
    return p


def test_clustering_separates_main_behaviours(mixed_run):
    p = mixed_run
    cats = {f.category for f in p.store.by_status("active")}
    assert {"benign", "ssh_bruteforce", "syn_flood", "udp_flood", "botnet_c2"} <= cats
    m = p.evaluator.metrics()
    final = m["final"]["per_class"]
    for beh in ("benign", "syn_flood", "botnet_c2", "ssh_bruteforce", "udp_flood"):
        assert final[beh]["recall"] >= 0.6, (beh, final[beh])
    # benign traffic is not pushed into attack fingerprints
    assert m["binary"]["precision"] >= 0.95
    assert m["binary"]["recall"] >= 0.8


def test_fingerprints_have_explanations(mixed_run):
    for fp in mixed_run.store.by_status("active"):
        assert fp.category_reasons, fp.id
        assert len(fp.minhash_sig) == minhash.NUM_PERM
        assert fp.versions and fp.versions[0]["version"] == 1
        if not is_benign(fp.category):
            assert fp.importance and abs(fp.importance[0]["z"]) >= abs(fp.importance[-1]["z"])


def test_cluster_fingerprints_are_mutually_distinct(mixed_run):
    p = mixed_run
    attack = [f for f in p.store.by_status("active") if not f.benign]
    Z = p.scaler.transform(np.vstack([f.centroid for f in attack]))
    sim = cosine_matrix(Z, Z)
    by_cat = {}
    for i, f in enumerate(attack):
        by_cat.setdefault(f.category, []).append(i)
    syn, udp = by_cat["syn_flood"][0], by_cat["udp_flood"][0]
    assert sim[syn, udp] < 0.85


def test_minhash_estimates_jaccard():
    a = minhash.signature([f"t{i}" for i in range(100)])
    b = minhash.signature([f"t{i}" for i in range(50, 150)])  # true Jaccard 1/3
    assert abs(minhash.jaccard(a, b) - 1 / 3) < 0.12
    assert minhash.jaccard(a, a) == 1.0
