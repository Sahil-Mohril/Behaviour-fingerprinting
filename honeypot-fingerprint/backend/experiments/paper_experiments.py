"""Reproduce every number in the paper (paper/main.tex).

    python -m experiments.paper_experiments [--data DIR] [--out ../paper/results]

With no datasets in the data folder this runs on the bundled fixtures (format-faithful
samples of 20-50 records per source, looped by the replay engine). Point --data at the
real CIC-IDS2017 / CIC-DDoS2019 / IoT-23 files to regenerate the tables on real data.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import json
import platform
import statistics
import tempfile
import time
from collections import Counter
from pathlib import Path

import numpy as np
import sklearn

from app.adapters import detect_adapter
from app.adapters.catalog import Catalog, load_events
from app.config import DATA_DIR, FIXTURE_DIR, Settings
from app.demo import DEMO_EPOCH
from app.features.extractor import FEATURES
from app.fingerprint import builder as fp_builder
from app.fingerprint import similarity
from app.labels import map_label
from app.pipeline import Pipeline
from app.replay.plans import build_custom, build_demo, build_returning
from app.rules.firewall import Allowlist, SimulatedFirewall
from app.rules.generator import STRATEGY, RuleGenerator
from app.schemas import Event

BASE = 1_800_000_000.0
RETURNING_CASES = [("cicids2017_sample.csv", "SSH-Patator"), ("cicids2017_sample.csv", "FTP-Patator"),
                   ("cicids2017_sample.csv", "PortScan"), ("cicddos2019_sample.csv", "Syn"),
                   ("cicddos2019_sample.csv", "DrDoS_DNS"), ("zeek_conn_labeled.log", "PartOfAHorizontalPortScan"),
                   ("zeek_conn_labeled.log", "C&C-HeartBeat")]


def tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="hfp-exp-"))


def mixed_items(sid: dict) -> list[dict]:
    return [
        dict(source_id=sid["cicids2017_sample.csv"], labels=["BENIGN"], repeat=80, repeat_new_ips=True, compress=7000),
        dict(source_id=sid["cicids2017_sample.csv"], labels=["SSH-Patator"], repeat=8, offset=30, compress=20),
        dict(source_id=sid["cicddos2019_sample.csv"], labels=["Syn"], repeat=200, offset=90, compress=1, remap_ips=True),
        dict(source_id=sid["cicddos2019_sample.csv"], labels=["DrDoS_DNS"], repeat=150, offset=40, compress=1),
        dict(source_id=sid["zeek_conn_labeled.log"], labels=["C&C-HeartBeat"], repeat=12, offset=20, compress=1),
        dict(source_id=sid["zeek_conn_labeled.log"], labels=["PartOfAHorizontalPortScan"], repeat=10, offset=150,
             compress=3, remap_ips=True),
        dict(source_id=sid["cowrie_sample.json"], repeat=6, offset=130, compress=6, label_override="ssh_bruteforce"),
        dict(source_id=sid["opencanary_sample.json"], repeat=6, offset=120, compress=4),
    ]


# ------------------------------------------------------------------ toggles
@contextlib.contextmanager
def variant(name: str, settings: Settings):
    """Ablation switches. Yields the settings to use."""
    old_anchor, old_hdb = similarity.ANCHOR, fp_builder.HDBSCAN
    try:
        if name == "numeric_only":
            settings.weight_numeric, settings.weight_categorical = 1.0, 0.0
        elif name == "categorical_only":
            settings.weight_numeric, settings.weight_categorical = 0.0, 1.0
        elif name == "no_anchor":
            similarity.ANCHOR = 0.0
        elif name.startswith("dbscan_"):
            eps = float(name.split("_")[1])
            from sklearn.cluster import DBSCAN

            class _DB:
                def __init__(self, min_cluster_size=5, min_samples=3, **_):
                    self.m = DBSCAN(eps=eps, min_samples=min_samples)

                def fit_predict(self, Z):
                    return self.m.fit_predict(Z)
            fp_builder.HDBSCAN = _DB
        elif name.startswith("thr_"):
            settings.similarity_threshold = float(name.split("_")[1])
        yield settings
    finally:
        similarity.ANCHOR, fp_builder.HDBSCAN = old_anchor, old_hdb


# ------------------------------------------------------------- experiments
def e1_adapters(fixtures: Path) -> list[dict]:
    rows = []
    fields = ["packets", "bytes", "duration", "tcp_flags", "syn_count", "username", "password", "command",
              "http_path", "user_agent", "dst_ip"]
    for p in sorted(fixtures.iterdir()):
        a = detect_adapter(p)
        if a is None:
            continue
        evs, _ = load_events(p)
        t0 = time.perf_counter()
        reps = 40
        for _ in range(reps):
            n = sum(1 for _ in a.iter_events(p))
        dt = (time.perf_counter() - t0) / reps
        labels = Counter(e.ground_truth_label for e in evs)
        rows.append({
            "file": p.name, "adapter": a.name, "records": len(evs),
            "labelled": sum(v for k, v in labels.items() if k), "classes": len([k for k in labels if k]),
            "mapped": sorted({map_label(k) for k in labels if k}),
            "coverage": {f: round(sum(1 for e in evs if getattr(e, f) not in (None, "")) / len(evs), 3) for f in fields},
            "records_per_s": round(n / dt) if dt > 0 else None,
        })
    return rows


def run_returning(cat: Catalog, sid: dict, fname: str, label: str, split: float, seed: int,
                  settings: Settings) -> dict:
    plan = build_returning(cat, sid[fname], label, split=split, remap_seed=seed, demo_script=True)
    start_b = plan.selections[-1].offset
    p = Pipeline(settings, state_dir=tmp())
    p.start(plan, BASE, reset_learning=True)
    p.run_headless()
    m = p.evaluator.metrics()
    ret = m["returning"]["details"][0] if m["returning"]["details"] else {}
    ralerts = [a for a in p.alerts.list() if a.type == "returning"]
    camp_b = next((c for c in m["campaigns"] if c["campaign_id"].endswith("#B")), {})
    camp_a = next((c for c in m["campaigns"] if c["campaign_id"].endswith("#A")), {})
    fp = p.store.get(ret["shared_fingerprints"][0]) if ret.get("shared_fingerprints") else None
    return {
        "source": fname, "label": label, "behaviour": map_label(label), "split": split, "seed": seed,
        "recognised": bool(ret.get("recognised")), "returning_alert": bool(ret.get("returning_alert")),
        "score": round(ralerts[0].score, 4) if ralerts else None,
        "alert_delay_s": round(ralerts[0].first_seen - (BASE + start_b), 2) if ralerts else None,
        "b_events": camp_b.get("events"), "b_dropped": camp_b.get("dropped"),
        "b_drop_ratio": round(camp_b["dropped"] / camp_b["events"], 3) if camp_b.get("events") else None,
        "ttd_a": camp_a.get("time_to_detect"), "ttr_a": camp_a.get("time_to_rule"),
        "fp_category": fp.category if fp else None, "fp_confidence": fp.confidence if fp else None,
        "n_fingerprints": len(p.store.by_status("active")),
    }


def e2_returning(cat: Catalog, sid: dict, settings_factory=Settings, splits=(0.3, 0.5, 0.7), seeds=(7, 11)) -> list[dict]:
    rows = []
    for fname, label in RETURNING_CASES:
        for split in splits:
            for seed in seeds:
                rows.append(run_returning(cat, sid, fname, label, split, seed, settings_factory()))
    return rows


def run_mixed(cat: Catalog, sid: dict, settings: Settings) -> dict:
    p = Pipeline(settings, state_dir=tmp())
    p.start(build_custom(cat, mixed_items(sid), "fixture mix"), BASE, reset_learning=True)
    t0 = time.perf_counter()
    p.run_headless()
    wall = time.perf_counter() - t0
    m = p.evaluator.metrics()
    attack_fps = [f for f in p.store.by_status("active") if not f.benign]
    return {
        "binary": m["binary"], "online": {k: m["online"][k] for k in ("macro", "accuracy", "per_class")},
        "final": {k: m["final"][k] for k in ("macro", "accuracy", "per_class", "confusion")},
        "windows": m["windows_evaluated"], "events": p.counters["events"], "wall_s": round(wall, 2),
        "n_fingerprints": len(p.store.by_status("active")), "n_attack_fps": len(attack_fps),
        "attack_categories": sorted({f.category for f in attack_fps}),
        "mean_ttd": m["mean_time_to_detect"], "mean_ttr": m["mean_time_to_rule"],
    }


def e3_ablations(cat: Catalog, sid: dict) -> list[dict]:
    names = ["full", "numeric_only", "categorical_only", "no_anchor", "thr_0.75", "thr_0.80", "thr_0.90", "thr_0.95",
             "dbscan_0.5", "dbscan_1.0", "dbscan_2.0"]
    rows = []
    for name in names:
        with variant(name, Settings()) as s:
            mixed = run_mixed(cat, sid, s)
        rets = []
        for fname, label in RETURNING_CASES:
            with variant(name, Settings()) as s:
                rets.append(run_returning(cat, sid, fname, label, 0.5, 7, s))
        rows.append({
            "variant": name, "binary_f1": mixed["binary"]["f1"], "binary_p": mixed["binary"]["precision"],
            "binary_r": mixed["binary"]["recall"], "macro_f1_online": mixed["online"]["macro"]["f1"],
            "macro_f1_final": mixed["final"]["macro"]["f1"], "n_attack_fps": mixed["n_attack_fps"],
            "returning_recognised": sum(r["recognised"] for r in rets), "returning_alerted": sum(r["returning_alert"] for r in rets),
            "returning_cases": len(rets),
            "mean_score": round(statistics.mean([r["score"] for r in rets if r["score"] is not None]), 4)
            if any(r["score"] is not None for r in rets) else None,
        })
    return rows


def e4_rules_firewall() -> dict:
    from collections import Counter as C
    from app.fingerprint.store import Fingerprint
    from app.labels import severity_of
    allow = Allowlist(["10.0.0.0/8"])
    gen = RuleGenerator(Settings(rule_mode="auto"), allow)

    def fp(cat, i):
        return Fingerprint(id=f"FP-{i:04d}", name=cat, category=cat, severity=severity_of(cat), confidence=1.0,
                           status="active", centroid=np.zeros(len(FEATURES)), spread=np.zeros(len(FEATURES)),
                           n_windows=10, tokens={"port": C({"80": 5, "22": 3}), "path": C({"/.env": 2}),
                                                 "cmd": C({"wget": 2, "chmod": 1})}, first_seen=0, last_seen=0)
    render = {}
    rules = []
    for i, cat in enumerate(sorted(STRATEGY)):
        ips = [f"45.{i}.0.{k}" for k in range(1, 30)]
        t0 = time.perf_counter()
        r, _ = gen.ensure(fp(cat, i), {"id": f"e{i}"}, ips, 0.0, False, None)
        if r is None:
            continue
        for _ in range(200):
            r.render()
        render[r.kind] = round((time.perf_counter() - t0) / 201 * 1e3, 4)
        gen.approve(r.id, 0.0)
        rules.append(r)
    fw = SimulatedFirewall(allow)
    fw.set_rules(gen.active())
    rng = np.random.RandomState(0)
    evs = []
    for k in range(200_000):
        if k % 4 == 0:
            ip = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"  # allowlisted
        elif k % 4 == 1:
            ip = rules[rng.randint(len(rules))].params.get("ips", ["45.0.0.1"])[0] if rules else "45.0.0.1"
        else:
            ip = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        proto = ["TCP", "UDP", "ICMP"][k % 3]
        evs.append(Event(timestamp=k * 1e-4, src_ip=ip, dst_port=[80, 22, 53][k % 3], protocol=proto,
                         tcp_flags="S" if proto == "TCP" else None, dst_service=["http", "ssh", "dns"][k % 3]))
    t0 = time.perf_counter()
    dropped = [fw.check(e) for e in evs]
    dt = time.perf_counter() - t0
    allow_drops = sum(1 for e, d in zip(evs, dropped) if d and allow.contains(e.src_ip))
    allow_total = sum(1 for e in evs if allow.contains(e.src_ip))
    return {"rules": len(rules), "kinds": sorted({r.kind for r in rules}), "render_ms_per_rule": render,
            "firewall_events": len(evs), "firewall_events_per_s": round(len(evs) / dt),
            "dropped": sum(1 for d in dropped if d), "allowlisted_events": allow_total,
            "allowlisted_dropped": allow_drops}


def e5_throughput(cat: Catalog, sid: dict) -> dict:
    items = [
        dict(source_id=sid["cicddos2019_sample.csv"], labels=["Syn"], repeat=2000, compress=2, remap_ips=True),
        dict(source_id=sid["cicddos2019_sample.csv"], labels=["DrDoS_DNS"], repeat=1500, compress=2, offset=5),
        dict(source_id=sid["cicids2017_sample.csv"], labels=["BENIGN"], repeat=400, repeat_new_ips=True, compress=6000),
        dict(source_id=sid["cicids2017_sample.csv"], labels=["SSH-Patator"], repeat=40, compress=8, offset=40),
    ]
    p = Pipeline(Settings(), state_dir=tmp())
    p.start(build_custom(cat, items, "throughput"), BASE, reset_learning=True)
    timings = {"process": [], "window": [], "match": [], "cluster": []}

    def timed(obj, attr, key):
        f = getattr(obj, attr)

        def w(*a, **k):
            t0 = time.perf_counter()
            r = f(*a, **k)
            timings[key].append(time.perf_counter() - t0)
            return r
        setattr(obj, attr, w)
    timed(p.extractor, "compute", "window")
    timed(p.matcher, "process", "match")
    timed(p.fpe, "cluster", "cluster")
    t0 = time.perf_counter()
    p.run_headless()
    wall = time.perf_counter() - t0
    buf = [b.w.x for b in p.fpe.buffer]
    scale = []
    from sklearn.cluster import HDBSCAN
    for n in (250, 500, 1000, 2000):
        if len(buf) < 50:
            break
        X = np.vstack([buf[i % len(buf)] for i in range(n)]) + np.random.RandomState(n).normal(0, 1e-3, (n, len(FEATURES)))
        Z = p.scaler.transform(X)
        t1 = time.perf_counter()
        HDBSCAN(min_cluster_size=5, min_samples=3, allow_single_cluster=True).fit_predict(Z)
        scale.append({"windows": n, "seconds": round(time.perf_counter() - t1, 4)})
    ms = lambda v: round(1e3 * statistics.mean(v), 3) if v else None  # noqa: E731
    p95 = lambda v: round(1e3 * float(np.percentile(v, 95)), 3) if v else None  # noqa: E731
    return {"events": p.counters["events"], "replay_seconds": round(p.engine.t, 1), "wall_s": round(wall, 2),
            "events_per_s": round(p.counters["events"] / wall), "speedup_vs_realtime": round(p.engine.t / wall, 1),
            "window_ms_mean": ms(timings["window"]), "window_ms_p95": p95(timings["window"]),
            "match_ms_mean": ms(timings["match"]), "match_ms_p95": p95(timings["match"]),
            "cluster_ms_mean": ms(timings["cluster"]), "cluster_ms_p95": p95(timings["cluster"]),
            "n_windows": len(timings["window"]), "n_cluster_runs": len(timings["cluster"]),
            "hdbscan_scaling": scale}


def e6_demo(data_dirs: list[Path], out: Path) -> dict:
    cat = Catalog(data_dirs, tmp() / "c.json")
    cat.refresh()
    plan = build_demo(cat)
    p = Pipeline(Settings(), state_dir=tmp())
    p.start(plan, DEMO_EPOCH, reset_learning=True)
    p.run_headless()
    m = p.evaluator.metrics()
    fam = {"benign": "benign", "unmatched": "unclassified", "unknown_anomaly": "unknown", "ssh_bruteforce": "attack"}
    with open(out / "demo_timeline.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["t", "benign", "unclassified", "attack", "unknown", "dropped"])
        for row in p.series_list(1000):
            c = Counter()
            for k, v in row["by_cat"].items():
                c[fam.get(k, "attack")] += v
            w.writerow([round(row["t"] - DEMO_EPOCH, 1), c["benign"], c["unclassified"], c["attack"], c["unknown"],
                        row["dropped"]])
    story = [{"t": round(n["t"] - DEMO_EPOCH, 1), "kind": n["kind"], "text": n["text"]} for n in p.narration]
    return {"plan": plan.name, "note": plan.note, "events": dict(p.counters), "story": story,
            "binary": m["binary"], "returning": {k: m["returning"][k] for k in ("replays", "recognised", "alerted")},
            "mean_ttd": m["mean_time_to_detect"], "mean_ttr": m["mean_time_to_rule"],
            "macro_online": m["online"]["macro"], "macro_final": m["final"]["macro"],
            "alerts": [{"type": a.type, "severity": a.severity, "count": a.count, "score": round(a.score, 3)}
                       for a in p.alerts.list()],
            "rules": [{"id": r.id, "kind": r.kind, "status": r.status, "hits": r.hits} for r in p.rules.list()]}


def env_info() -> dict:
    cpu = platform.processor()
    try:
        import subprocess
        out = subprocess.run(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).Name"],
                             capture_output=True, text=True, timeout=20).stdout.strip()
        cpu = out or cpu
    except Exception:  # noqa: BLE001
        pass
    return {"cpu": cpu, "os": platform.platform(), "python": platform.python_version(), "sklearn": sklearn.__version__,
            "numpy": np.__version__}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=DATA_DIR)
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[2] / "paper" / "results")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    cat = Catalog([FIXTURE_DIR], tmp() / "c.json")
    cat.refresh()
    sid = {s["name"]: s["id"] for s in cat.list()}
    res = {"env": env_info(), "data_source": "fixtures"}
    steps = [("e1_adapters", lambda: e1_adapters(FIXTURE_DIR)), ("e2_returning", lambda: e2_returning(cat, sid)),
             ("e3_mixed_full", lambda: run_mixed(cat, sid, Settings())), ("e3_ablations", lambda: e3_ablations(cat, sid)),
             ("e4_rules_firewall", e4_rules_firewall), ("e5_throughput", lambda: e5_throughput(cat, sid)),
             ("e6_demo", lambda: e6_demo([args.data, FIXTURE_DIR], args.out))]
    for name, fn in steps:
        t0 = time.perf_counter()
        res[name] = fn()
        print(f"{name}: {time.perf_counter() - t0:.1f}s", flush=True)
        (args.out / "results.json").write_text(json.dumps(res, indent=1, default=str))
    print("wrote", args.out / "results.json")


if __name__ == "__main__":
    main()
