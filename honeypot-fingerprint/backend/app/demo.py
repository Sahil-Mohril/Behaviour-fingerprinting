"""Deterministic demo, headless: `python -m app.demo` (add --data DIR to pick a data folder).

Runs the same scripted plan as the dashboard's Demo button (fixed seed and remap), prints
the story and the evaluation metrics. Uses CIC-IDS2017 / CIC-DDoS2019 / Zeek data from the
data folder when present, otherwise the bundled fixtures (looped, very small).
"""
from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from .adapters.catalog import Catalog
from .config import DATA_DIR, FIXTURE_DIR, Settings
from .pipeline import Pipeline
from .replay.plans import build_demo

DEMO_EPOCH = 1_767_225_600.0  # fixed base epoch keeps runs byte-identical


def run(data_dirs: list[Path], quiet: bool = False) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="hfp-demo-"))
    cat = Catalog(data_dirs, tmp / "catalog.json")
    cat.refresh()
    plan = build_demo(cat)
    p = Pipeline(Settings(), state_dir=tmp)
    t0 = time.time()
    p.start(plan, DEMO_EPOCH, reset_learning=True)
    p.run_headless()
    m = p.evaluator.metrics()
    result = {
        "plan": plan.name, "note": plan.note, "runtime_s": round(time.time() - t0, 2),
        "events": dict(p.counters),
        "story": [{"t": round(n["t"] - DEMO_EPOCH, 1), "kind": n["kind"], "text": n["text"]} for n in p.narration],
        "fingerprints": [f.summary() for f in p.store.fps.values()],
        "alerts": [{"id": a.id, "type": a.type, "severity": a.severity, "count": a.count, "title": a.title}
                   for a in p.alerts.list()],
        "rules": [{"id": r.id, "kind": r.kind, "status": r.status, "dropped": r.hits} for r in p.rules.list()],
        "metrics": {k: m.get(k) for k in ("binary", "mean_time_to_detect", "mean_time_to_rule", "returning",
                                          "windows_evaluated")},
        "macro_online": m.get("online", {}).get("macro"), "macro_final": m.get("final", {}).get("macro"),
    }
    if not quiet:
        print(f"== {result['plan']} ==\n{result['note']}\n")
        for s in result["story"]:
            print(f"[T+{s['t']:6.1f}s] {s['kind']:<11} {s['text']}")
        print("\nfingerprints:")
        for f in result["fingerprints"]:
            print(f"  {f['id']} {f['status']:<9} {f['category']:<18} conf={f['confidence']:.2f} hits={f['hit_count']}")
        print("alerts:")
        for a in result["alerts"]:
            print(f"  {a['id']} {a['type']:<15} {a['severity']:<8} x{a['count']:<4} {a['title']}")
        print("rules:")
        for r in result["rules"]:
            print(f"  {r['id']} {r['kind']:<12} {r['status']:<10} dropped={r['dropped']}")
        print("\nmetrics:", json.dumps(result["metrics"], indent=1, default=str))
        print("macro (online / after clustering):", result["macro_online"], result["macro_final"])
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, default=DATA_DIR)
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args()
    res = run([args.data, FIXTURE_DIR], quiet=args.json)
    if args.json:
        print(json.dumps(res, indent=1, default=str))


if __name__ == "__main__":
    main()
