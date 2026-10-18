"""Plan builders: custom mixes, "returning attacker" splits and the scripted demo."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Optional

from ..adapters.catalog import Catalog, load_events
from ..labels import is_benign, map_label
from .engine import ReplayPlan, ScriptStep, Selection


class PlanError(ValueError):
    pass


def _source(catalog: Catalog, sid: str) -> dict:
    s = catalog.get(sid)
    if not s:
        raise PlanError(f"unknown source {sid}")
    if s.get("status") != "ready":
        raise PlanError(f"source {s['name']} is not ready ({s.get('status')})")
    return s


def _benign_labels(src: dict) -> list[str]:
    return [l for l in src["labels"] if map_label(l) and is_benign(map_label(l))]


def build_custom(catalog: Catalog, items: list[dict], name: str = "Custom mix") -> ReplayPlan:
    """items: [{source_id, labels?, t_from?, t_to?, offset?, compress?, max_rows?, sample_every?,
    remap_ips?, remap_seed?, label_override?, repeat?, repeat_new_ips?}]"""
    if not items:
        raise PlanError("select at least one source")
    plan = ReplayPlan(name=name, mode="custom")
    for k, it in enumerate(items):
        src = _source(catalog, it["source_id"])
        labels = it.get("labels") or None
        plan.selections.append(Selection(
            source_id=src["id"], path=src["path"], adapter=src["adapter"], labels=labels,
            t_from=it.get("t_from"), t_to=it.get("t_to"), offset=float(it.get("offset", 0.0)),
            compress=float(it.get("compress", 1.0)), max_rows=int(it.get("max_rows", 50_000)),
            sample_every=max(1, int(it.get("sample_every", 1))), remap_ips=bool(it.get("remap_ips", False)),
            remap_seed=int(it.get("remap_seed", 1000 + k)), label_override=it.get("label_override") or None,
            repeat=max(1, int(it.get("repeat", 1))), repeat_new_ips=bool(it.get("repeat_new_ips", False)),
            name=f"{src['name']}#{k + 1}",
        ))
    return plan


BACKGROUND_RATE = 40.0  # target benign events per replay second
MIN_PART_RECORDS = 60  # records per returning-attacker part before looping kicks in


def background_selection(src: dict, label: str, total: float) -> Selection:
    """Benign slice sized from the catalog so it spans the plan at ~BACKGROUND_RATE events/s.
    Tiny sources (fixtures) are looped to reach a usable volume."""
    info = src["labels"][label]
    count = info["count"]
    span = max(1.0, (info.get("t_max") or 0) - (info.get("t_min") or 0))
    needed = BACKGROUND_RATE * total
    sel = Selection(source_id=src["id"], path=src["path"], adapter=src["adapter"], labels=[label], offset=0.0,
                    name="background", campaign_id=f"{src['name']}:{label}")
    if count >= needed:
        rate = count / span
        sel.compress = max(1.0, min(BACKGROUND_RATE / max(rate, 1e-9), span / total))
        sel.max_rows = int(min(60_000, rate * sel.compress * total * 1.05 + 10))
    else:
        target = min(needed, 2000)
        sel.repeat = max(1, math.ceil(target / max(1, count)))
        sel.repeat_new_ips = True
        looped = sel.repeat * span * (1 + 1 / max(1, count - 1))
        sel.compress = max(1e-3, looped / total)
        sel.max_rows = count
    return sel


def _attack_events(src: dict, label: str, max_rows: int):
    evs, _ = load_events(Path(src["path"]), src["adapter"], [label], max_rows=max_rows)
    if len(evs) < 4:
        raise PlanError(f"label {label!r} has only {len(evs)} records in {src['name']}")
    return evs


def build_returning(catalog: Catalog, source_id: str, label: str, split: float = 0.5,
                    target_seconds: float = 60.0, gap: float = 30.0, baseline: float = 30.0,
                    include_benign: bool = True, remap_seed: int = 7, max_rows: int = 40_000,
                    fast_warmup: bool = True, demo_script: bool = False) -> ReplayPlan:
    """Split one attack class in time: part A builds fingerprints, part B returns from remapped IPs."""
    src = _source(catalog, source_id)
    evs = _attack_events(src, label, max_rows)
    split = min(0.9, max(0.1, split))
    cut = max(2, min(len(evs) - 2, int(len(evs) * split)))
    a0, a1 = evs[0].timestamp, evs[cut - 1].timestamp
    b0, b1 = evs[cut].timestamp, evs[-1].timestamp
    # very short classes (e.g. test fixtures) are looped so each part yields enough windows
    rep_a = max(1, math.ceil(MIN_PART_RECORDS / cut))
    rep_b = max(1, math.ceil(MIN_PART_RECORDS / (len(evs) - cut)))
    def looped(t0, t1, n, rep):
        span = max(1e-3, t1 - t0)
        return span if rep == 1 else rep * span * (1 + 1 / max(1, n - 1))
    span_a = looped(a0, a1, cut, rep_a)
    span_b = looped(b0, b1, len(evs) - cut, rep_b)
    compress = span_a / target_seconds if rep_a > 1 else max(1.0, span_a / target_seconds)
    dur_a = span_a / compress
    dur_b = span_b / compress
    start_a = baseline
    start_b = start_a + dur_a + gap
    total = start_b + dur_b + 20
    cid = f"{src['name']}:{label}"
    plan = ReplayPlan(name=f"Returning attacker: {label}", mode="returning", duration=total,
                      fast_until=(start_b - 3) if fast_warmup else 0.0,
                      note=f"Part A ({cut} records) builds the fingerprint; part B ({len(evs) - cut} records) "
                           f"returns from remapped IPs. Dataset time compressed {compress:.1f}x."
                           + (f" Short slices looped (A x{rep_a}, B x{rep_b})." if rep_a > 1 or rep_b > 1 else ""))
    if include_benign:
        for bl in _benign_labels(src)[:1]:
            plan.selections.append(background_selection(src, bl, total))
    plan.selections.append(Selection(source_id=src["id"], path=src["path"], adapter=src["adapter"], labels=[label],
                                     t_from=a0, t_to=a1, offset=start_a, compress=compress, max_rows=max_rows,
                                     repeat=rep_a, name="part A", campaign_id=f"{cid}#A"))
    plan.selections.append(Selection(source_id=src["id"], path=src["path"], adapter=src["adapter"], labels=[label],
                                     t_from=b0, t_to=b1, offset=start_b, compress=compress, max_rows=max_rows,
                                     remap_ips=True, remap_seed=remap_seed, repeat=rep_b, name="part B",
                                     campaign_id=f"{cid}#B", parent_campaign=f"{cid}#A"))
    end_a = start_a + dur_a
    plan.script += [
        ScriptStep(0.0, "narrate", {"text": "Baseline: replaying benign traffic to calibrate the scaler and anomaly model."}),
        ScriptStep(start_a, "narrate", {"text": f"Part A of '{label}' starts ({cut} records, original IPs)."}),
        ScriptStep(end_a + 2, "force_cluster", {}),
        ScriptStep(end_a + 2.5, "narrate", {"text": "Part A finished: fingerprints built from it."}),
        ScriptStep(start_b, "narrate", {"text": f"Part B returns from remapped IPs, timestamps shifted to now ({len(evs) - cut} records)."}),
    ]
    if demo_script:
        plan.script.append(ScriptStep(start_b - 10, "set_mode", {"mode": "auto"}))
        plan.script.append(ScriptStep(start_b - 9.5, "narrate", {"text": "Operator switches the firewall to auto-apply (simulated firewall only)."}))
        plan.script.append(ScriptStep(total - 2, "narrate", {"text": "Demo complete. See the Evaluation page for metrics.", "kind": "done"}))
    plan.script.sort(key=lambda s: s.t)
    return plan


DEMO_PREFERENCE = ["SSH-Patator", "FTP-Patator", "PortScan", "DoS Hulk", "Syn", "DrDoS_DNS",
                   "PartOfAHorizontalPortScan", "DDoS"]


def pick_demo_source(catalog: Catalog) -> tuple[dict, str, bool]:
    """Prefer real datasets (non-fixture) with a well-known attack label; fall back to fixtures."""
    for fixture in (False, True):
        for want in DEMO_PREFERENCE:
            s = catalog.find(lambda s: s.get("fixture", False) == fixture and s["labels"].get(want, {}).get("count", 0) >= 8)
            if s:
                return s, want, fixture
    raise PlanError("no source with a demo-capable attack label; add CIC-IDS2017 CSVs to the data folder")


def build_demo(catalog: Catalog) -> ReplayPlan:
    src, label, fixture = pick_demo_source(catalog)
    plan = build_returning(catalog, src["id"], label, split=0.45, target_seconds=50.0, gap=30.0, baseline=30.0,
                           include_benign=True, remap_seed=2024, max_rows=12_000, fast_warmup=False,
                           demo_script=True)
    plan.name = f"Demo: {label} returns from new IPs"
    plan.mode = "demo"
    plan.duration = max(plan.duration or 0, 180.0)
    if fixture:
        plan.note = ("Running on bundled test fixtures (very few records): download CIC-IDS2017 into the data "
                     "folder for the full demo. " + plan.note)
    return plan
