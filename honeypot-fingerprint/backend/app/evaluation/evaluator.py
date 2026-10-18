"""Evaluation against dataset ground truth. The only module that reads labels.

It receives full events (with labels) from the capture layer, and window-level detection
results (entity + member event seqs, no labels) from the pipeline, and joins them here.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Optional

from ..labels import CATEGORY_NAMES, UNKNOWN, is_benign, map_label
from ..schemas import Event

MAX_RECORDS = 60_000


class Evaluator:
    def __init__(self, fp_category=None):
        # callable fp_id -> current category, so retrospective scores follow re-categorisation
        self.fp_category = fp_category or (lambda fid: None)
        self.reset()

    def reset(self) -> None:
        self.seq_info: dict[int, tuple[str, str, float]] = {}
        self.seq_order: deque = deque()
        self.records: dict[int, dict] = {}
        self.record_order: deque = deque()
        self.campaigns: dict[str, dict] = {}
        self.campaign_meta: dict[str, dict] = {}
        self.returning_alerts: list[dict] = []
        self.fp_campaign_hits: dict[str, Counter] = defaultdict(Counter)
        self.dropped_by_label: Counter = Counter()

    def register_campaigns(self, campaigns: list[dict]) -> None:
        for c in campaigns:
            self.campaign_meta[c["campaign_id"]] = {"parent_id": c.get("parent_id"), "label": c.get("label"),
                                                    "ips": set(c.get("ips", []))}

    # ------------------------------------------------------------ ingestion
    def observe_events(self, events: list[Event]) -> None:
        for e in events:
            beh = map_label(e.ground_truth_label)
            c = self.campaigns.setdefault(e.campaign_id, {
                "campaign_id": e.campaign_id, "label": e.ground_truth_label, "behaviour": beh or "unlabelled",
                "first_ts": e.timestamp, "events": 0, "dropped": 0, "ips": set(), "detected_ts": None,
                "rule_ts": None, "fps": Counter()})
            c["events"] += 1
            c["ips"].add(e.src_ip)
            if e.action == "dropped":
                c["dropped"] += 1
                self.dropped_by_label[beh or "unlabelled"] += 1
                continue
            self.seq_info[e.seq] = (beh, e.campaign_id, e.timestamp)
            self.seq_order.append((e.timestamp, e.seq))

    def prune(self, before: float) -> None:
        while self.seq_order and self.seq_order[0][0] < before:
            _, s = self.seq_order.popleft()
            self.seq_info.pop(s, None)

    def observe_detection(self, window_id: int, seqs: list[int], category: str, fp_id: Optional[str], t: float,
                          kind: str) -> None:
        labels = Counter()
        camps = Counter()
        for s in seqs:
            info = self.seq_info.get(s)
            if not info:
                continue
            beh, cid, _ = info
            if beh:
                labels[beh] += 1
            camps[cid] += 1
        if not labels:
            return
        truth = labels.most_common(1)[0][0]
        attack_pred = category not in ("unmatched",) and not is_benign(category)
        self.records[window_id] = {"truth": truth, "online": category, "final": category, "t": t,
                                   "fp": fp_id, "attack_pred": attack_pred, "camps": list(camps)}
        self.record_order.append(window_id)
        while len(self.record_order) > MAX_RECORDS:
            self.records.pop(self.record_order.popleft(), None)
        for cid in camps:
            c = self.campaigns.get(cid)
            if not c:
                continue
            if fp_id and kind == "match":
                c["fps"][fp_id] += 1
                self.fp_campaign_hits[fp_id][cid] += 1
            if attack_pred and c["detected_ts"] is None and not is_benign(c["behaviour"]):
                c["detected_ts"] = t

    def reassign(self, window_id: int, category: str, fp_id: str) -> None:
        r = self.records.get(window_id)
        if r:
            r["final"] = category
            r["fp"] = r["fp"] or fp_id
            for cid in r["camps"]:
                c = self.campaigns.get(cid)
                if c is not None:
                    c["fps"][fp_id] += 1
                    self.fp_campaign_hits[fp_id][cid] += 1

    def observe_rule(self, fp_id: str, ips: list[str], t: float) -> None:
        ipset = set(ips)
        for c in self.campaigns.values():
            if c["rule_ts"] is not None or is_benign(c["behaviour"]):
                continue
            if c["fps"].get(fp_id) or (ipset & c["ips"]):
                c["rule_ts"] = t

    def observe_returning_alert(self, fp_id: str, ips: list[str], t: float) -> None:
        self.returning_alerts.append({"fp_id": fp_id, "ips": set(ips), "t": t})

    # -------------------------------------------------------------- metrics
    def metrics(self) -> dict:
        recs = list(self.records.values())
        out: dict = {"windows_evaluated": len(recs)}
        if not recs:
            out.update(empty=True, campaigns=self._campaign_rows(), returning=self._returning())
            return out
        for r in recs:
            if r["fp"]:
                r["final"] = self.fp_category(r["fp"]) or r["final"]
        for mode in ("online", "final"):
            truth = [r["truth"] for r in recs]
            pred = [r[mode] for r in recs]
            labels_t = sorted(set(truth))
            labels_p = sorted(set(pred) | set(labels_t))
            cm = Counter(zip(truth, pred))
            per_class = {}
            for lab in labels_t:
                tp = cm[(lab, lab)]
                fp = sum(v for (t, p), v in cm.items() if p == lab and t != lab)
                fn = sum(v for (t, p), v in cm.items() if t == lab and p != lab)
                prec = tp / (tp + fp) if tp + fp else 0.0
                rec = tp / (tp + fn) if tp + fn else 0.0
                f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
                per_class[lab] = {"precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
                                  "support": sum(v for (t, _), v in cm.items() if t == lab)}
            macro = {k: round(sum(p[k] for p in per_class.values()) / len(per_class), 3)
                     for k in ("precision", "recall", "f1")}
            out[mode] = {
                "confusion": {"rows": labels_t, "cols": labels_p,
                              "matrix": [[cm[(t, p)] for p in labels_p] for t in labels_t]},
                "per_class": per_class, "macro": macro, "accuracy": round(sum(cm[(l, l)] for l in labels_t) / len(recs), 3),
            }
        # binary attack-vs-benign detection (online)
        tp = sum(1 for r in recs if r["attack_pred"] and not is_benign(r["truth"]))
        fp = sum(1 for r in recs if r["attack_pred"] and is_benign(r["truth"]))
        fn = sum(1 for r in recs if not r["attack_pred"] and not is_benign(r["truth"]))
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        out["binary"] = {"precision": round(prec, 3), "recall": round(rec, 3),
                         "f1": round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0.0,
                         "tp": tp, "fp": fp, "fn": fn, "tn": len(recs) - tp - fp - fn}
        rows = self._campaign_rows()
        ttd = [c["time_to_detect"] for c in rows if c["time_to_detect"] is not None]
        ttr = [c["time_to_rule"] for c in rows if c["time_to_rule"] is not None]
        out["mean_time_to_detect"] = round(sum(ttd) / len(ttd), 2) if ttd else None
        out["mean_time_to_rule"] = round(sum(ttr) / len(ttr), 2) if ttr else None
        out["campaigns"] = rows
        out["returning"] = self._returning()
        out["dropped_by_label"] = dict(self.dropped_by_label)
        out["category_names"] = CATEGORY_NAMES
        return out

    def _campaign_rows(self) -> list[dict]:
        rows = []
        for c in self.campaigns.values():
            rows.append({
                "campaign_id": c["campaign_id"], "label": c["label"], "behaviour": c["behaviour"],
                "events": c["events"], "dropped": c["dropped"], "n_ips": len(c["ips"]),
                "time_to_detect": None if c["detected_ts"] is None else round(c["detected_ts"] - c["first_ts"], 2),
                "time_to_rule": None if c["rule_ts"] is None else round(c["rule_ts"] - c["first_ts"], 2),
                "fingerprints": [f for f, _ in c["fps"].most_common(3)],
                "parent_id": self.campaign_meta.get(c["campaign_id"], {}).get("parent_id"),
            })
        return sorted(rows, key=lambda r: r["campaign_id"])

    def _returning(self) -> dict:
        replays = [(cid, m) for cid, m in self.campaign_meta.items() if m.get("parent_id")]
        details = []
        for cid, m in replays:
            child = self.campaigns.get(cid)
            parent = self.campaigns.get(m["parent_id"])
            if not child:
                continue
            parent_fps = set(parent["fps"]) if parent else set()
            shared = [f for f in child["fps"] if f in parent_fps]
            alert = any(a["fp_id"] in parent_fps and (a["ips"] & child["ips"]) for a in self.returning_alerts)
            details.append({"campaign_id": cid, "parent_id": m["parent_id"], "recognised": bool(shared),
                            "returning_alert": alert, "shared_fingerprints": shared,
                            "child_windows_on_parent_fp": sum(child["fps"][f] for f in shared)})
        n = len(details)
        return {"replays": n, "recognised": sum(d["recognised"] for d in details),
                "alerted": sum(d["returning_alert"] for d in details),
                "rate": round(sum(d["recognised"] for d in details) / n, 3) if n else None,
                "alert_rate": round(sum(d["returning_alert"] for d in details) / n, 3) if n else None,
                "details": details}
