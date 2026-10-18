"""Pipeline orchestrator: replay -> decoys -> simulated firewall -> capture -> features ->
detection -> alerts -> rules, plus periodic clustering. Synchronous and deterministic; the
runtime calls it from a background thread, tests and the CLI demo call it directly.
"""
from __future__ import annotations

import itertools
from collections import Counter, deque
from typing import Optional

import numpy as np

from .alerts.manager import AlertManager
from .config import STATE_DIR, Settings
from .detection.anomaly import AnomalyModel
from .detection.matcher import Detection, LiveMatcher, touch_episode
from .evaluation.evaluator import Evaluator
from .features.extractor import FEATURES, FeatureExtractor, WindowVector, shape_key
from .fingerprint.builder import FingerprintEngine
from .fingerprint.scaler import BaselineScaler
from .fingerprint.store import Fingerprint, FingerprintStore
from .geoip import lookup
from .honeypot.services import DecoyServices
from .labels import CATEGORY_NAMES, is_benign, severity_rank
from .replay.engine import ReplayEngine, ReplayPlan, ScriptStep
from .rules.firewall import Allowlist, SimulatedFirewall
from .rules.generator import RuleGenerator
from .schemas import Event

DEFAULT_ALLOWLIST = [("10.0.0.0/8", "internal management network"), ("192.0.2.10/32", "uptime monitor")]
SERIES_SECONDS = 900


class Pipeline:
    def __init__(self, settings: Optional[Settings] = None, persistence=None, state_dir=STATE_DIR):
        self.settings = settings or Settings()
        self.persist = persistence
        self.state_dir = state_dir
        self.allowlist = Allowlist()
        for cidr, note in DEFAULT_ALLOWLIST:
            self.allowlist.add(cidr, note)
        self.firewall = SimulatedFirewall(self.allowlist)
        self.engine = ReplayEngine()
        self._seq = itertools.count(1)
        self._new_learning()
        self.reset_session()

    # ----------------------------------------------------------------- state
    def _new_learning(self) -> None:
        s = self.settings
        self.scaler = BaselineScaler(len(FEATURES))
        self.store = FingerprintStore()
        self.fpe = FingerprintEngine(s, self.store, self.scaler)
        self.anomaly = AnomalyModel(s.anomaly_contamination)
        self.matcher = LiveMatcher(s, self.fpe, self.anomaly)
        self.alerts = AlertManager(s.alert_dedupe_seconds)
        self.rules = RuleGenerator(s, self.allowlist)
        self.firewall.set_rules([])

    def reset_session(self) -> None:
        self.decoys = DecoyServices(self.settings)
        self.extractor = FeatureExtractor(self.settings)
        self.evaluator = Evaluator(lambda fid: (self.store.get(fid).category if self.store.get(fid) else None))
        self.counters = Counter()
        self.series: dict[int, dict] = {}
        self.markers: deque = deque(maxlen=200)
        self.recent: deque = deque(maxlen=500)
        self.narration: deque = deque(maxlen=100)
        self.ip_cat: dict[str, str] = {}
        self.group_cat: dict[str, str] = {}
        self.attackers: dict[str, float] = {}
        self.baseline_x: list[np.ndarray] = []
        self.baseline_ready = self.scaler.has_baseline and self.anomaly.ready
        self.next_window_end: Optional[float] = None
        self.last_cluster: Optional[float] = None
        self.outbox = {"events": [], "alerts": {}, "fingerprints": {}, "rules": {}, "narration": [], "markers": []}
        self.fpe.buffer = []
        self.started_at: Optional[float] = None

    def reset_all(self) -> None:
        self._new_learning()
        self.reset_session()
        if self.persist:
            self.persist.wipe()

    def load_persisted(self) -> None:
        if not self.persist:
            return
        st = self.persist.load_settings()
        if st:
            self.settings.update(st)
        self.store.load(self.persist.load_all("fingerprint"))
        self.alerts.load(self.persist.load_all("alert"))
        self.rules.load(self.persist.load_all("rule"))
        al = self.persist.load_allowlist()
        if al is not None:
            self.allowlist.entries.clear()
            for c, n in al:
                self.allowlist.add(c, n)
        if self.scaler.load(self.state_dir / "scaler.joblib"):
            self.baseline_ready = False  # anomaly model is refit on each session's baseline
        self.sync_firewall()

    # ------------------------------------------------------------- lifecycle
    def start(self, plan: ReplayPlan, base_epoch: float, reset_learning: bool = False, loader=None) -> None:
        if reset_learning:
            self.reset_all()
        self.reset_session()
        kw = {"loader": loader} if loader else {}
        self.engine.load(plan, base_epoch, **kw)
        self.evaluator.register_campaigns(self.engine.campaign_list())
        self.next_window_end = base_epoch + self.settings.hop_seconds
        self.last_cluster = base_epoch
        self.started_at = base_epoch
        self.say(base_epoch, f"Loaded plan '{plan.name}': {self.engine.total_events} events from "
                             f"{len(plan.selections)} selection(s).", "info")
        if plan.note:
            self.say(base_epoch, plan.note, "info")

    def say(self, t: float, text: str, kind: str = "info") -> None:
        n = {"t": t, "text": text, "kind": kind}
        self.narration.append(n)
        self.outbox["narration"].append(n)

    def step(self) -> int:
        """Advance the replay by one step. Returns the number of events processed."""
        if self.engine.state in ("idle", "finished"):
            return 0
        events, fired = self.engine.step()
        now = self.engine.now
        for s in fired:
            self.apply_script(s, now)
        self.process(events, now)
        if self.engine.state == "finished":
            self.flush_persist()
            self.say(now, "Replay finished.", "done")
        return len(events)

    def run_headless(self, max_steps: int = 10_000_000) -> None:
        self.engine.state = "running"
        n = 0
        while self.engine.state == "running" and n < max_steps:
            self.step()
            n += 1
        self.flush_persist()

    def apply_script(self, s: ScriptStep, now: float) -> None:
        if s.action == "narrate":
            self.say(now, s.args.get("text", ""), s.args.get("kind", "story"))
        elif s.action == "set_mode":
            self.settings.rule_mode = s.args.get("mode", "suggest")
            self.say(now, f"Rule mode set to '{self.settings.rule_mode}'.", "story")
        elif s.action == "force_cluster":
            self.cluster(now, force=True)

    # --------------------------------------------------------------- capture
    def process(self, events: list[Event], now: float) -> None:
        accepted_obs = []
        rows: list[dict] = []
        for e in events:
            e.seq = next(self._seq)
            e.country, e.asn = lookup(e.src_ip)
            self.decoys.respond(e)
            rid = self.firewall.check(e)
            sec = int(e.timestamp)
            b = self.series.get(sec)
            if b is None:
                b = self.series[sec] = {"t": sec, "accepted": 0, "dropped": 0, "by_cat": Counter()}
            if rid:
                e.action, e.rule_id = "dropped", rid
                self.firewall.record_drop(rid)
                b["dropped"] += 1
                self.counters["dropped"] += 1
                r = self.rules.rules.get(rid)
                if r:
                    r.hits += 1
            else:
                obs = e.observe()
                accepted_obs.append(obs)
                cat = self.ip_cat.get(e.src_ip) or self.group_cat.get(shape_key(obs)) or "unmatched"
                b["accepted"] += 1
                b["by_cat"][cat] += 1
                self.counters["accepted"] += 1
            self.counters["events"] += 1
            row = e.to_row()
            rows.append(row)
            self.recent.append(row)
        self.outbox["events"].extend(rows[-300:])
        if len(self.outbox["events"]) > 300:
            self.outbox["events"] = self.outbox["events"][-300:]
        if events:
            self.evaluator.observe_events(events)
            if self.persist:
                self.persist.save_events(rows)
        self.extractor.add(accepted_obs)
        if len(self.series) > SERIES_SECONDS:
            for k in sorted(self.series)[: len(self.series) - SERIES_SECONDS]:
                del self.series[k]
        # windows on the hop grid
        while self.next_window_end is not None and now >= self.next_window_end:
            t_end = self.next_window_end
            self.next_window_end += self.settings.hop_seconds
            self.on_window(t_end)
        expired = self.rules.expire(now)
        if expired:
            self.sync_firewall()
            for r in expired:
                self._rule_out(r)
        self._flush_dirty()

    # ---------------------------------------------------------------- windows
    def on_window(self, t_end: float) -> None:
        windows = self.extractor.compute(t_end)
        self.evaluator.prune(t_end - self.settings.window_seconds * 3)
        if not self.baseline_ready:
            self._baseline(windows, t_end)
        dets = self.matcher.process(windows, t_end) if windows else []
        for d in dets:
            self._on_detection(d, t_end)
        s = self.settings
        if self.baseline_ready and t_end - (self.last_cluster or t_end) >= s.cluster_interval_seconds:
            self.cluster(t_end)
        cutoff = t_end - 60
        self.attackers = {ip: t for ip, t in self.attackers.items() if t >= cutoff}

    def _baseline(self, windows: list[WindowVector], t_end: float) -> None:
        s = self.settings
        self.baseline_x += [w.x for w in windows]
        elapsed = t_end - (self.started_at or t_end)
        enough = len(self.baseline_x) >= 10
        if (elapsed >= s.baseline_seconds and enough) or elapsed >= 3 * s.baseline_seconds:
            X = np.vstack(self.baseline_x) if self.baseline_x else np.zeros((0, len(FEATURES)))
            if len(X):
                if not self.scaler.has_baseline:
                    self.scaler.fit_baseline(X)
                    self.scaler.save(self.state_dir / "scaler.joblib")
                self.anomaly.fit(self.scaler.transform(X))
            self.baseline_ready = True
            self.last_cluster = t_end
            self.say(t_end, f"Baseline calibrated on {len(X)} windows; anomaly model "
                            f"{'trained' if self.anomaly.ready else 'not trained (too few windows)'}.", "info")

    def _on_detection(self, d: Detection, now: float) -> None:
        w = d.window
        cat = d.category
        if d.kind != "none":
            for ip in w.ips[:200]:
                self.ip_cat[ip] = cat
            if w.kind == "group":
                self.group_cat[w.entity[4:]] = cat
        self.evaluator.observe_detection(w.id, w.seqs, cat, d.fp.id if d.fp else None, now, d.kind)
        if d.kind == "match" and d.fp and not d.fp.benign:
            for ip in w.ips[:200]:
                self.attackers[ip] = now
            fp = d.fp
            for ip in w.ips[:50]:
                c, a = lookup(ip)
                fp.countries[c] += 1
                fp.asns[a] += 1
            ex = d.explanation
            breakdown = {"score": round(d.score, 4), "numeric": round(d.numeric, 4),
                         "categorical": None if d.categorical is None else round(d.categorical, 4),
                         "weights": ex.get("weights"), "threshold": ex.get("threshold"),
                         "numeric_detail": ex.get("numeric"), "categorical_detail": ex.get("categorical")}
            if d.episode and d.episode.get("returning"):
                sev = max(fp.severity, "high", key=severity_rank)
                alert, created = self.alerts.raise_(
                    "returning", f"Returning behaviour: {fp.name}", fp.id, fp.name, fp.category, sev, now, w.ips,
                    w.entity, d.score, breakdown,
                    f"Behaviour {fp.id} seen in an earlier episode is back from {len(d.episode['ips'])} new source(s) "
                    f"with no overlap with previous sources. " + d.explanation.get("text", ""), d.episode["id"])
                if created:
                    self.evaluator.observe_returning_alert(fp.id, list(d.episode["ips"]), now)
                    self.say(now, f"RETURNING BEHAVIOUR: {fp.name} ({fp.id}) is back from new IPs "
                                  f"{', '.join(list(d.episode['ips'])[:3])} (score {d.score:.2f}).", "alert")
                else:
                    self.evaluator.observe_returning_alert(fp.id, w.ips, now)
                returning = True
            else:
                alert, created = self.alerts.raise_(
                    "match", f"{CATEGORY_NAMES.get(fp.category, fp.category)} matched {fp.id}", fp.id, fp.name,
                    fp.category, fp.severity, now, w.ips, w.entity, d.score, breakdown,
                    d.explanation.get("text", ""), d.episode["id"] if d.episode else None)
                returning = False
            self._alert_out(alert)
            self._rule_for(fp, d.episode, w.ips, now, returning, alert)
        elif d.kind == "anomaly" and d.fp is not None and d.fp.status == "candidate":
            alert, _ = self.alerts.raise_(
                "anomaly", f"Unknown anomaly: candidate {d.fp.id}", d.fp.id, d.fp.name, d.fp.category,
                "low" if d.fp.hit_count < 3 else "medium", now, w.ips, w.entity, 0.0,
                {"anomaly_score": round(d.anomaly_score, 4)}, d.explanation.get("text", ""), None)
            self._alert_out(alert)
            self._fp_out(d.fp)

    def _rule_for(self, fp: Fingerprint, episode: Optional[dict], ips: list[str], now: float, returning: bool,
                  alert) -> None:
        if severity_rank(alert.severity) < severity_rank(self.settings.rule_min_severity) and not returning:
            return
        rule, change = self.rules.ensure(fp, episode, ips, now, returning, alert.id)
        if not rule or not change:
            return
        if rule.id not in alert.rule_ids:
            alert.rule_ids.append(rule.id)
        if change == "created":
            self.evaluator.observe_rule(fp.id, rule.params.get("ips", []), now)
            self.say(now, f"Rule {rule.id} ({rule.kind}) {'' if self.settings.rule_mode == 'auto' else 'suggested '}"
                          f"for {fp.name}: {rule.reason}", "rule")
        if self.rules.auto_apply(rule, now):
            self.markers.append({"t": now, "rule_id": rule.id, "label": f"{rule.id} active"})
            self.outbox["markers"].append(self.markers[-1])
            self.say(now, f"Auto-applied {rule.id} in the simulated firewall.", "rule")
        if rule.status == "active":
            self.sync_firewall()
        self._rule_out(rule)

    # ------------------------------------------------------------- clustering
    def cluster(self, now: float, force: bool = False) -> list:
        self.last_cluster = now
        if not self.baseline_ready and not force:
            return []
        changes = self.fpe.cluster(now, force=force)
        for fp, what in changes:
            members = [b for b in self.fpe.buffer if b.fp == fp.id]
            for b in members:
                self.evaluator.reassign(b.w.id, fp.category, fp.id)
            self._fp_out(fp)
            if what == "created":
                ips = set()
                for b in members:
                    ips |= set(b.w.ips)
                start = min((b.w.t_start for b in members), default=now)
                ep, _ = touch_episode(fp, ips, start, now, self.settings.episode_gap_seconds)
                fp.ips.update(ips)
                fp.hit_count += len(members)
                self.say(now, f"New fingerprint {fp.id} '{fp.name}' from {len(members)} windows "
                              f"(confidence {fp.confidence:.2f}).", "fingerprint")
                if not fp.benign:
                    alert, _ = self.alerts.raise_(
                        "new_fingerprint", f"New fingerprint: {fp.name}", fp.id, fp.name, fp.category, fp.severity,
                        now, sorted(ips)[:200], "", 0.0, {"category_reasons": fp.category_reasons},
                        f"HDBSCAN formed a cluster of {len(members)} windows; rule layer says {fp.category} "
                        f"({'; '.join(fp.category_reasons[:3])}).", ep["id"])
                    self._alert_out(alert)
                    self._rule_for(fp, ep, sorted(ips), now, False, alert)
            elif what == "promoted":
                self.say(now, f"Candidate {fp.id} promoted to an active fingerprint by clustering.", "fingerprint")
        if changes and self.persist:
            self.scaler.save(self.state_dir / "scaler.joblib")
        return changes

    # ---------------------------------------------------------------- outputs
    def sync_firewall(self) -> None:
        self.firewall.set_rules(self.rules.active())

    def _alert_out(self, a) -> None:
        self.outbox["alerts"][a.id] = a.to_dict()

    def _fp_out(self, fp: Fingerprint) -> None:
        self.outbox["fingerprints"][fp.id] = fp.summary()

    def _rule_out(self, r) -> None:
        self.outbox["rules"][r.id] = r.to_dict()

    def _flush_dirty(self) -> None:
        for fid in list(self.store.dirty):
            fp = self.store.get(fid)
            if fp:
                self.outbox["fingerprints"][fid] = fp.summary()
        for aid in self.alerts.dirty:
            self.outbox["alerts"][aid] = self.alerts.alerts[aid].to_dict()
        for rid in self.rules.dirty:
            if rid in self.rules.rules:
                self.outbox["rules"][rid] = self.rules.rules[rid].to_dict()
        if self.persist:
            self.persist.flush_events()
            self.flush_persist(entities_only=True)
        else:
            self.store.dirty.clear()
            self.store.deleted.clear()
            self.alerts.dirty.clear()
            self.rules.dirty.clear()

    def flush_persist(self, entities_only: bool = False) -> None:
        if not self.persist:
            return
        if not entities_only:
            self.persist.flush_events(force=True)
        for fid in list(self.store.dirty):
            fp = self.store.get(fid)
            if fp:
                self.persist.upsert("fingerprint", fid, fp.to_state())
        for fid in list(self.store.deleted):
            self.persist.delete("fingerprint", fid)
        for aid in list(self.alerts.dirty):
            self.persist.upsert("alert", aid, self.alerts.alerts[aid].to_dict())
        for rid in list(self.rules.dirty):
            if rid in self.rules.rules:
                self.persist.upsert("rule", rid, self.rules.rules[rid].to_dict())
        self.persist.commit(force=not entities_only)
        self.store.dirty.clear()
        self.store.deleted.clear()
        self.alerts.dirty.clear()
        self.rules.dirty.clear()

    def drain(self) -> dict:
        out = self.outbox
        self.outbox = {"events": [], "alerts": {}, "fingerprints": {}, "rules": {}, "narration": [], "markers": []}
        return out

    # ------------------------------------------------------------ dashboards
    def kpis(self) -> dict:
        now = self.engine.now
        secs = [self.series[k] for k in sorted(self.series)[-6:-1]] if self.series else []
        eps = sum(b["accepted"] + b["dropped"] for b in secs) / max(1, len(secs))
        return {
            "events_total": self.counters["events"], "accepted": self.counters["accepted"],
            "dropped": self.counters["dropped"], "events_per_sec": round(eps, 1),
            "active_attackers": len(self.attackers),
            "open_alerts": sum(1 for a in self.alerts.alerts.values() if a.status != "resolved"),
            "active_rules": len(self.rules.active()),
            "suggested_rules": sum(1 for r in self.rules.rules.values() if r.status == "suggested"),
            "fingerprints": len(self.store.by_status("active")),
            "candidates": len(self.store.by_status("candidate")),
            "baseline_ready": self.baseline_ready, "now": now, "rule_mode": self.settings.rule_mode,
        }

    def series_list(self, last: int = 300) -> list[dict]:
        keys = sorted(self.series)[-last:]
        return [{"t": k, "accepted": self.series[k]["accepted"], "dropped": self.series[k]["dropped"],
                 "by_cat": dict(self.series[k]["by_cat"])} for k in keys]

    def geo(self) -> list[dict]:
        c = Counter()
        attack = Counter()
        for r in self.recent:
            c[r["country"]] += 1
        for ip in self.attackers:
            attack[lookup(ip)[0]] += 1
        return [{"country": k, "events": v, "attackers": attack.get(k, 0)} for k, v in c.most_common(20)]

    def is_benign_fp(self, fid: str) -> bool:
        fp = self.store.get(fid)
        return bool(fp and is_benign(fp.category))
