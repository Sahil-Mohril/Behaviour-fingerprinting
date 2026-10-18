"""Events, fingerprints, alerts, rules, allowlist, settings, metrics and exports."""
from __future__ import annotations

import math
from typing import Optional

import numpy as np
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from ..features.extractor import FEATURE_GROUPS, FEATURES, FIDX
from ..fingerprint.similarity import cosine_matrix, fp_jaccard
from ..labels import BEHAVIOURS, CATEGORY_NAMES, UNKNOWN, severity_of
from ..rules.templates import FORMATS, export

router = APIRouter(prefix="/api", tags=["data"])

RADAR_AXES = ["log_events_ps", "log_rate_per_source", "log_n_sources", "log_bytes_per_flow", "log_pkts_per_flow",
              "log_flow_dur", "half_open_ratio", "udp_ratio", "log_uniq_dst_ports", "log_uniq_dst_ips", "iat_cv",
              "fail_ratio", "web_ratio", "ssh_ratio", "sensitive_path_ratio", "log_cmd_count"]


def rt(request: Request):
    return request.app.state.runtime


def _radar(r, fp) -> list[dict]:
    z = r.pipeline.scaler.baseline_z(fp.centroid)
    return [{"axis": a, "z": round(float(z[FIDX[a]]), 2),
             "value": round(1 / (1 + math.exp(-float(np.clip(z[FIDX[a]], -12, 12)) / 2)), 4)} for a in RADAR_AXES]


# ------------------------------------------------------------------- events
@router.get("/events")
def events(request: Request, page: int = Query(1, ge=1), size: int = Query(100, ge=1, le=1000),
           src_ip: Optional[str] = None, dst_service: Optional[str] = None, protocol: Optional[str] = None,
           action: Optional[str] = None, ground_truth_label: Optional[str] = None, event_type: Optional[str] = None,
           country: Optional[str] = None):
    r = rt(request)
    if r.persist is None:
        with r.lock:
            rows = list(r.pipeline.recent)[::-1]
        return {"items": rows[(page - 1) * size: page * size], "total": len(rows), "page": page, "size": size}
    r.persist.flush_events(force=True)
    items, total = r.persist.query_events(page, size, src_ip=src_ip, dst_service=dst_service, protocol=protocol,
                                          action=action, ground_truth_label=ground_truth_label,
                                          event_type=event_type, country=country)
    return {"items": items, "total": total, "page": page, "size": size}


# ------------------------------------------------------------- fingerprints
class FpPatch(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None


class MergeIn(BaseModel):
    ids: list[str]


def _fp(r, fid):
    fp = r.pipeline.store.get(fid)
    if not fp:
        raise HTTPException(404, "fingerprint not found")
    return fp


@router.get("/fingerprints")
def fingerprints(request: Request, status: Optional[str] = None):
    r = rt(request)
    with r.lock:
        fps = [f for f in r.pipeline.store.fps.values() if not status or f.status == status]
        return [{**f.summary(), "radar": _radar(r, f)} for f in sorted(fps, key=lambda f: f.id)]


@router.get("/fingerprints/meta")
def fingerprint_meta():
    return {"features": FEATURES, "groups": FEATURE_GROUPS, "radar_axes": RADAR_AXES,
            "categories": CATEGORY_NAMES, "behaviours": {k: v[0] for k, v in BEHAVIOURS.items()}}


@router.get("/fingerprints/projection")
def projection(request: Request, method: str = "pca", limit: int = Query(800, ge=50, le=3000)):
    r = rt(request)
    with r.lock:
        buf = list(r.pipeline.fpe.buffer)[-limit:]
        fps = r.pipeline.store.by_status("active", "candidate")
        if len(buf) < 3:
            return {"method": method, "points": [], "centroids": []}
        X = np.vstack([b.w.x for b in buf])
        Z = r.pipeline.scaler.transform(X)
        C = r.pipeline.scaler.transform(np.vstack([f.centroid for f in fps])) if fps else np.zeros((0, Z.shape[1]))
        meta = [(b.w.id, b.w.entity, b.w.t_end, b.fp, b.anomaly, b.w.n_events, b.w.services) for b in buf]
        cats = {f.id: f.category for f in r.pipeline.store.fps.values()}
        names = {f.id: f.name for f in r.pipeline.store.fps.values()}
    allz = np.vstack([Z, C])
    if method == "tsne" and len(allz) >= 10:
        from sklearn.manifold import TSNE
        P = TSNE(n_components=2, perplexity=min(30, max(5, len(allz) // 4)), init="pca", random_state=0).fit_transform(allz)
    else:
        from sklearn.decomposition import PCA
        method = "pca"
        P = PCA(n_components=2, random_state=0).fit_transform(allz)
    pts = [{"x": round(float(P[i, 0]), 4), "y": round(float(P[i, 1]), 4), "window_id": m[0], "entity": m[1],
            "t": m[2], "fp": m[3], "category": cats.get(m[3], UNKNOWN if m[4] else "unmatched"),
            "fp_name": names.get(m[3]), "anomaly": m[4], "n_events": m[5], "services": m[6]} for i, m in enumerate(meta)]
    cents = [{"x": round(float(P[len(meta) + j, 0]), 4), "y": round(float(P[len(meta) + j, 1]), 4), "fp": f.id,
              "name": f.name, "category": f.category} for j, f in enumerate(fps)]
    return {"method": method, "points": pts, "centroids": cents}


@router.get("/fingerprints/compare")
def compare(request: Request, ids: str):
    r = rt(request)
    fids = [i for i in ids.split(",") if i][:3]
    with r.lock:
        fps = [_fp(r, i) for i in fids]
        sc = r.pipeline.scaler
        Z = sc.transform(np.vstack([f.centroid for f in fps]))
        cos = cosine_matrix(Z, Z)
        w1, w2 = r.settings.weight_numeric, r.settings.weight_categorical
        pairs = []
        for a in range(len(fps)):
            for b in range(a + 1, len(fps)):
                jac = fp_jaccard(fps[a].minhash_sig, fps[b].minhash_sig)
                comb = (w1 * cos[a, b] + w2 * jac) / (w1 + w2)
                diff = np.abs(Z[a] - Z[b])
                top = [{"feature": FEATURES[i], "a_z": round(float(Z[a][i]), 2), "b_z": round(float(Z[b][i]), 2)}
                       for i in np.argsort(-diff)[:5]]
                pairs.append({"a": fps[a].id, "b": fps[b].id, "cosine": round(float(cos[a, b]), 4),
                              "jaccard_minhash": round(jac, 4), "combined": round(float(comb), 4),
                              "weights": {"numeric": w1, "categorical": w2}, "most_different": top})
        return {"fingerprints": [{**f.summary(), "radar": _radar(r, f)} for f in fps], "pairs": pairs}


@router.get("/fingerprints/{fid}")
def fingerprint(fid: str, request: Request):
    r = rt(request)
    with r.lock:
        fp = _fp(r, fid)
        d = fp.detail()
        d["radar"] = _radar(r, fp)
        d["rules"] = [x.to_dict() for x in r.pipeline.rules.list() if x.fp_id == fid][:20]
        d["alerts"] = [a.to_dict() for a in r.pipeline.alerts.list() if a.fp_id == fid][:20]
        return d


@router.patch("/fingerprints/{fid}")
def patch_fingerprint(fid: str, body: FpPatch, request: Request):
    r = rt(request)
    with r.lock:
        fp = _fp(r, fid)
        if body.name:
            fp.name, fp.name_locked = body.name.strip()[:80], True
        if body.category:
            if body.category not in CATEGORY_NAMES:
                raise HTTPException(400, "unknown category")
            fp.category, fp.category_locked = body.category, True
            fp.severity = severity_of(body.category)
            fp.notes.append(f"category set to {body.category} by user")
        if body.severity:
            fp.severity = body.severity
        fp.snapshot(r.pipeline.engine.now, "edited by user")
        r.pipeline.store.touch(fp)
        r.pipeline.flush_persist()
        return fp.summary()


@router.post("/fingerprints/{fid}/promote")
def promote(fid: str, request: Request):
    r = rt(request)
    with r.lock:
        fp = _fp(r, fid)
        fp.status = "active"
        fp.notes.append("promoted by user")
        if fp.name.startswith("Candidate:"):
            fp.name = r.pipeline.store.suggest_name(fp.category)
        fp.snapshot(r.pipeline.engine.now, "promoted by user")
        r.pipeline.store.touch(fp)
        r.pipeline.flush_persist()
        return fp.summary()


@router.post("/fingerprints/{fid}/dismiss")
def dismiss(fid: str, request: Request):
    r = rt(request)
    with r.lock:
        fp = _fp(r, fid)
        fp.status = "dismissed"
        fp.notes.append("dismissed by user: similar windows are suppressed")
        r.pipeline.store.touch(fp)
        r.pipeline.flush_persist()
        return fp.summary()


@router.post("/fingerprints/merge")
def merge(body: MergeIn, request: Request):
    r = rt(request)
    with r.lock:
        try:
            fp = r.pipeline.fpe.merge(body.ids, r.pipeline.engine.now)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        r.pipeline.flush_persist()
        return fp.summary()


@router.post("/fingerprints/{fid}/split")
def split(fid: str, request: Request):
    r = rt(request)
    with r.lock:
        try:
            out = r.pipeline.fpe.split(fid, r.pipeline.engine.now)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        r.pipeline.flush_persist()
        return [f.summary() for f in out]


@router.delete("/fingerprints/{fid}")
def delete_fp(fid: str, request: Request):
    r = rt(request)
    with r.lock:
        _fp(r, fid)
        r.pipeline.fpe.forget(fid)
        r.pipeline.flush_persist()
        return {"ok": True}


# ------------------------------------------------------------------- alerts
@router.get("/alerts")
def alerts(request: Request, status: Optional[str] = None, severity: Optional[str] = None,
           type: Optional[str] = None, limit: int = Query(500, le=5000)):
    r = rt(request)
    with r.lock:
        out = [a.to_dict() for a in r.pipeline.alerts.list()
               if (not status or a.status == status) and (not severity or a.severity == severity)
               and (not type or a.type == type)]
        return out[:limit]


@router.post("/alerts/{aid}/{action}")
def alert_action(aid: str, action: str, request: Request):
    status = {"ack": "acknowledged", "acknowledge": "acknowledged", "resolve": "resolved", "reopen": "open"}.get(action)
    if not status:
        raise HTTPException(400, "action must be ack, resolve or reopen")
    r = rt(request)
    with r.lock:
        a = r.pipeline.alerts.set_status(aid, status)
        if not a:
            raise HTTPException(404, "alert not found")
        r.pipeline.flush_persist()
        return a.to_dict()


# -------------------------------------------------------------------- rules
class RulePatch(BaseModel):
    ips: Optional[list[str]] = None
    rate: Optional[int] = None
    max: Optional[int] = None
    timeout: Optional[int] = None
    ports: Optional[list[int]] = None
    expires_in: Optional[float] = None


@router.get("/rules")
def rules(request: Request, status: Optional[str] = None):
    r = rt(request)
    with r.lock:
        return [x.to_dict() for x in r.pipeline.rules.list() if not status or x.status == status]


@router.get("/rules/export")
def export_rules(request: Request, format: str = "nftables", status: str = "active"):
    if format not in FORMATS:
        raise HTTPException(400, f"format must be one of {FORMATS}")
    r = rt(request)
    with r.lock:
        sel = [x for x in r.pipeline.rules.list() if status == "all" or x.status == status]
        text = export(sel, format)
    ext = {"nftables": "nft", "iptables": "sh", "suricata": "rules"}[format]
    return PlainTextResponse(text, headers={"Content-Disposition": f'attachment; filename="honeypot-{status}.{ext}"'})


@router.post("/rules/{rid}/{action}")
def rule_action(rid: str, action: str, request: Request):
    r = rt(request)
    with r.lock:
        gen = r.pipeline.rules
        if rid not in gen.rules:
            raise HTTPException(404, "rule not found")
        now = r.pipeline.engine.now
        if action == "approve":
            rule = gen.approve(rid, now)
            r.pipeline.markers.append({"t": now, "rule_id": rid, "label": f"{rid} active"})
            r.pipeline.outbox["markers"].append(r.pipeline.markers[-1])
        elif action == "reject":
            rule = gen.reject(rid, now)
        elif action == "expire":
            rule = gen.rules[rid]
            rule.set_status("expired", now, "user")
            gen.dirty.add(rid)
        else:
            raise HTTPException(400, "action must be approve, reject or expire")
        r.pipeline.sync_firewall()
        r.pipeline.flush_persist()
        return rule.to_dict()


@router.patch("/rules/{rid}")
def edit_rule(rid: str, body: RulePatch, request: Request):
    r = rt(request)
    with r.lock:
        if rid not in r.pipeline.rules.rules:
            raise HTTPException(404, "rule not found")
        rule = r.pipeline.rules.edit(rid, body.model_dump(exclude_none=True), r.pipeline.engine.now)
        r.pipeline.sync_firewall()
        r.pipeline.flush_persist()
        return rule.to_dict()


# ---------------------------------------------------------------- allowlist
class AllowIn(BaseModel):
    cidr: str
    note: str = ""


def _save_allow(r):
    r.pipeline.rules.purge_allowlisted()
    r.pipeline.sync_firewall()
    if r.persist:
        r.persist.save_allowlist(r.pipeline.allowlist.list())
    r.pipeline.flush_persist()


@router.get("/allowlist")
def allowlist(request: Request):
    return rt(request).pipeline.allowlist.list()


@router.post("/allowlist")
def add_allow(body: AllowIn, request: Request):
    r = rt(request)
    with r.lock:
        try:
            cidr = r.pipeline.allowlist.add(body.cidr, body.note)
        except ValueError as exc:
            raise HTTPException(400, f"invalid CIDR: {exc}") from exc
        _save_allow(r)
        return {"cidr": cidr, "note": body.note}


@router.delete("/allowlist")
def del_allow(cidr: str, request: Request):
    r = rt(request)
    with r.lock:
        r.pipeline.allowlist.remove(cidr)
        _save_allow(r)
        return {"ok": True}


# ----------------------------------------------------------------- settings
@router.get("/settings")
def get_settings(request: Request):
    return rt(request).settings.to_dict()


@router.put("/settings")
def put_settings(body: dict, request: Request):
    r = rt(request)
    with r.lock:
        changed = r.settings.update(body)
        if {"window_seconds", "hop_seconds", "long_horizon_seconds", "min_events_per_ip"} & set(changed):
            r.pipeline.extractor.reset()
        if "alert_dedupe_seconds" in changed:
            r.pipeline.alerts.dedupe_seconds = r.settings.alert_dedupe_seconds
        if "anomaly_contamination" in changed:
            r.pipeline.anomaly.contamination = r.settings.anomaly_contamination
        if r.persist:
            r.persist.save_settings(r.settings.to_dict())
        return {"settings": r.settings.to_dict(), "changed": changed}


# ------------------------------------------------------------------ metrics
@router.get("/metrics/overview")
def overview(request: Request, seconds: int = Query(300, le=900)):
    r = rt(request)
    with r.lock:
        p = r.pipeline
        return {"kpis": p.kpis(), "series": p.series_list(seconds), "markers": list(p.markers),
                "narration": list(p.narration), "status": r.status(), "geo": p.geo(),
                "decoys": p.decoys.stats(), "recent": list(p.recent)[-200:]}


@router.get("/metrics/evaluation")
def evaluation(request: Request):
    r = rt(request)
    with r.lock:
        return r.pipeline.evaluator.metrics()
