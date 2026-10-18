"""CICFlowMeter CSV adapter (CIC-IDS2017 'TrafficLabelling' and CIC-DDoS2019 CSVs).

One CSV row (a bidirectional flow) becomes one flow-level Event. The dataset's Label
column goes into `ground_truth_label` verbatim.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional

import numpy as np
import pandas as pd

from ..schemas import Event, service_for_port
from .base import PROTO_NUM, Adapter

# canonical name -> accepted header spellings (headers are stripped before matching)
ALIASES = {
    "src_ip": ["Source IP", "Src IP"],
    "src_port": ["Source Port", "Src Port"],
    "dst_ip": ["Destination IP", "Dst IP"],
    "dst_port": ["Destination Port", "Dst Port"],
    "protocol": ["Protocol"],
    "timestamp": ["Timestamp"],
    "duration_us": ["Flow Duration"],
    "fwd_pkts": ["Total Fwd Packets", "Tot Fwd Pkts", "Total Fwd Packet"],
    "bwd_pkts": ["Total Backward Packets", "Tot Bwd Pkts", "Total Bwd packets"],
    "fwd_bytes": ["Total Length of Fwd Packets", "TotLen Fwd Pkts", "Total Length of Fwd Packet"],
    "bwd_bytes": ["Total Length of Bwd Packets", "TotLen Bwd Pkts", "Total Length of Bwd Packet"],
    "fin": ["FIN Flag Count", "FIN Flag Cnt"],
    "syn": ["SYN Flag Count", "SYN Flag Cnt"],
    "rst": ["RST Flag Count", "RST Flag Cnt"],
    "psh": ["PSH Flag Count", "PSH Flag Cnt"],
    "ack": ["ACK Flag Count", "ACK Flag Cnt"],
    "avg_pkt": ["Average Packet Size", "Pkt Size Avg", "Packet Length Mean", "Pkt Len Mean"],
    "label": ["Label"],
}
REQUIRED = ("src_ip", "dst_port", "timestamp", "label")
CHUNK = 100_000


class CICFlowError(ValueError):
    pass


def _resolve_columns(path: Path) -> dict[str, str]:
    header = pd.read_csv(path, nrows=0, encoding="utf-8", encoding_errors="replace", skipinitialspace=True)
    stripped = {c.strip(): c for c in header.columns}
    cols: dict[str, str] = {}
    for canon, names in ALIASES.items():
        for n in names:
            if n in stripped:
                cols[canon] = stripped[n]
                break
    missing = [c for c in REQUIRED if c not in cols]
    if missing:
        raise CICFlowError(
            f"{path.name}: missing columns {missing}. Use the CSVs that include Source IP and "
            "Timestamp (CIC-IDS2017 'GeneratedLabelledFlows/TrafficLabelling', CIC-DDoS2019 CSV-01-12/03-11), "
            "not the 'MachineLearningCVE' variant."
        )
    return cols


def _parse_timestamps(raw: pd.Series) -> np.ndarray:
    s = raw.astype(str).str.strip()
    iso = s.str.match(r"^\d{4}-")
    out = pd.Series(np.nan, index=s.index)
    if iso.any():
        out[iso] = pd.to_datetime(s[iso], format="mixed", errors="coerce", utc=True).astype("int64") / 1e9
    if (~iso).any():
        dt = pd.to_datetime(s[~iso], format="mixed", dayfirst=True, errors="coerce", utc=True)
        ampm = s[~iso].str.contains("AM|PM", case=False)
        # CIC-IDS2017 12-hour clock without AM/PM: hours 1..7 are afternoon.
        fix = (~ampm) & dt.dt.hour.between(1, 7)
        dt = dt.where(~fix, dt + pd.Timedelta(hours=12))
        secs = dt.astype("int64") / 1e9
        secs[dt.isna()] = np.nan
        out[~iso] = secs
    vals = out.to_numpy(dtype=float)
    vals[vals < 0] = np.nan
    return vals


def _spread_coarse(ts: np.ndarray) -> np.ndarray:
    """Spread rows sharing a minute-resolution timestamp evenly across that minute (file order)."""
    valid = ~np.isnan(ts)
    if not valid.any():
        return ts
    if np.all(np.mod(ts[valid], 60.0) == 0):
        s = pd.Series(ts)
        rank = s.groupby(s).cumcount().to_numpy()
        size = s.groupby(s).transform("size").to_numpy()
        return ts + 60.0 * rank / np.maximum(size, 1)
    return ts


def _num(df: pd.DataFrame, cols: dict, key: str) -> Optional[np.ndarray]:
    if key not in cols:
        return None
    v = pd.to_numeric(df[cols[key]], errors="coerce").to_numpy(dtype=float)
    v[~np.isfinite(v)] = np.nan
    return v


def _iv(a: Optional[np.ndarray], i: int) -> Optional[int]:
    if a is None:
        return None
    x = a[i]
    return None if np.isnan(x) else int(x)


class CICFlowAdapter(Adapter):
    name = "cicflow"
    description = "CICFlowMeter CSV (CIC-IDS2017 / CIC-DDoS2019)"
    extensions = (".csv",)

    def sniff(self, path: Path, head: str) -> bool:
        return path.suffix.lower() == ".csv" and "Label" in head and ("Flow" in head or "Fwd" in head)

    def iter_chunks(self, path: Path, columns: tuple[str, ...]) -> Iterator[tuple[pd.DataFrame, dict]]:
        cols = _resolve_columns(path)
        use = [cols[c] for c in columns if c in cols]
        for chunk in pd.read_csv(path, usecols=use, chunksize=CHUNK, encoding="utf-8",
                                 encoding_errors="replace", skipinitialspace=True, low_memory=False):
            yield chunk, cols

    def scan(self, path: Path) -> dict:
        """Label counts and time range per label (for the catalog)."""
        labels: dict[str, dict] = {}
        rows = 0
        for chunk, cols in self.iter_chunks(path, ("timestamp", "label")):
            ts = _spread_coarse(_parse_timestamps(chunk[cols["timestamp"]]))
            lab = chunk[cols["label"]].astype(str).str.strip().to_numpy()
            rows += len(chunk)
            df = pd.DataFrame({"l": lab, "t": ts})
            for l, g in df.groupby("l"):
                d = labels.setdefault(l, {"count": 0, "t_min": None, "t_max": None})
                d["count"] += len(g)
                tmin, tmax = np.nanmin(g["t"]) if g["t"].notna().any() else None, np.nanmax(g["t"]) if g["t"].notna().any() else None
                if tmin is not None:
                    d["t_min"] = tmin if d["t_min"] is None else min(d["t_min"], tmin)
                    d["t_max"] = tmax if d["t_max"] is None else max(d["t_max"], tmax)
        return {"rows": rows, "labels": labels}

    def iter_events(self, path: Path, labels: Optional[set[str]] = None, t_from: Optional[float] = None,
                    t_to: Optional[float] = None, **_) -> Iterator[Event]:
        src = f"cicflow:{path.name}"
        for chunk, cols in self.iter_chunks(path, tuple(ALIASES)):
            lab = chunk[cols["label"]].astype(str).str.strip().to_numpy()
            ts = _spread_coarse(_parse_timestamps(chunk[cols["timestamp"]]))
            keep = ~np.isnan(ts)
            if labels:
                keep &= np.isin(lab, list(labels))
            if t_from is not None:
                keep &= ts >= t_from
            if t_to is not None:
                keep &= ts <= t_to
            if not keep.any():
                continue
            chunk = chunk[keep]
            lab, ts = lab[keep], ts[keep]
            src_ip = chunk[cols["src_ip"]].astype(str).str.strip().to_numpy()
            dst_ip = chunk[cols["dst_ip"]].astype(str).str.strip().to_numpy() if "dst_ip" in cols else None
            sport, dport = _num(chunk, cols, "src_port"), _num(chunk, cols, "dst_port")
            proto = _num(chunk, cols, "protocol")
            dur = _num(chunk, cols, "duration_us")
            fp, bp = _num(chunk, cols, "fwd_pkts"), _num(chunk, cols, "bwd_pkts")
            fb, bb = _num(chunk, cols, "fwd_bytes"), _num(chunk, cols, "bwd_bytes")
            fin, syn, rst = _num(chunk, cols, "fin"), _num(chunk, cols, "syn"), _num(chunk, cols, "rst")
            psh, ack, avg = _num(chunk, cols, "psh"), _num(chunk, cols, "ack"), _num(chunk, cols, "avg_pkt")
            for i in range(len(chunk)):
                f_p, b_p = _iv(fp, i), _iv(bp, i)
                pk = (f_p or 0) + (b_p or 0) if (f_p is not None or b_p is not None) else None
                f_b, b_b = _iv(fb, i), _iv(bb, i)
                nbytes = (f_b or 0) + (b_b or 0) if (f_b is not None or b_b is not None) else None
                p = PROTO_NUM.get(_iv(proto, i) or 6, "TCP")
                s_c, a_c, r_c = _iv(syn, i), _iv(ack, i), _iv(rst, i)
                flags = None
                if p == "TCP" and s_c is not None:
                    flags = ("S" if s_c else "") + ("A" if a_c else "") + ("R" if r_c else "") + ("F" if _iv(fin, i) else "")
                d_us = None if dur is None or np.isnan(dur[i]) else max(0.0, dur[i]) / 1e6
                size = None if avg is None or np.isnan(avg[i]) else float(avg[i])
                if size is None and pk and nbytes is not None:
                    size = nbytes / pk
                dp = _iv(dport, i)
                yield Event(
                    timestamp=float(ts[i]), orig_timestamp=float(ts[i]), src_ip=src_ip[i],
                    src_port=_iv(sport, i), dst_ip=None if dst_ip is None else dst_ip[i],
                    dst_service=service_for_port(dp), dst_port=dp, protocol=p, tcp_flags=flags,
                    packet_size=size, bytes=nbytes, duration=d_us, packets=pk, fwd_packets=f_p,
                    bwd_packets=b_p, syn_count=s_c, ack_count=a_c, fin_count=_iv(fin, i), rst_count=r_c,
                    psh_count=_iv(psh, i), event_type="flow", source=src, ground_truth_label=lab[i],
                )
