#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_quick_charts.py
Creates quick SOC charts from a scored CSV.

It will:
- Accept either tuned or base hybrid files
- Create 'alert' if missing (by threshold or top-N)
- Save 3 PNG charts and print the exact output folder

Usage (PowerShell example):
  python "C:\coding\jupyter personal\HackVerse\make_quick_charts.py" ^
    --in "C:\coding\jupyter personal\HackVerse\hybrid_out\hybrid_scored_tuned.csv" ^
    --out "C:\coding\jupyter personal\HackVerse\charts" ^
    --threshold 0.5 ^
    --fallback-topn 500
"""
import argparse
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

def log(m): print(f"[CHARTS] {m}")

def ensure_alert(df: pd.DataFrame, threshold: float, fallback_topn: int) -> pd.DataFrame:
    df = df.copy()
    if "alert" in df.columns and df["alert"].isin([0,1]).any():
        # Already has an alert column; if all zeros, fallback
        if df["alert"].sum() == 0:
            log("Existing 'alert' column has 0 positives; applying FALLBACK top-N -> mark top alerts.")
            mark_topn(df, fallback_topn)
        return df

    if "hybrid_score" not in df.columns:
        raise ValueError("Input CSV must have 'hybrid_score' when 'alert' is missing.")

    # Create alert via threshold
    df["alert"] = (pd.to_numeric(df["hybrid_score"], errors="coerce") >= float(threshold)).astype(int)
    if df["alert"].sum() == 0:
        log(f"No alerts at threshold {threshold}. Applying FALLBACK top-{fallback_topn}.")
        mark_topn(df, fallback_topn)
    return df

def mark_topn(df: pd.DataFrame, n: int):
    n = max(1, min(int(n), len(df)))
    idx = df["hybrid_score"].astype(float).rank(method="first", ascending=False) <= n
    df.loc[idx, "alert"] = 1

def safe_series(df: pd.DataFrame, col: str):
    return df[col].astype(str) if col in df.columns else pd.Series([], dtype=str)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True, help="Path to hybrid_scored_tuned.csv or hybrid_scored.csv")
    ap.add_argument("--out", dest="out_dir", default="", help="Charts output directory (default: <input_dir>\\charts)")
    ap.add_argument("--threshold", type=float, default=0.5, help="Threshold if 'alert' missing (default 0.5)")
    ap.add_argument("--fallback-topn", type=int, default=500, help="If still no alerts, mark top-N by score (default 500)")
    args = ap.parse_args()

    in_path = Path(args.in_path)
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")

    # Decide output folder
    out_dir = Path(args.out_dir) if args.out_dir else in_path.parent.parent / "charts"
    out_dir.mkdir(parents=True, exist_ok=True)

    log(f"Loading: {in_path}")
    df = pd.read_csv(in_path)

    # Timestamp → hour (robust)
    if "timestamp" not in df.columns:
        raise ValueError("Input CSV must have 'timestamp' column.")
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["hour"] = ts.dt.hour

    # Ensure alert column exists and has positives
    df = ensure_alert(df, args.threshold, args.fallback_topn)
    pos = int(df["alert"].sum())
    total = len(df)
    log(f"Alerts count: {pos} of {total} rows")

    # ===== Chart 1: Alerts by hour =====
    plt.figure()
    df[df["alert"] == 1]["hour"].value_counts().sort_index().plot(kind="bar")
    plt.title("Alerts by Hour (UTC)")
    plt.xlabel("Hour")
    plt.ylabel("Count")
    plt.tight_layout()
    p1 = out_dir / "alerts_by_hour.png"
    plt.savefig(p1); plt.close()
    log(f"[OUT] {p1}")

    # ===== Chart 2: Top protocols in alerts =====
    prot = "protocol" if "protocol" in df.columns else None
    plt.figure()
    if prot:
        df[df["alert"] == 1][prot].astype(str).value_counts().head(10).plot(kind="bar")
    else:
        pd.Series({"no-protocol-col": pos}).plot(kind="bar")
    plt.title("Top Protocols in Alerts")
    plt.tight_layout()
    p2 = out_dir / "top_protocols_alerts.png"
    plt.savefig(p2); plt.close()
    log(f"[OUT] {p2}")

    # ===== Chart 3: Top hosts in alerts =====
    host = "host" if "host" in df.columns else None
    plt.figure()
    if host:
        df[df["alert"] == 1][host].astype(str).value_counts().head(10).plot(kind="bar")
    else:
        pd.Series({"no-host-col": pos}).plot(kind="bar")
    plt.title("Top Hosts in Alerts")
    plt.tight_layout()
    p3 = out_dir / "top_hosts_alerts.png"
    plt.savefig(p3); plt.close()
    log(f"[OUT] {p3}")

    # Helpful summary print
    log("Done. If you don't see files, double-check this folder path above.")
    log(f"Charts folder: {out_dir}")

if __name__ == "__main__":
    main()
