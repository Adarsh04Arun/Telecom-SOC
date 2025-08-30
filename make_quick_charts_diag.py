#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_quick_charts_diag.py
Writes charts to a known folder and prints absolute paths + row counts.
"""

import argparse
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import sys
import traceback

def log(m): print(f"[CHARTS] {m}")

def ensure_alert(df: pd.DataFrame, threshold: float, topn: int) -> pd.DataFrame:
    df = df.copy()
    if "alert" in df.columns and df["alert"].isin([0,1]).any():
        if df["alert"].sum() == 0 and "hybrid_score" in df.columns:
            log("Existing 'alert' has 0 positives; marking top-N by score.")
            idx = df["hybrid_score"].astype(float).rank(method="first", ascending=False) <= topn
            df.loc[idx, "alert"] = 1
        return df
    if "hybrid_score" not in df.columns:
        raise ValueError("CSV missing 'alert' and 'hybrid_score'. Need one of them.")
    df["alert"] = (pd.to_numeric(df["hybrid_score"], errors="coerce") >= threshold).astype(int)
    if df["alert"].sum() == 0:
        log(f"No alerts at threshold={threshold}. Marking top-N={topn}.")
        idx = df["hybrid_score"].astype(float).rank(method="first", ascending=False) <= topn
        df.loc[idx, "alert"] = 1
    return df

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True, help="Path to hybrid_scored(_tuned).csv")
    ap.add_argument("--out", dest="out_dir", required=True, help="Folder to save charts (will be created)")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--topn", type=int, default=500)
    args = ap.parse_args()

    in_path = Path(args.in_path).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    log(f"Input CSV: {in_path}")
    if not in_path.exists():
        sys.exit(f"[ERROR] Input file not found: {in_path}")

    try:
        df = pd.read_csv(in_path)
    except Exception as e:
        traceback.print_exc()
        sys.exit(f"[ERROR] read_csv failed: {e}")

    log(f"Rows in CSV: {len(df)}")
    if len(df) == 0:
        sys.exit("[ERROR] CSV has 0 rows. Nothing to chart.")

    # Timestamp -> hour
    if "timestamp" not in df.columns:
        sys.exit("[ERROR] CSV missing 'timestamp' column.")
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["hour"] = ts.dt.hour
    log(f"Null timestamps: {(ts.isna()).sum()}")

    # Ensure alert is present and has positives
    df = ensure_alert(df, args.threshold, args.topn)
    pos = int(df["alert"].sum())
    log(f"Alerts (sum of 'alert' column): {pos}")

    # Absolute output paths
    p1 = out_dir / "alerts_by_hour.png"
    p2 = out_dir / "top_protocols_alerts.png"
    p3 = out_dir / "top_hosts_alerts.png"
    log(f"Output folder: {out_dir}")

    # Chart 1
    plt.figure()
    df[df["alert"] == 1]["hour"].value_counts().sort_index().plot(kind="bar")
    plt.title("Alerts by Hour (UTC)"); plt.xlabel("Hour"); plt.ylabel("Count"); plt.tight_layout()
    plt.savefig(p1); plt.close()
    log(f"[OUT] {p1}")

    # Chart 2
    plt.figure()
    if "protocol" in df.columns:
        df[df["alert"] == 1]["protocol"].astype(str).value_counts().head(10).plot(kind="bar")
    else:
        pd.Series({"no-protocol-col": pos}).plot(kind="bar")
    plt.title("Top Protocols in Alerts"); plt.tight_layout()
    plt.savefig(p2); plt.close()
    log(f"[OUT] {p2}")

    # Chart 3
    plt.figure()
    if "host" in df.columns:
        df[df["alert"] == 1]["host"].astype(str).value_counts().head(10).plot(kind="bar")
    else:
        pd.Series({"no-host-col": pos}).plot(kind="bar")
    plt.title("Top Hosts in Alerts"); plt.tight_layout()
    plt.savefig(p3); plt.close()
    log(f"[OUT] {p3}")

    log("Done.")

if __name__ == "__main__":
    main()
