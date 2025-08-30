
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Step 2 – IBM DataPrep/Data Refinery (Code-Equivalent Pipeline)
--------------------------------------------------------------
This script performs the same transformations you'd apply in IBM DataPrep:
- Enforce column types (datetime/int/str)
- Trim whitespace & standardize case for select columns
- Clean `msg` (remove control chars, clip length)
- Fill missing values for key columns
- Deduplicate on composite key
- Optional sanity filters
- Save refined CSV/Parquet + profiling JSON + 5k sample
Usage:
  python step2_dataprep_refine.py \
    --input telecom_soc_events_realtime.csv \
    --outdir refined_output \
    --name telecom_soc_events_realtime_refined
"""
import argparse, json, re
from pathlib import Path
import pandas as pd
import numpy as np
from datetime import timezone

# ---------------------------- Helpers ----------------------------

CONTROL_CHARS_RE = re.compile(r'[\x00-\x1F\x7F]')

CATEGORICAL_COLS = ["host","user","process","event_type","action","status","severity","protocol","service","tags"]
INT_COLS = ["hour","severity_num","is_internal_src","is_internal_dst","label_suspicious"]
TIME_COLS = ["timestamp"]
OPTIONAL_DROP = []  # e.g., ["date","src_ip","dst_ip","tags"] if you want a modeling view

COMPOSITE_KEY = ["timestamp","host","event_type","src_ip","dst_ip"]

def enforce_types(df: pd.DataFrame) -> pd.DataFrame:
    # Timestamp -> ISO8601 UTC (Z)
    ts = pd.to_datetime(df.get("timestamp"), errors="coerce", utc=True)
    df["timestamp"] = ts.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    # Integers
    for c in INT_COLS:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
        else:
            df[c] = 0
    # Strings
    for c in CATEGORICAL_COLS + ["date","src_ip","dst_ip","msg"]:
        if c in df.columns:
            df[c] = df[c].astype("string").fillna("")
        else:
            df[c] = ""
    return df

def trim_and_case(df: pd.DataFrame) -> pd.DataFrame:
    # Trim spaces for selected columns
    for c in ["host","user","process","event_type","action","status","severity","protocol","service","tags"]:
        if c in df.columns:
            df[c] = df[c].astype(str).str.strip()
    # Lowercase standardization (keep identifiers like host/user/process as-is)
    for c in ["event_type","action","severity","protocol","service","tags"]:
        if c in df.columns:
            df[c] = df[c].str.lower()
    return df

def clean_msg(df: pd.DataFrame, clip_len: int = 2000) -> pd.DataFrame:
    if "msg" in df.columns:
        df["msg"] = df["msg"].astype(str).str.replace(CONTROL_CHARS_RE, "", regex=True)
        df["msg"] = df["msg"].str.slice(0, clip_len)
    return df

def fill_missing(df: pd.DataFrame) -> pd.DataFrame:
    if "host" in df.columns: df["host"] = df["host"].replace("", "unknown-host")
    if "user" in df.columns: df["user"] = df["user"].replace("", "system")
    if "process" in df.columns: df["process"] = df["process"].fillna("").replace({pd.NA:""})
    if "protocol" in df.columns: df["protocol"] = df["protocol"].replace("", "unknown")
    if "service" in df.columns: df["service"] = df["service"].replace("", "unknown")
    return df

def deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    keys = [k for k in COMPOSITE_KEY if k in df.columns]
    if keys:
        before = len(df)
        df = df.drop_duplicates(subset=keys, keep="first")
        after = len(df)
        print(f"[Dedup] {before-after} duplicate rows removed using key {keys}")
    return df

def sanity_filters(df: pd.DataFrame) -> pd.DataFrame:
    # Remove rows where both src/dst are link-local (169.254.*.*)
    if "src_ip" in df.columns and "dst_ip" in df.columns:
        mask = ~(df["src_ip"].astype(str).str.startswith("169.254.") & df["dst_ip"].astype(str).str.startswith("169.254."))
        removed = len(df) - mask.sum()
        if removed > 0:
            print(f"[Filter] Removed {removed} link-local only rows")
        df = df[mask]
    # Drop null timestamps
    df = df[df["timestamp"].astype(str) != ""]
    return df

def profile(df: pd.DataFrame) -> dict:
    info = {
        "rows": int(df.shape[0]),
        "cols": int(df.shape[1]),
        "null_counts": df.isna().sum().to_dict(),
        "empty_counts": (df.astype(str).eq("").sum()).to_dict(),
        "dtypes": df.dtypes.astype(str).to_dict(),
        "class_balance": df["label_suspicious"].value_counts(dropna=False).to_dict() if "label_suspicious" in df.columns else {},
        "cardinality": {c:int(df[c].nunique()) for c in ["host","user","process","event_type","protocol","service"] if c in df.columns},
        "composite_key": [k for k in COMPOSITE_KEY if k in df.columns],
    }
    return info

# ---------------------------- Main ----------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to telecom_soc_events_realtime.csv")
    ap.add_argument("--outdir", required=True, help="Output directory for refined assets")
    ap.add_argument("--name", default="telecom_soc_events_realtime_refined", help="Base name for outputs")
    ap.add_argument("--drop_ids", action="store_true", help="Drop ID-like columns (date, src_ip, dst_ip, tags) to create modeling view")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_dir = Path(args.outdir); out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Load] Reading {in_path}")
    df = pd.read_csv(in_path)

    print("[Step] Enforce types")
    df = enforce_types(df)

    print("[Step] Trim + case normalize")
    df = trim_and_case(df)

    print("[Step] Clean msg")
    df = clean_msg(df, clip_len=2000)

    print("[Step] Fill missing")
    df = fill_missing(df)

    print("[Step] Deduplicate")
    df = deduplicate(df)

    print("[Step] Sanity filters")
    df = sanity_filters(df)

    # Save refined
    refined_csv = out_dir / f"{args.name}.csv"
    print(f"[Save] CSV -> {refined_csv}")
    df.to_csv(refined_csv, index=False, encoding="utf-8")

    # Parquet (optional)
    refined_parquet = out_dir / f"{args.name}.parquet"
    try:
        import pyarrow  # noqa: F401
        df.to_parquet(refined_parquet, index=False)
        print(f"[Save] Parquet -> {refined_parquet}")
    except Exception as e:
        print(f"[Warn] Parquet not written (install pyarrow or fastparquet). Error: {e}")
        refined_parquet = None

    # Profile JSON
    prof = profile(df)
    prof_path = out_dir / f"{args.name}_profile.json"
    with open(prof_path, "w", encoding="utf-8") as f:
        json.dump(prof, f, indent=2)
    print(f"[Save] Profile -> {prof_path}")

    # 5k sample
    n = min(5000, len(df))
    sample = df.sample(n=n, random_state=42).reset_index(drop=True)
    sample_path = out_dir / f"{args.name}_sample_5k.csv"
    sample.to_csv(sample_path, index=False, encoding="utf-8")
    print(f"[Save] Sample 5k -> {sample_path}")

    # Optional modeling view (drop ID-like cols)
    if args.drop_ids:
        drop_cols = [c for c in ["date","src_ip","dst_ip","tags"] if c in df.columns]
        model_df = df.drop(columns=drop_cols)
        model_csv = out_dir / f"{args.name}_modelview.csv"
        model_df.to_csv(model_csv, index=False, encoding="utf-8")
        print(f"[Save] Model View -> {model_csv}")

    # Emit a simple flow manifest to document steps (for your report)
    flow_manifest = {
        "flow_name": "step2_dataprep_refine",
        "steps": [
            "enforce_types(timestamp→datetime ISO Z, ints, strings)",
            "trim_whitespace(selected cols)",
            "lowercase(event_type,action,severity,protocol,service,tags)",
            "clean_msg(remove control chars, clip 2000)",
            "fill_missing(host,user,process,protocol,service)",
            "deduplicate(timestamp,host,event_type,src_ip,dst_ip)",
            "sanity_filters(remove link-local-only, drop null ts)"
        ],
        "composite_key": COMPOSITE_KEY
    }
    flow_path = out_dir / f"{args.name}_flow.json"
    with open(flow_path, "w", encoding="utf-8") as f:
        json.dump(flow_manifest, f, indent=2)
    print(f"[Save] Flow manifest -> {flow_path}")

if __name__ == "__main__":
    main()
