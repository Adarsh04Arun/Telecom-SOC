#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
step2_final_ibm_refine.py
--------------------------------------------------------------
Hackathon-ready DataPrep for the Telecom SOC dataset.

What it does (in order):
  1) Load CSV (e.g., telecom_soc_events_realtime.csv)
  2) Enforce IBM-friendly schema:
       - timestamp -> ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ)
       - ints -> hour, severity_num, is_internal_src, is_internal_dst, label_suspicious
       - strings -> host, user, process, event_type, action, status, severity, protocol, service, tags, msg, src_ip, dst_ip, date
  3) Clean content:
       - trim spaces on key categoricals
       - lowercase: event_type, action, severity, protocol, service, tags
       - msg: strip control chars, clip to 2000 chars
  4) Fill minimal defaults (host/user/protocol/service)
  5) Deduplicate on (timestamp, host, event_type, src_ip, dst_ip)
  6) Sanity filters (drop link-local-only pairs, drop empty timestamp)
  7) Save refined CSV/Parquet, profile JSON, sample-5k CSV, model-view CSV (drops id-like cols)
  8) Try to run IBM Data Prep Kit transforms on Parquet (if installed):
       - Unique ID -> dpk_unique_id.parquet
       - Exact Dedup -> dpk_dedup.parquet
       - Profiler    -> dpk_profile.json
     ...and if produced, write a _dpk_merged.csv that merges Unique ID back into CSV.

CLI:
  python step2_final_ibm_refine.py --input PATH_TO_CSV --outdir OUT_DIR --name telecom_soc_events_realtime_refined --drop_ids

Windows (PowerShell) single-line example:
  python "C:\coding\jupyter personal\HackVerse\step2_final_ibm_refine.py" --input "C:\coding\jupyter personal\HackVerse\telecom_soc_events_realtime.csv" --outdir "C:\coding\jupyter personal\HackVerse\refined_output" --name telecom_soc_events_realtime_refined --drop_ids
"""
import argparse, json, re, importlib, sys
from pathlib import Path
import pandas as pd

CONTROL_CHARS_RE = re.compile(r'[\x00-\x1F\x7F]')

# Columns we expect in the telecom SOC dataset
CATEGORICAL_COLS = ["host","user","process","event_type","action","status","severity","protocol","service","tags","date","src_ip","dst_ip"]
INT_COLS = ["hour","severity_num","is_internal_src","is_internal_dst","label_suspicious"]
TEXT_COLS = ["msg"]
TIME_COLS = ["timestamp"]

COMPOSITE_KEY = ["timestamp","host","event_type","src_ip","dst_ip"]

def log(msg: str):
    print(f"[STEP2] {msg}")

def enforce_types(df: pd.DataFrame) -> pd.DataFrame:
    # Timestamp -> ISO8601 UTC with Z
    if "timestamp" not in df.columns:
        df["timestamp"] = ""
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["timestamp"] = ts.dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Integers
    for c in INT_COLS:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
        else:
            df[c] = 0

    # Strings
    for c in CATEGORICAL_COLS + TEXT_COLS:
        if c in df.columns:
            df[c] = df[c].astype("string").fillna("")
        else:
            df[c] = ""

    return df

def trim_and_case(df: pd.DataFrame) -> pd.DataFrame:
    # Trim spaces on key categoricals
    for c in ["host","user","process","event_type","action","status","severity","protocol","service","tags"]:
        if c in df.columns:
            df[c] = df[c].astype(str).str.strip()
    # Standardize case where appropriate (keep host/user/process as-is)
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

def deduplicate_pandas(df: pd.DataFrame) -> pd.DataFrame:
    keys = [k for k in COMPOSITE_KEY if k in df.columns]
    if not keys:
        return df
    before = len(df)
    df = df.drop_duplicates(subset=keys, keep="first")
    after = len(df)
    log(f"pandas dedup removed {before-after} rows on key {keys}")
    return df

def sanity_filters(df: pd.DataFrame) -> pd.DataFrame:
    # Drop rows where BOTH endpoints are link-local 169.254.x.x
    if "src_ip" in df.columns and "dst_ip" in df.columns:
        mask = ~(df["src_ip"].astype(str).str.startswith("169.254.") & df["dst_ip"].astype(str).str.startswith("169.254."))
        removed = int(len(df) - mask.sum())
        if removed > 0:
            log(f"removed {removed} link-local-only rows")
        df = df[mask]
    # Drop empty timestamps
    df = df[df["timestamp"].astype(str) != ""]
    return df

def profile_json(df: pd.DataFrame, out_dir: Path, base: str):
    info = {
        "rows": int(df.shape[0]),
        "cols": int(df.shape[1]),
        "null_counts": df.isna().sum().to_dict(),
        "empty_counts": (df.astype(str).eq("").sum()).to_dict(),
        "dtypes": df.dtypes.astype(str).to_dict(),
        "class_balance": df["label_suspicious"].value_counts(dropna=False).to_dict() if "label_suspicious" in df.columns else {},
        "cardinality": {c:int(df[c].nunique()) for c in ["host","user","process","event_type","protocol","service"] if c in df.columns},
        "composite_key": COMPOSITE_KEY,
    }
    out = out_dir / f"{base}_profile.json"
    out.write_text(json.dumps(info, indent=2), encoding="utf-8")
    log(f"Profile JSON -> {out}")

def write_outputs(df: pd.DataFrame, out_dir: Path, base: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / f"{base}.csv"
    df.to_csv(csv_path, index=False, encoding="utf-8")
    log(f"CSV -> {csv_path}")

    parquet_path = out_dir / f"{base}.parquet"
    try:
        import pyarrow  # noqa: F401
        df.to_parquet(parquet_path, index=False)
        log(f"Parquet -> {parquet_path}")
    except Exception as e:
        log(f"Parquet skipped (install pyarrow). Error: {e}")
        parquet_path = None

    # Sample 5k
    n = min(5000, len(df))
    sample = df.sample(n=n, random_state=42).reset_index(drop=True)
    sample_path = out_dir / f"{base}_sample_5k.csv"
    sample.to_csv(sample_path, index=False, encoding="utf-8")
    log(f"Sample 5k -> {sample_path}")

    return csv_path, parquet_path

def optional_model_view(df: pd.DataFrame, out_dir: Path, base: str, drop_ids: bool):
    if not drop_ids:
        return None
    drop_cols = [c for c in ["date","src_ip","dst_ip","tags"] if c in df.columns]
    mv = df.drop(columns=drop_cols)
    model_csv = out_dir / f"{base}_modelview.csv"
    mv.to_csv(model_csv, index=False, encoding="utf-8")
    log(f"Model View CSV -> {model_csv}")
    return model_csv

def try_run_dpk(parquet_path: Path, out_dir: Path) -> dict:
    """
    Try IBM Data Prep Kit transforms (module paths may vary by version).
    We attempt several common import paths and run if available.
    Returns dict with produced artifact paths.
    """
    artifacts = {"unique_id": None, "dedup": None, "profile": None}

    if parquet_path is None or not parquet_path.exists():
        log("DPK: parquet not available, skipping DPK transforms.")
        return artifacts

    def _try_import(paths):
        for p in paths:
            try:
                return importlib.import_module(p)
            except Exception:
                continue
        return None

    # Candidate module paths (DPK often organizes under data_prep_toolkit.transforms.*)
    uid_mod = _try_import([
        "data_prep_toolkit.transforms.unique_id",
        "data_prep_toolkit.transforms.annotations.unique_id",
        "dpk.transforms.unique_id",
    ])
    ededup_mod = _try_import([
        "data_prep_toolkit.transforms.exact_dedup",
        "data_prep_toolkit.transforms.dedup.exact_dedup",
        "dpk.transforms.exact_dedup",
    ])
    profiler_mod = _try_import([
        "data_prep_toolkit.transforms.profiler",
        "data_prep_toolkit.transforms.analysis.profiler",
        "dpk.transforms.profiler",
    ])

    # Unique ID
    if uid_mod and hasattr(uid_mod, "run"):
        log("DPK Unique ID -> running")
        uid_out = out_dir / "dpk_unique_id.parquet"
        try:
            uid_mod.run(str(parquet_path), str(uid_out))
            artifacts["unique_id"] = uid_out
            log(f"DPK Unique ID -> {uid_out}")
        except Exception as e:
            log(f"DPK Unique ID failed: {e}")
    else:
        log("DPK Unique ID not available; skipping")

    # Exact Dedup
    source_for_dedup = artifacts["unique_id"] or parquet_path
    if ededup_mod and hasattr(ededup_mod, "run"):
        log("DPK Exact Dedup -> running")
        dedup_out = out_dir / "dpk_dedup.parquet"
        try:
            # Most versions accept (input, output); some accept keys param we skip for exact dedup
            ededup_mod.run(str(source_for_dedup), str(dedup_out))
            artifacts["dedup"] = dedup_out
            log(f"DPK Dedup -> {dedup_out}")
        except Exception as e:
            log(f"DPK Exact Dedup failed: {e}")
    else:
        log("DPK Exact Dedup not available; skipping")

    # Profiler
    source_for_profile = artifacts["dedup"] or artifacts["unique_id"] or parquet_path
    if profiler_mod and hasattr(profiler_mod, "run"):
        log("DPK Profiler -> running")
        prof_out = out_dir / "dpk_profile.json"
        try:
            profiler_mod.run(str(source_for_profile), str(prof_out))
            artifacts["profile"] = prof_out
            log(f"DPK Profile -> {prof_out}")
        except Exception as e:
            log(f"DPK Profiler failed: {e}")
    else:
        log("DPK Profiler not available; skipping")

    return artifacts

def maybe_merge_uid_back_to_csv(uid_parquet: Path, refined_csv: Path, out_dir: Path):
    """
    If DPK Unique ID produced a parquet with an added column (e.g., 'unique_id'),
    merge it back to CSV on the composite key, so downstream CSV has the UID.
    """
    if not uid_parquet or not uid_parquet.exists():
        return None
    try:
        import pyarrow  # ensure we can read parquet
    except Exception:
        log("Merge UID skipped (pyarrow not installed).")
        return None

    try:
        uid_df = pd.read_parquet(uid_parquet)
        base_df = pd.read_csv(refined_csv)
        # Guess the UID column
        uid_col = None
        for c in uid_df.columns:
            if c.lower() in ("unique_id", "uid", "row_id", "record_id"):
                uid_col = c; break
        if not uid_col:
            # If we can't find a plausible UID column, bail gracefully
            log("No obvious UID column in DPK output; skipping merge.")
            return None
        # Merge on composite key; if missing keys, fallback to index join
        keys = [k for k in COMPOSITE_KEY if k in base_df.columns and k in uid_df.columns]
        if keys:
            merged = base_df.merge(uid_df[keys + [uid_col]], on=keys, how="left")
        else:
            uid_df = uid_df.reset_index().rename(columns={"index":"_idx"})
            base_df = base_df.reset_index().rename(columns={"index":"_idx"})
            merged = base_df.merge(uid_df[["_idx", uid_col]], on="_idx", how="left").drop(columns=["_idx"])

        out_csv = out_dir / (refined_csv.stem + "_dpk_merged.csv")
        merged.to_csv(out_csv, index=False, encoding="utf-8")
        log(f"Refined CSV with UID -> {out_csv}")
        return out_csv
    except Exception as e:
        log(f"Merge UID failed: {e}")
        return None

def write_flow_manifest(out_dir: Path, base: str):
    flow_manifest = {
        "flow_name": "step2_final_ibm_refine",
        "steps": [
            "enforce_types(timestamp→ISO Z; ints; strings)",
            "trim_whitespace(host,user,process,event_type,action,status,severity,protocol,service,tags)",
            "lowercase(event_type,action,severity,protocol,service,tags)",
            "clean_msg(remove control chars; clip 2000)",
            "fill_missing(host=unknown-host, user=system, protocol/service=unknown)",
            "deduplicate(timestamp,host,event_type,src_ip,dst_ip)",
            "sanity_filters(remove link-local-only; drop empty timestamp)",
            "write outputs (CSV, Parquet, sample_5k, profile.json, modelview.csv)",
            "try DPK transforms (Unique ID, Exact Dedup, Profiler) on Parquet",
            "merge DPK Unique ID back to CSV if available",
        ],
        "composite_key": COMPOSITE_KEY
    }
    flow_path = out_dir / f"{base}_flow.json"
    flow_path.write_text(json.dumps(flow_manifest, indent=2), encoding="utf-8")
    log(f"Flow manifest -> {flow_path}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to telecom_soc_events_realtime.csv (or similar)")
    ap.add_argument("--outdir", required=True, help="Output directory for refined assets")
    ap.add_argument("--name", default="telecom_soc_events_realtime_refined", help="Base name for outputs")
    ap.add_argument("--drop_ids", action="store_true", help="Also create model view (drop date, src_ip, dst_ip, tags)")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_dir = Path(args.outdir); out_dir.mkdir(parents=True, exist_ok=True)

    # 1) Load
    log(f"Loading {in_path}")
    df = pd.read_csv(in_path)

    # 2) Enforce types
    log("Enforce types")
    df = enforce_types(df)

    # 3) Trim/case
    log("Trim + lowercase")
    df = trim_and_case(df)

    # 4) Clean msg
    log("Clean msg")
    df = clean_msg(df, clip_len=2000)

    # 5) Fill minimal defaults
    log("Fill missing")
    df = fill_missing(df)

    # 6) Deduplicate (pandas)
    log("Pandas dedup")
    df = deduplicate_pandas(df)

    # 7) Sanity filters
    log("Sanity filters")
    df = sanity_filters(df)

    # Save refined outputs
    base = args.name
    profile_json(df, out_dir, base)
    refined_csv, refined_parquet = write_outputs(df, out_dir, base)
    model_csv = optional_model_view(df, out_dir, base, args.drop_ids)

    # Optional: run DPK transforms
    artifacts = try_run_dpk(refined_parquet, out_dir)

    # Optional: merge Unique ID back to refined CSV
    _ = maybe_merge_uid_back_to_csv(artifacts.get("unique_id"), refined_csv, out_dir)

    # Flow manifest for your report
    write_flow_manifest(out_dir, base)

    log("DONE.")

if __name__ == "__main__":
    main()
