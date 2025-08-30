# step2_with_ibm_dpk.py
# Uses pandas for tabular hygiene + IBM Data Prep Kit (if present) for dedup/profiler.
import argparse, json, re, importlib
from pathlib import Path
import pandas as pd

CONTROL_CHARS_RE = re.compile(r'[\x00-\x1F\x7F]')

CATEGORICAL_COLS = ["host","user","process","event_type","action","status","severity","protocol","service","tags"]
INT_COLS = ["hour","severity_num","is_internal_src","is_internal_dst","label_suspicious"]
COMPOSITE_KEY = ["timestamp","host","event_type","src_ip","dst_ip"]

def log(msg): print(f"[DPK-STEP2] {msg}")

def enforce_types(df: pd.DataFrame) -> pd.DataFrame:
    ts = pd.to_datetime(df.get("timestamp"), errors="coerce", utc=True)
    df["timestamp"] = ts.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    for c in INT_COLS:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
        else:
            df[c] = 0
    for c in CATEGORICAL_COLS + ["date","src_ip","dst_ip","msg"]:
        if c in df.columns:
            df[c] = df[c].astype("string").fillna("")
        else:
            df[c] = ""
    return df

def trim_and_case(df: pd.DataFrame) -> pd.DataFrame:
    for c in ["host","user","process","event_type","action","status","severity","protocol","service","tags"]:
        if c in df.columns:
            df[c] = df[c].astype(str).str.strip()
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
    if keys:
        before = len(df)
        df = df.drop_duplicates(subset=keys, keep="first")
        after = len(df)
        log(f"pandas dedup removed {before-after} rows on key {keys}")
    return df

def sanity_filters(df: pd.DataFrame) -> pd.DataFrame:
    if "src_ip" in df.columns and "dst_ip" in df.columns:
        mask = ~(df["src_ip"].astype(str).str.startswith("169.254.") & df["dst_ip"].astype(str).str.startswith("169.254."))
        removed = len(df) - mask.sum()
        if removed > 0:
            log(f"removed {removed} link-local-only rows")
        df = df[mask]
    df = df[df["timestamp"].astype(str) != ""]
    return df

def write_outputs(df: pd.DataFrame, out_dir: Path, base: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / f"{base}.csv"
    df.to_csv(csv_path, index=False, encoding="utf-8")
    log(f"CSV -> {csv_path}")

    parquet_path = out_dir / f"{base}.parquet"
    try:
        import pyarrow  # noqa
        df.to_parquet(parquet_path, index=False)
        log(f"Parquet -> {parquet_path}")
    except Exception as e:
        log(f"Parquet skipped (install pyarrow). Error: {e}")
        parquet_path = None
    return csv_path, parquet_path

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

def try_run_dpk(parquet_path: Path, out_dir: Path):
    """
    Tries to run Data Prep Kit transforms on the parquet file:
      - Unique ID annotation
      - Exact Dedup filter
      - Profiler
    Each step is optional; if the transform isn't installed, we skip gracefully.
    """
    if parquet_path is None or not parquet_path.exists():
        log("DPK: parquet not available, skipping DPK transforms.")
        return

    def _try_import(path):
        try:
            return importlib.import_module(path)
        except Exception:
            return None

    # Unique ID annotation
    uid_mod = _try_import("data_prep_toolkit.transforms.unique_id")
    if uid_mod and hasattr(uid_mod, "run"):
        log("DPK Unique ID -> running")
        uid_out = out_dir / "dpk_unique_id.parquet"
        uid_mod.run(str(parquet_path), str(uid_out))  # DPK transform signature pattern
        parquet_for_next = uid_out
    else:
        log("DPK Unique ID not available; skipping")
        parquet_for_next = parquet_path

    # Exact Dedup
    ededup_mod = _try_import("data_prep_toolkit.transforms.exact_dedup")
    if ededup_mod and hasattr(ededup_mod, "run"):
        log("DPK Exact Dedup -> running")
        dedup_out = out_dir / "dpk_dedup.parquet"
        # typical signature: input_path, output_path, and optional key column
        ededup_mod.run(str(parquet_for_next), str(dedup_out))
        parquet_for_next = dedup_out
    else:
        log("DPK Exact Dedup not available; skipping")

    # Profiler
    profiler_mod = _try_import("data_prep_toolkit.transforms.profiler")
    if profiler_mod and hasattr(profiler_mod, "run"):
        log("DPK Profiler -> running")
        prof_out = out_dir / "dpk_profile.json"
        profiler_mod.run(str(parquet_for_next), str(prof_out))
        log(f"DPK profile -> {prof_out}")
    else:
        log("DPK Profiler not available; skipping")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to telecom_soc_events_realtime.csv")
    ap.add_argument("--outdir", required=True, help="Output directory for refined assets")
    ap.add_argument("--name", default="telecom_soc_events_realtime_refined", help="Base name for outputs")
    ap.add_argument("--drop_ids", action="store_true", help="Drop ID-like columns (date, src_ip, dst_ip, tags)")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_dir = Path(args.outdir)

    log(f"Loading {in_path}")
    df = pd.read_csv(in_path)

    log("Enforce types")
    df = enforce_types(df)

    log("Trim + lowercase")
    df = trim_and_case(df)

    log("Clean msg")
    df = clean_msg(df, clip_len=2000)

    log("Fill missing")
    df = fill_missing(df)

    log("Pandas dedup")
    df = deduplicate_pandas(df)

    log("Sanity filters")
    df = sanity_filters(df)

    # Optional modeling view
    if args.drop_ids:
        drop_cols = [c for c in ["date","src_ip","dst_ip","tags"] if c in df.columns]
        df_model = df.drop(columns=drop_cols)
        model_csv = Path(out_dir) / f"{args.name}_modelview.csv"
        out_dir.mkdir(parents=True, exist_ok=True)
        df_model.to_csv(model_csv, index=False, encoding="utf-8")
        log(f"Model view -> {model_csv}")

    # Save refined artifacts
    csv_path, parquet_path = write_outputs(df, out_dir, args.name)
    profile_json(df, out_dir, args.name)

    # Try to run IBM Data Prep Kit transforms (optional)
    try_run_dpk(parquet_path, out_dir)

if __name__ == "__main__":
    main()
