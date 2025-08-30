#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEBUG version: always writes mitre_mapping_rag.csv/md with loud logging.
- Verifies input paths
- Logs CWD and absolute output paths
- Falls back to heuristic-only if RAG/Granite fail
"""

import argparse, json, sys, traceback
from pathlib import Path
import pandas as pd
import numpy as np
from datetime import datetime

LOG_PREFIX = "[MITRE-RAG-DEBUG]"

def log(msg):
    print(f"{LOG_PREFIX} {msg}", flush=True)

def heuristic_map(row):
    et = str(row.get("event_type","")).lower()
    proto = str(row.get("protocol","")).upper()
    reasons = str(row.get("rule_reasons","")).lower()
    if any(k in et for k in ["autorun","scheduled_task","service_install"]) or "persistence" in reasons:
        return ("Persistence","TA0003","T1547 Boot or Logon Autostart Execution","Persistence indicator")
    if proto == "SSH":
        return ("Initial Access","TA0001","T1078 Valid Accounts","Ingress SSH / credential use")
    if proto in ("SIP","SMTP"):
        return ("Command and Control","TA0011","T1071 Application Layer Protocol",f"High-sev {proto} traffic")
    return ("Discovery","TA0007","T1046 Network Service Scanning","Suspicious network activity")

def safe_write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if not path.exists():
        raise RuntimeError(f"Write failed for {path}")
    log(f"WROTE: {path}  ({path.stat().st_size} bytes)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top_csv", required=True)
    ap.add_argument("--index", required=True)
    ap.add_argument("--out_csv", default=r"C:\coding\jupyter personal\HackVerse\docs\mitre_mapping_rag.csv")
    ap.add_argument("--out_md",  default=r"C:\coding\jupyter personal\HackVerse\docs\mitre_mapping_rag.md")
    # Granite (optional) — we won’t fail if missing
    ap.add_argument("--granite_model_id", default="")
    ap.add_argument("--project_id", default="")
    ap.add_argument("--api_key", default="")
    ap.add_argument("--url", default="")
    args = ap.parse_args()

    log(f"Python: {sys.version}")
    log(f"CWD: {Path.cwd().resolve()}")
    log(f"ARGS: {args}")

    top_path = Path(args.top_csv).resolve()
    idx_dir  = Path(args.index).resolve()
    out_csv  = Path(args.out_csv).resolve()
    out_md   = Path(args.out_md).resolve()

    log(f"TOP CSV: {top_path}  exists={top_path.exists()}")
    log(f"RAG IDX: {idx_dir}  exists={idx_dir.exists()}")
    log(f"OUT CSV: {out_csv}")
    log(f"OUT  MD: {out_md}")

    if not top_path.exists():
        log("ERROR: top_csv not found"); sys.exit(2)
    if not idx_dir.exists():
        log("WARN: rag_index folder not found; will proceed without RAG")

    # Load data
    try:
        df = pd.read_csv(top_path)
    except Exception as e:
        traceback.print_exc()
        log(f"ERROR reading top_csv: {e}")
        sys.exit(3)

    log(f"Rows in top_csv: {len(df)}")
    if len(df) == 0:
        # Still write empty skeleton outputs so you SEE files
        safe_write_text(out_csv, "")
        safe_write_text(out_md, "# MITRE ATT&CK Mapping (empty)\nNo rows in top alerts.")
        sys.exit(0)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    # Heuristic mapping (guaranteed)
    rows=[]
    for _, r in df.head(200).iterrows():
        stage,tactic,tech,signal = heuristic_map(r)
        rows.append({
            "timestamp_utc": r.get("timestamp",""),
            "host": r.get("host",""),
            "user": r.get("user",""),
            "stage_final": stage,
            "tactic_final": tactic,
            "technique_final": tech,
            "evidence_final": signal,
            "source_final": "heuristic",
            "protocol": r.get("protocol",""),
            "dst_ip": r.get("dst_ip",""),
            "hybrid_score": r.get("hybrid_score",0)
        })
    out_df = pd.DataFrame(rows).sort_values(["timestamp_utc","hybrid_score"], ascending=[True,False])

    # Try RAG + Granite enhancement (but NEVER fail)
    enhanced = False
    try:
        # Only try if index exists
        if idx_dir.exists():
            # Minimal retrieval to prove flow; we won’t block output if this fails
            # (Full RAG was in the other script; this is just to ensure files get written.)
            pass
        # Optionally call Granite if creds present (non-blocking)
        if all([args.granite_model_id, args.project_id, args.api_key, args.url]):
            # You can plug in the earlier Granite call here if you want.
            # For debug run, we skip to ensure outputs are written.
            log("Granite creds provided; skipping in DEBUG to guarantee outputs.")
        enhanced = True
    except Exception as e:
        log(f"WARN: RAG/Granite step failed non-fatally: {e}")

    # Write outputs (ALWAYS)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out_csv, index=False, encoding="utf-8")
    if not out_csv.exists():
        raise RuntimeError("CSV write didn’t materialize")

    # MD pretty view
    lines = ["# MITRE ATT&CK Mapping (DEBUG Heuristic)\n",
             f"_Generated: {datetime.utcnow().isoformat()}Z_\n"]
    for _, rr in out_df.head(50).iterrows():
        lines.append(
            f"- **{rr['stage_final']}** / {rr['tactic_final']} / {rr['technique_final']} — {rr['evidence_final']}  \n"
            f"  Host: {rr['host']} | Time: {rr['timestamp_utc']} | Proto: {rr['protocol']} | Ref: {rr['source_final']}"
        )
    safe_write_text(out_md, "\n".join(lines))

    log("DONE. Files should now exist at the exact absolute paths above.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc()
        print(f"{LOG_PREFIX} FATAL: {e}", file=sys.stderr, flush=True)
        sys.exit(1)
