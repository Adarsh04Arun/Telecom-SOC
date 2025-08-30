#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rule_scorer.py
--------------------------------------
Add a rule-based score (0–2) to your refined Telecom SOC dataset.

Input:
  - events CSV (e.g., telecom_soc_events_realtime_refined.csv)
  - rules.json (schema below)

Output:
  - refined_with_rules.csv (same folder as output path you pass)

Usage (PowerShell):
  python "C:\...\rule_scorer.py" "C:\...\telecom_soc_events_realtime_refined.csv" "C:\...\refined_with_rules.csv" --rules "C:\...\rules.json"
"""

import argparse
import json
import re
from pathlib import Path

import pandas as pd
import numpy as np

def log(msg): print(f"[RULES] {msg}")

# --- helpers ---
PRIVATE_PREFIXES = ("10.", "172.", "192.168")
LINK_LOCAL = "169.254."

def is_private_ipv4(ip: str) -> bool:
    s = str(ip)
    return s.startswith(PRIVATE_PREFIXES) or s.startswith("127.")

def is_external_ipv4(ip: str) -> bool:
    s = str(ip)
    if not s or s.startswith(LINK_LOCAL):
        return False
    return not is_private_ipv4(s)

def infer_direction(src_ip: str, dst_ip: str) -> str:
    """
    Best-effort: egress (internal->external), ingress (external->internal), internal, external
    """
    s_int = is_private_ipv4(src_ip)
    d_int = is_private_ipv4(dst_ip)
    if s_int and not d_int:  return "egress"
    if not s_int and d_int:  return "ingress"
    if s_int and d_int:      return "internal"
    return "external"

def load_rules(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def ensure_cols(df: pd.DataFrame, cols: list[str]) -> None:
    for c in cols:
        if c not in df.columns:
            df[c] = ""

def score_with_rules(df: pd.DataFrame, rules: dict) -> pd.Series:
    """
    Produces an integer score in {0,1,2} per row.
    You can add more rules here as needed.
    """
    score = pd.Series(0, index=df.index, dtype=int)

    # --- Rule 1: High/Critical + protocol in {SSH, SMTP, SIP} ---
    if "high_proto_combo" in rules:
        sev_list = [s.lower() for s in rules["high_proto_combo"].get("severity", [])]
        proto_list = rules["high_proto_combo"].get("protocol", [])
        sev = df["severity"].astype(str).str.lower()
        proto = df["protocol"].astype(str)
        mask = sev.isin(sev_list) & proto.isin(proto_list)
        s_val = int(rules["high_proto_combo"].get("score", 2))
        score = np.maximum(score, mask.astype(int) * s_val)

    # --- Rule 2: Persistence events (autorun/service install/scheduled task) ---
    if "persistence_events" in rules:
        et_list = rules["persistence_events"].get("event_type", [])
        mask = df["event_type"].astype(str).isin(et_list)
        s_val = int(rules["persistence_events"].get("score", 2))
        score = np.maximum(score, mask.astype(int) * s_val)

    # --- Rule 3: Ingress SSH from external to internal ---
    if "ingress_ssh" in rules:
        proto = df["protocol"].astype(str)
        # precomputed or on-the-fly direction
        if "direction" in df.columns:
            dircol = df["direction"].astype(str).str.lower()
            ing = dircol.eq("ingress")
        else:
            ing = df.apply(lambda r: infer_direction(str(r.get("src_ip","")), str(r.get("dst_ip","")))=="ingress", axis=1)
        mask = (proto == rules["ingress_ssh"].get("protocol", "SSH")) & ing
        s_val = int(rules["ingress_ssh"].get("score", 1))
        score = np.maximum(score, mask.astype(int) * s_val)

    # Cap to 0–2 (keeps it simple for fusion: divide by 2 → 0/0.5/1)
    score = score.clip(lower=0, upper=2)
    return score

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_csv", help="Refined events CSV (e.g., telecom_soc_events_realtime_refined.csv)")
    ap.add_argument("output_csv", help="Output path for refined_with_rules.csv")
    ap.add_argument("--rules", required=True, help="Path to rules.json")
    args = ap.parse_args()

    in_path = Path(args.input_csv)
    out_path = Path(args.output_csv)
    rules_path = Path(args.rules)

    log(f"Loading: {in_path}")
    df = pd.read_csv(in_path)

    # Ensure expected columns exist (safe-guards)
    ensure_cols(df, ["severity","protocol","event_type","src_ip","dst_ip"])

    log(f"Loading rules: {rules_path}")
    rules = load_rules(rules_path)

    log("Scoring with rules...")
    df["rule_score"] = score_with_rules(df, rules)

    # Optional: keep a text reason (useful for dashboards)
    reasons = []
    sev_low = df["severity"].astype(str).str.lower()
    proto = df["protocol"].astype(str)
    et = df["event_type"].astype(str)

    # Precompute direction for reasons (cheap)
    direction = df.apply(lambda r: infer_direction(str(r.get("src_ip","")), str(r.get("dst_ip",""))), axis=1)

    for i in range(len(df)):
        r = []
        if df.loc[i, "rule_score"] >= 1:
            # annotate reasons
            if sev_low.iat[i] in ("high","critical") and proto.iat[i] in ("SSH","SMTP","SIP"):
                r.append("high_sev_proto_combo")
            if et.iat[i] in ("service_install","scheduled_task_created","autorun_entry"):
                r.append("persistence_signal")
            if proto.iat[i] == "SSH" and direction.iat[i] == "ingress":
                r.append("ingress_ssh")
        reasons.append("|".join(r))
    df["rule_reasons"] = reasons

    log(f"Writing: {out_path}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False, encoding="utf-8")
    log("DONE.")

if __name__ == "__main__":
    main()
