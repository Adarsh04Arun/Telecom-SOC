#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hybrid_fuse_autoai.py
--------------------------------------------------------------
Fuse AutoAI predictions with rules to produce a final hybrid alert score.

Inputs:
  --events     Path to refined events CSV (ideally already with rule_score; if not, pass --rules-json)
  --preds      Path to AutoAI predictions CSV downloaded from the AutoAI experiment UI
  --outdir     Output directory
Options:
  --join-on    Comma-separated keys to join events<->preds (e.g., "timestamp,host,src_ip,dst_ip").
               If omitted, the script will align rows by order (safe for typical AutoAI exports).
  --proba-col  Name of the probability column inside preds CSV (if you want to force it).
  --alpha      Weight for model probability in hybrid score (default 0.7)
  --thresh     Alert threshold on hybrid score (default 0.5)
  --top-n      Size of top alerts CSV (default 500)
  --rules-json If events CSV has no rule_score, compute it using a rules.json file (same schema as shown earlier)

Output files:
  outdir/
    hybrid_scored.csv         (all rows + model_proba + hybrid_score + alert)
    top_alerts.csv            (top N by hybrid_score desc)
    hybrid_metrics.json       (ROC-AUC, PR-AUC, precision/recall/F1, confusion matrix)
"""

import argparse
from pathlib import Path
import json
import re
import sys

import numpy as np
import pandas as pd

# Optional eval metrics
try:
    from sklearn.metrics import roc_auc_score, average_precision_score, precision_recall_fscore_support, confusion_matrix
    HAVE_SKLEARN = True
except Exception:
    HAVE_SKLEARN = False


COMPOSITE_KEY_DEFAULT = ["timestamp","host","event_type","src_ip","dst_ip"]  # used only if you pass --join-on

def log(msg): print(f"[HYBRID] {msg}")

# ------------------------- Rules engine (optional) -------------------------
def load_rules(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def is_external_ipv4(ip: str) -> bool:
    s = str(ip)
    return not (s.startswith("10.") or s.startswith("172.") or s.startswith("192.168"))

def compute_rule_score(df: pd.DataFrame, rules: dict) -> pd.Series:
    """
    Very lightweight, matches the example rules.json in the workflow.
    If you have your own rules, adjust here.
    """
    score = pd.Series(0, index=df.index, dtype=int)

    # Rule: high/critical + protocol in {SSH, SMTP, SIP}
    if "severity" in df.columns and "protocol" in df.columns and "high_proto_combo" in rules:
        sev_set = set(x.lower() for x in rules["high_proto_combo"].get("severity", []))
        proto_set = set(rules["high_proto_combo"].get("protocol", []))
        mask = df["severity"].astype(str).str.lower().isin(sev_set) & df["protocol"].astype(str).isin(proto_set)
        score = np.maximum(score, mask.astype(int) * int(rules["high_proto_combo"].get("score", 2)))

    # Rule: persistence events
    if "event_type" in df.columns and "persistence_events" in rules:
        et_set = set(rules["persistence_events"].get("event_type", []))
        mask = df["event_type"].astype(str).isin(et_set)
        score = np.maximum(score, mask.astype(int) * int(rules["persistence_events"].get("score", 2)))

    # Rule: ingress SSH (external -> internal)
    if "protocol" in df.columns and "src_ip" in df.columns and "dst_ip" in df.columns and "ingress_ssh" in rules:
        ssh_mask = df["protocol"].astype(str).eq("SSH")
        ext_src = df["src_ip"].astype(str).apply(is_external_ipv4)
        int_dst = ~(df["dst_ip"].astype(str).apply(is_external_ipv4))
        mask = ssh_mask & ext_src & int_dst
        score = np.maximum(score, mask.astype(int) * int(rules["ingress_ssh"].get("score", 1)))

    return score


# ------------------------- AutoAI proba detection -------------------------
def detect_proba_col(preds: pd.DataFrame, forced_name: str | None = None) -> str:
    if forced_name:
        if forced_name not in preds.columns:
            raise ValueError(f"Forced proba column '{forced_name}' not found in predictions CSV.")
        return forced_name

    # Common patterns seen in AutoAI / general ML outputs
    candidates_regex = [
        r"^prob.*1$",            # probability_1, prob_1
        r"^.*prob.*pos.*$",      # prob_positive, probability_pos
        r"^.*pred.*prob.*$",     # prediction_probability
        r"^.*proba.*$",          # proba, model_proba
        r"^.*score.*$",          # score
        r"^.*probability.*$",    # probability
    ]
    numeric_cols = [c for c in preds.columns if pd.api.types.is_numeric_dtype(preds[c])]

    def looks_like_proba(col) -> bool:
        s = preds[col].dropna().astype(float)
        if s.empty: return False
        # must be within [0,1] mostly
        within = ((s >= -0.01) & (s <= 1.01)).mean() > 0.98
        # and not degenerate all-zeros or all-ones
        mean_ok = 0.005 < s.mean() < 0.995
        return bool(within and mean_ok)

    # Regex search first
    for rx in candidates_regex:
        pattern = re.compile(rx, re.IGNORECASE)
        for c in preds.columns:
            if pattern.match(c) and c in numeric_cols and looks_like_proba(c):
                return c

    # Fallback: last numeric col that looks like proba
    for c in reversed(numeric_cols):
        if looks_like_proba(c):
            return c

    raise ValueError(
        f"Could not auto-detect probability column. "
        f"Numeric columns found: {numeric_cols}. "
        f"Pass --proba-col explicitly."
    )


# ------------------------- Join alignment -------------------------
def align_predictions(events: pd.DataFrame, preds: pd.DataFrame, proba_col: str, join_on: list[str] | None):
    """
    If join_on provided: merge on those keys (must exist in both).
    Else: align by row order (robust for typical AutoAI 'download predictions' that match order).
    Returns a tuple: (aligned_df, model_proba_series)
    """
    if join_on:
        missing_left = [k for k in join_on if k not in events.columns]
        missing_right = [k for k in join_on if k not in preds.columns]
        if missing_left or missing_right:
            raise ValueError(f"--join-on keys missing. Events missing={missing_left}, Preds missing={missing_right}")

        merged = events.merge(preds[join_on + [proba_col]], on=join_on, how="left")
        if merged[proba_col].isna().any():
            log("Warning: some rows did not find a matching prediction by join keys; "
                "ensure the keys match between events and preds.")
        return merged, merged[proba_col].astype(float)

    # Align by order: ensure same length or clip to min
    n = min(len(events), len(preds))
    if len(events) != len(preds):
        log(f"Row-count mismatch; aligning by order truncated to {n} rows (events={len(events)}, preds={len(preds)})")

    ev = events.iloc[:n].copy()
    proba = preds.iloc[:n][proba_col].astype(float).reset_index(drop=True)
    ev = ev.reset_index(drop=True)
    return ev, proba


# ------------------------- Metrics -------------------------
def compute_metrics(y_true: pd.Series | None, y_score: pd.Series, y_pred: pd.Series) -> dict:
    out = {}
    if y_true is not None and y_true.notna().any() and HAVE_SKLEARN:
        yt = y_true.astype(int)
        try:
            out["roc_auc"] = float(roc_auc_score(yt, y_score))
        except Exception:
            out["roc_auc"] = None
        try:
            out["pr_auc"] = float(average_precision_score(yt, y_score))
        except Exception:
            out["pr_auc"] = None
        p, r, f1, _ = precision_recall_fscore_support(yt, y_pred, average="binary", zero_division=0)
        out["precision"] = float(p); out["recall"] = float(r); out["f1"] = float(f1)
        cm = confusion_matrix(yt, y_pred, labels=[0,1])
        out["confusion_matrix"] = {"tn": int(cm[0,0]), "fp": int(cm[0,1]), "fn": int(cm[1,0]), "tp": int(cm[1,1])}
    else:
        out["note"] = "Labels unavailable or sklearn missing; computed no metrics."
    return out


# ------------------------- Main -------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True, help="Path to refined events CSV (ideally with rule_score, else use --rules-json)")
    ap.add_argument("--preds", required=True, help="Path to AutoAI predictions CSV (download from experiment UI)")
    ap.add_argument("--outdir", required=True, help="Output directory")
    ap.add_argument("--join-on", default="", help="Comma-separated join keys, e.g. timestamp,host,src_ip,dst_ip")
    ap.add_argument("--proba-col", default="", help="Probability column name in preds CSV (if you want to force it)")
    ap.add_argument("--alpha", type=float, default=0.7, help="Weight for model proba in hybrid score (default 0.7)")
    ap.add_argument("--thresh", type=float, default=0.5, help="Alert threshold on hybrid score (default 0.5)")
    ap.add_argument("--top-n", type=int, default=500, help="Top-N alerts to export (default 500)")
    ap.add_argument("--rules-json", default="", help="If events has no rule_score, compute it from this rules.json")
    args = ap.parse_args()

    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)

    # Load events
    log(f"Loading events: {args.events}")
    events = pd.read_csv(args.events)

    # Ensure/compute rule_score
    if "rule_score" not in events.columns:
        if args.rules_json:
            log(f"events has no rule_score; computing from {args.rules_json}")
            rules = load_rules(Path(args.rules_json))
            events["rule_score"] = compute_rule_score(events, rules)
        else:
            log("events has no rule_score and no --rules-json provided. Proceeding with rule_score=0.")
            events["rule_score"] = 0

    # Load predictions
    log(f"Loading predictions: {args.preds}")
    preds = pd.read_csv(args.preds)

    # Detect probability column
    proba_col = detect_proba_col(preds, forced_name=args.proba_col if args.proba_col else None)
    log(f"Using model probability column: {proba_col}")

    # Align rows
    join_keys = [k.strip() for k in args.join_on.split(",") if k.strip()] if args.join_on else None
    aligned_df, model_proba = align_predictions(events, preds, proba_col, join_keys)

    # Compute hybrid score: α * model_proba + (1-α) * (rule_score/2)
    alpha = float(args.alpha)
    if not (0.0 <= alpha <= 1.0):
        raise ValueError("--alpha must be in [0,1]")
    hybrid = alpha * model_proba + (1.0 - alpha) * (aligned_df["rule_score"] / 2.0)
    aligned_df["model_proba"] = model_proba
    aligned_df["hybrid_score"] = hybrid
    aligned_df["alert"] = (aligned_df["hybrid_score"] >= float(args.thresh)).astype(int)

    # Metrics (if labels present)
    y_true = aligned_df["label_suspicious"] if "label_suspicious" in aligned_df.columns else None
    metrics = compute_metrics(y_true, aligned_df["hybrid_score"], aligned_df["alert"])

    # Save outputs
    out_all = outdir / "hybrid_scored.csv"
    aligned_df.to_csv(out_all, index=False, encoding="utf-8")
    log(f"Wrote: {out_all}")

    top_n = int(args.top_n)
    top = aligned_df.sort_values("hybrid_score", ascending=False).head(top_n)
    out_top = outdir / "top_alerts.csv"
    top.to_csv(out_top, index=False, encoding="utf-8")
    log(f"Wrote: {out_top}")

    out_metrics = outdir / "hybrid_metrics.json"
    out_metrics.write_text(json.dumps({
        "alpha": alpha,
        "threshold": float(args.thresh),
        "proba_column": proba_col,
        "row_count": int(len(aligned_df)),
        "metrics": metrics
    }, indent=2), encoding="utf-8")
    log(f"Wrote: {out_metrics}")

    log("DONE.")

if __name__ == "__main__":
    main()
