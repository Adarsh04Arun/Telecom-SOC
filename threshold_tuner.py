#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
threshold_tuner.py
----------------------------------------------------
Tune the alert threshold using the existing hybrid scores.

Inputs:
  --hybrid   Path to hybrid_scored.csv  (must contain columns: hybrid_score, [label_suspicious optional])
  --outdir   Where to write tuned outputs (default: same folder as --hybrid)

Objectives (pick one):
  (default) --objective f1          -> choose threshold that maximizes F1 (requires labels)
            --target-recall 0.80    -> choose the *highest* threshold that achieves >= target recall
            --budget 500            -> if labels missing, pick threshold that keeps ~top-N alerts (by score)

Optional:
  --grid "0.10,0.15,...,0.90"       -> custom threshold grid (comma-separated)
  --topn 500                        -> size of top alerts CSV

Outputs (in outdir):
  hybrid_threshold_summary.csv      -> precision/recall/F1 for each threshold (if labels available)
  hybrid_metrics_tuned.json         -> metrics at chosen threshold (or alert count if no labels)
  hybrid_scored_tuned.csv           -> same rows as input, with NEW 'alert' column (0/1) at tuned threshold
  top_alerts_tuned.csv              -> top-N by score (threshold applied)
"""

import argparse, json
from pathlib import Path
import numpy as np
import pandas as pd

# -------------------- metrics helpers --------------------
def binary_metrics(y_true: pd.Series, y_score: pd.Series, thr: float) -> dict:
    y_pred = (y_score >= thr).astype(int)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2*precision*recall/(precision+recall) if (precision+recall) else 0.0
    return {
        "threshold": thr,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "alerts": int(y_pred.sum())
    }

def choose_by_target_recall(dfm: pd.DataFrame, target: float) -> pd.Series:
    # Among thresholds with recall >= target, pick the one with highest precision.
    ok = dfm[dfm["recall"] >= target]
    if ok.empty:
        # fallback: pick the threshold with max recall
        return dfm.sort_values("recall", ascending=False).iloc[0]
    return ok.sort_values(["precision", "threshold"], ascending=[False, True]).iloc[0]

# -------------------- main --------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hybrid", required=True, help="Path to hybrid_scored.csv")
    ap.add_argument("--outdir", default="", help="Output directory (default: same folder as --hybrid)")
    ap.add_argument("--objective", choices=["f1"], default="f1", help="Objective if labels available")
    ap.add_argument("--target-recall", type=float, default=None, help="Pick highest thr achieving >= this recall")
    ap.add_argument("--budget", type=int, default=None, help="If labels missing, pick threshold for ~top-N alerts")
    ap.add_argument("--grid", default="", help="Comma-separated thresholds, e.g. '0.2,0.3,0.4,0.5,0.6'")
    ap.add_argument("--topn", type=int, default=500, help="Top-N alerts CSV")
    args = ap.parse_args()

    hybrid_path = Path(args.hybrid)
    out_dir = Path(args.outdir) if args.outdir else hybrid_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(hybrid_path)
    if "hybrid_score" not in df.columns:
        raise ValueError("hybrid_scored.csv must contain 'hybrid_score' column.")
    y_score = pd.to_numeric(df["hybrid_score"], errors="coerce")

    have_labels = "label_suspicious" in df.columns and df["label_suspicious"].notna().any()
    y_true = pd.to_numeric(df["label_suspicious"], errors="coerce").fillna(0).astype(int) if have_labels else None

    # Threshold grid
    if args.grid:
        thr_grid = [float(x) for x in args.grid.split(",") if x.strip()]
    else:
        thr_grid = list(np.round(np.linspace(0.10, 0.90, 17), 2))

    chosen = None
    summary_path = out_dir / "hybrid_threshold_summary.csv"
    metrics_path = out_dir / "hybrid_metrics_tuned.json"
    scored_tuned = out_dir / "hybrid_scored_tuned.csv"
    top_tuned    = out_dir / "top_alerts_tuned.csv"

    if have_labels:
        # Evaluate on the grid
        rows = [binary_metrics(y_true, y_score, thr) for thr in thr_grid]
        dfm = pd.DataFrame(rows).sort_values("threshold")
        dfm.to_csv(summary_path, index=False)

        # Choose threshold
        if args.target_recall is not None:
            chosen = choose_by_target_recall(dfm, float(args.target_recall))
            chosen_obj = {"strategy": f"target_recall>={args.target_recall}"}
        else:
            # default: maximize F1
            chosen = dfm.sort_values(["f1","threshold"], ascending=[False, True]).iloc[0]
            chosen_obj = {"strategy": "maximize_f1"}

        thr = float(chosen["threshold"])
        y_pred = (y_score >= thr).astype(int)
        df_out = df.copy()
        df_out["alert"] = y_pred
        df_out.to_csv(scored_tuned, index=False)

        # Save top-N
        top = df_out.sort_values("hybrid_score", ascending=False).head(int(args.topn))
        top.to_csv(top_tuned, index=False)

        # Save metrics
        result = {
            "chosen_threshold": thr,
            "objective": chosen_obj,
            "metrics_at_threshold": {
                "precision": float(chosen["precision"]),
                "recall": float(chosen["recall"]),
                "f1": float(chosen["f1"]),
                "tp": int(chosen["tp"]), "fp": int(chosen["fp"]),
                "tn": int(chosen["tn"]), "fn": int(chosen["fn"]),
                "alerts": int(chosen["alerts"])
            },
            "grid_file": str(summary_path.name),
            "outputs": {
                "hybrid_scored_tuned.csv": str(scored_tuned.name),
                "top_alerts_tuned.csv": str(top_tuned.name)
            }
        }
        metrics_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"[OK] Tuned threshold={thr:.2f}  -> precision={chosen['precision']:.3f}, recall={chosen['recall']:.3f}, f1={chosen['f1']:.3f}")
        print(f"[OUT] {summary_path}\n[OUT] {scored_tuned}\n[OUT] {top_tuned}\n[OUT] {metrics_path}")

    else:
        # No labels: pick threshold by alert budget (top-N)
        if not args.budget:
            raise ValueError("No labels found. Provide --budget N to target ~top-N alerts.")
        budget = int(args.budget)

        # Convert budget to threshold by percentile
        # Alerts = number of rows with score >= thr. We choose thr at the score of the N-th ranked row.
        sorted_scores = y_score.sort_values(ascending=False).reset_index(drop=True)
        n = min(budget, len(sorted_scores))
        thr = float(sorted_scores.iloc[n-1]) if n > 0 else 1.0

        df_out = df.copy()
        df_out["alert"] = (df_out["hybrid_score"] >= thr).astype(int)
        df_out.to_csv(scored_tuned, index=False)
        top = df_out.sort_values("hybrid_score", ascending=False).head(int(args.topn))
        top.to_csv(top_tuned, index=False)

        result = {
            "chosen_threshold": thr,
            "objective": {"strategy": f"budget_top_{budget}"},
            "approx_alerts": int(df_out["alert"].sum()),
            "outputs": {
                "hybrid_scored_tuned.csv": str(scored_tuned.name),
                "top_alerts_tuned.csv": str(top_tuned.name)
            }
        }
        metrics_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"[OK] Tuned threshold by budget={budget} -> thr≈{thr:.3f}, alerts≈{int(df_out['alert'].sum())}")
        print(f"[OUT] {scored_tuned}\n[OUT] {top_tuned}\n[OUT] {metrics_path}")

if __name__ == "__main__":
    main()
