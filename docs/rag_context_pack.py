#!/usr/bin/env python3
"""
rag_context_pack.py
-------------------
Builds a lightweight context file for Prompt Lab / Granite LLM grounded generation.

Inputs:
  --index   Path to rag_index folder
  --top_csv Path to top_alerts_tuned.csv
  --out     Output rag_context.md

Outputs:
  A Markdown file containing:
   - Top suspicious alerts (timestamp, host, user, proto, score)
   - Extracted RAG text snippets from your knowledge base
"""

import argparse, json
from pathlib import Path
import pandas as pd

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", required=True, help="Path to rag_index folder")
    ap.add_argument("--top_csv", required=True, help="Path to top_alerts_tuned.csv")
    ap.add_argument("--out", required=True, help="Output rag_context.md")
    args = ap.parse_args()

    idxdir = Path(args.index)
    top_csv = Path(args.top_csv)
    outpath = Path(args.out)

    # --- Load top alerts ---
    df = pd.read_csv(top_csv)
    if "hybrid_score" in df.columns:
        df = df.sort_values("hybrid_score", ascending=False)
    top_rows = df.head(30).to_dict(orient="records")

    # --- Load KB texts ---
    kb_texts = []
    if (idxdir/"texts.jsonl").exists():
        for line in (idxdir/"texts.jsonl").read_text(encoding="utf-8").splitlines():
            try:
                kb_texts.append(json.loads(line)["text"])
            except: pass
    kb_snippets = kb_texts[:20]

    # --- Write Markdown ---
    lines = ["# RAG Context Pack\n"]
    lines.append("## Top Alerts (Sample)\n")
    for r in top_rows:
        lines.append(f"- {r.get('timestamp','')} | Host={r.get('host','')} | User={r.get('user','')} "
                     f"| Proto={r.get('protocol','')} | Dst={r.get('dst_ip','')} "
                     f"| Score={r.get('hybrid_score','')}")
    lines.append("\n## Knowledge Base Snippets\n")
    for t in kb_snippets:
        lines.append(f"- {t.strip()[:300]}...")

    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] wrote {outpath}")

if __name__ == "__main__":
    main()
