#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_mitre_table_rag_granite.py
--------------------------------
RAG-augmented MITRE ATT&CK mapping from top alerts, with optional IBM Granite LLM
normalization on watsonx.ai.

Inputs:
  --top_csv   Path to top_alerts_tuned.csv
  --index     Path to rag_index folder produced by rag_build_kb.py
  --out_csv   Output CSV (default: docs/mitre_mapping_rag.csv)
  --out_md    Output Markdown (default: docs/mitre_mapping_rag.md)

Optional Granite (watsonx.ai) args:
  --granite_model_id   e.g. granite-13b-instruct-v2 or granite-8b-instruct
  --project_id         your watsonx project id (GUID)
  --api_key            your IBM Cloud API key
  --url                region API endpoint, e.g. https://us-south.ml.cloud.ibm.com or https://eu-de.ml.cloud.ibm.com

Install (once):
  pip install pandas numpy sentence-transformers faiss-cpu pypdf rich
  pip install ibm-watsonx-ai   # only if using Granite
"""

from __future__ import annotations
import argparse, json, textwrap
from pathlib import Path
from typing import List, Tuple, Dict, Any
import pandas as pd
import numpy as np

# Embeddings / RAG
from sentence_transformers import SentenceTransformer
try:
    import faiss  # type: ignore
    HAVE_FAISS = True
except Exception:
    HAVE_FAISS = False

from rich import print

# -------------------------- RAG helpers --------------------------

def load_index(idxdir: Path):
    backend = (idxdir / "backend.txt").read_text(encoding="utf-8").strip()
    texts = [json.loads(l)["text"] for l in (idxdir/"texts.jsonl").read_text(encoding="utf-8").splitlines()]
    metas = [json.loads(l) for l in (idxdir/"metas.jsonl").read_text(encoding="utf-8").splitlines()]
    if backend == "faiss" and HAVE_FAISS:
        index = faiss.read_index(str(idxdir/"kb.faiss"))
    else:
        index = np.load(idxdir/"kb.npy")
    return backend, texts, metas, index

def embed_model():
    return SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

def rag_search(model, backend, texts, metas, index, query: str, k: int = 5) -> List[Dict[str, Any]]:
    q = model.encode([query], convert_to_numpy=True, normalize_embeddings=True).astype(np.float32)[0]
    if backend == "faiss" and HAVE_FAISS:
        D, I = index.search(q.reshape(1,-1), k)
        I = I[0].tolist(); D = D[0].tolist()
    else:
        sims = (index @ q)
        I = np.argsort(-sims)[:k].tolist()
        D = [float(sims[i]) for i in I]
    out = []
    for i, s in zip(I, D):
        meta = metas[i]; src = meta.get("file", meta.get("source","kb"))
        out.append({"score": round(s,4), "source": src, "text": texts[i]})
    return out

# ----------------------- Heuristic MITRE mapping -----------------------

def infer_stage_tactic_tech(row: pd.Series) -> Tuple[str,str,str,str]:
    """
    Returns: stage, tactic, technique, signal
    Heuristics based on protocol, event_type, rule_reasons, etc.
    Safe defaults if columns missing.
    """
    et = str(row.get("event_type","")).lower()
    proto = str(row.get("protocol","")).upper()
    reasons = str(row.get("rule_reasons","")).lower()

    # Persistence signals
    if "autorun" in et or "scheduled_task" in et or "service_install" in et or "persistence" in reasons:
        return ("Persistence", "TA0003", "T1547 Boot or Logon Autostart Execution", "Persistence indicator")

    # SSH ingress → initial access / lateral movement depending on flow (we default to initial access)
    if proto == "SSH":
        return ("Initial Access", "TA0001", "T1078 Valid Accounts", "Ingress SSH / credential use")

    # App-layer C2 hints
    if proto in ("SIP","SMTP"):
        return ("Command and Control", "TA0011", "T1071 Application Layer Protocol", f"High-sev {proto} traffic")

    # Discovery / Scanning fallback
    return ("Discovery", "TA0007", "T1046 Network Service Scanning", "Suspicious network activity")

# ----------------------- Granite (watsonx.ai) -----------------------

def have_granite_env(args) -> bool:
    return all([args.api_key, args.project_id, args.url, args.granite_model_id])

def call_granite(batch_rows: List[Dict[str, Any]],
                 rag_snippets: List[Dict[str, Any]],
                 args) -> List[Dict[str, Any]]:
    """
    Calls IBM watsonx.ai Granite to normalize MITRE mapping and add concise evidence lines.
    Graceful fallback to heuristics if SDK missing or creds invalid.
    """
    try:
        from ibm_watsonx_ai.foundation_models import Model
        from ibm_watsonx_ai import Credentials
    except Exception as e:
        print("[yellow]Granite SDK not available; using heuristic mapping only.[/yellow]")
        return []

    creds = Credentials(api_key=args.api_key, url=args.url)
    model = Model(
        model_id=args.granite_model_id,
        credentials=creds,
        project_id=args.project_id,
        params={
            "decoding_method": "greedy",
            "max_new_tokens": 512,
            "temperature": 0.2,
            "repetition_penalty": 1.05,
        }
    )

    # Compose prompt
    # Keep it tight: ask for normalized tactic/technique, 1-line evidence, and cite sources from our RAG items.
    rag_block = "\n".join([f"[Source: {s['source']}] {s['text'][:500]}" for s in rag_snippets])
    cases_block = "\n".join([
        f"- Row: host={r.get('host','')}, user={r.get('user','')}, proto={r.get('protocol','')}, "
        f"event_type={r.get('event_type','')}, sev={r.get('severity','')}, dst_ip={r.get('dst_ip','')}, "
        f"time={r.get('timestamp','')}"
        for r in batch_rows
    ])

    system = (
        "You are a precise DFIR assistant. Normalize each input row to a single MITRE ATT&CK "
        "(Stage label, Tactic ID, Technique ID/Name). Use ONLY supported evidence from the provided sources."
        " Provide output as compact JSON lines: "
        '{"stage": "...", "tactic": "TAxxxx", "technique": "Txxxx Name", "evidence": "1 line", "source_hint": "filename.md or mitre_csv"}'
    )
    user = f"""RAG Sources:
{rag_block}

Rows to map:
{cases_block}

Rules:
- Prefer ATT&CK v12+ IDs (TAxxxx, Txxxx).
- Evidence must be ≤1 sentence and reflect the row fields.
- Add a 'source_hint' from any Source bracket that best supports your mapping.
Return one JSON object per row, each on its own line.
"""

    prompt = f"<|system|>\n{system}\n<|user|>\n{user}\n"
    try:
        resp = model.generate_text(prompt=prompt)
        text = resp if isinstance(resp, str) else (resp.get("results",[{}])[0].get("generated_text",""))
    except Exception as e:
        print(f"[yellow]Granite call failed: {e}. Falling back to heuristics[/yellow]")
        return []

    # Parse JSONL-ish lines
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            out.append(obj)
        except Exception:
            # try to salvage with simple extraction
            out.append({"_raw": line})
    return out

# ----------------------- Main pipeline -----------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top_csv", required=True, help="Path to top_alerts_tuned.csv")
    ap.add_argument("--index", required=True, help="Path to rag_index folder")
    ap.add_argument("--out_csv", default=r"C:\coding\jupyter personal\HackVerse\docs\mitre_mapping_rag.csv")
    ap.add_argument("--out_md",  default=r"C:\coding\jupyter personal\HackVerse\docs\mitre_mapping_rag.md")

    # Granite options (optional)
    ap.add_argument("--granite_model_id", default="", help="e.g., granite-13b-instruct-v2")
    ap.add_argument("--project_id", default="", help="watsonx.ai project id")
    ap.add_argument("--api_key", default="", help="IBM Cloud API key")
    ap.add_argument("--url", default="", help="e.g. https://us-south.ml.cloud.ibm.com")
    ap.add_argument("--k", type=int, default=4, help="RAG passages per query")

    args = ap.parse_args()

    top = pd.read_csv(args.top_csv)
    if "timestamp" in top.columns:
        top["timestamp"] = pd.to_datetime(top["timestamp"], errors="coerce", utc=True)

    idxdir = Path(args.index)
    backend, texts, metas, index = load_index(idxdir)
    sbert = embed_model()

    # Build per-row heuristic mapping + RAG evidence (queries depend on the heuristic)
    rows_out = []
    all_rag_hits = []  # for LLM prompt
    for _, r in top.iterrows():
        stage, tactic, technique, signal = infer_stage_tactic_tech(r)

        # make a focused query for this row
        q_bits = [signal]
        proto = str(r.get("protocol","")).upper()
        if stage == "Persistence":
            q_bits.append("Windows persistence triage autoruns scheduled tasks remediation")
        elif proto == "SSH":
            q_bits.append("Initial Access via SSH triage credential misuse containment")
        elif proto in ("SIP","SMTP"):
            q_bits.append("C2 via application layer protocol detection containment")
        else:
            q_bits.append("Discovery scanning triage network service scanning")

        query = " ".join(q_bits)
        hits = rag_search(sbert, backend, texts, metas, index, query, k=args.k)
        # Keep top 2 per row for brevity
        hits_keep = hits[:2]
        all_rag_hits.extend(hits_keep)

        rows_out.append({
            "timestamp_utc": r.get("timestamp",""),
            "host": r.get("host",""),
            "user": r.get("user",""),
            "stage": stage,
            "tactic": tactic,
            "technique": technique,
            "signal": signal,
            "protocol": r.get("protocol",""),
            "dst_ip": r.get("dst_ip",""),
            "hybrid_score": r.get("hybrid_score",0),
            "rag_sources": " | ".join(f"{h['source']} (s={h['score']})" for h in hits_keep)
        })

    df_map = pd.DataFrame(rows_out)

    # Optional: Granite normalization to refine mapping/evidence
    granite_results = []
    if have_granite_env(args):
        # Use a small sample (e.g., top 40) to stay snappy
        sample_rows = df_map.sort_values("hybrid_score", ascending=False).head(40)
        batch_rows = sample_rows.to_dict(orient="records")
        # de-duplicate RAG hits for prompt size
        unique_hits = {}
        for h in all_rag_hits:
            key = (h["source"], h["text"][:120])
            unique_hits[key] = h
        rag_snippets = list(unique_hits.values())[:15]
        granite_results = call_granite(batch_rows, rag_snippets, args)

        # Merge Granite suggestions back into df_map where possible (by timestamp+host)
        # We'll do a simple left merge on (timestamp_utc, host) order
        if granite_results:
            # build a mapping in order
            gnorm = []
            for i, row in enumerate(batch_rows):
                sug = granite_results[i] if i < len(granite_results) else {}
                gnorm.append({
                    "timestamp_utc": row.get("timestamp_utc", row.get("timestamp","")),
                    "host": row.get("host",""),
                    "g_stage": sug.get("stage",""),
                    "g_tactic": sug.get("tactic",""),
                    "g_technique": sug.get("technique",""),
                    "g_evidence": sug.get("evidence", sug.get("_raw","")),
                    "g_source_hint": sug.get("source_hint","")
                })
            gdf = pd.DataFrame(gnorm)
            # Merge by nearest join on timestamp+host where possible
            on_cols = ["timestamp_utc","host"]
            for c in on_cols:
                if c not in df_map.columns:
                    df_map[c] = ""
            df_map = df_map.merge(gdf, on=on_cols, how="left")

            # Prefer Granite when present
            df_map["stage_final"] = np.where(df_map["g_stage"].fillna("")!="", df_map["g_stage"], df_map["stage"])
            df_map["tactic_final"] = np.where(df_map["g_tactic"].fillna("")!="", df_map["g_tactic"], df_map["tactic"])
            df_map["technique_final"] = np.where(df_map["g_technique"].fillna("")!="", df_map["g_technique"], df_map["technique"])
            df_map["evidence_final"] = df_map["g_evidence"].fillna("").replace("", np.nan)
            df_map["evidence_final"] = df_map["evidence_final"].fillna(df_map["signal"])
            df_map["source_final"] = df_map["g_source_hint"].fillna("").replace("", np.nan)
            df_map["source_final"] = df_map["source_final"].fillna(df_map["rag_sources"])
        else:
            # no Granite suggestions → final = heuristic
            df_map["stage_final"] = df_map["stage"]
            df_map["tactic_final"] = df_map["tactic"]
            df_map["technique_final"] = df_map["technique"]
            df_map["evidence_final"] = df_map["signal"]
            df_map["source_final"] = df_map["rag_sources"]
    else:
        # No Granite → final = heuristic
        df_map["stage_final"] = df_map["stage"]
        df_map["tactic_final"] = df_map["tactic"]
        df_map["technique_final"] = df_map["technique"]
        df_map["evidence_final"] = df_map["signal"]
        df_map["source_final"] = df_map["rag_sources"]

    # Reorder/trim columns
    keep = [
        "timestamp_utc","host","user",
        "stage_final","tactic_final","technique_final",
        "evidence_final","source_final",
        "protocol","dst_ip","hybrid_score"
    ]
    keep = [c for c in keep if c in df_map.columns]
    final_df = df_map[keep].sort_values(["timestamp_utc","hybrid_score"], ascending=[True,False])

    # Write CSV + MD
    out_csv = Path(args.out_csv)
    out_md  = Path(args.out_md)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    final_df.to_csv(out_csv, index=False, encoding="utf-8")
    print(f"[green]Wrote CSV → {out_csv}[/green]")

    lines = ["# MITRE ATT&CK Mapping (RAG + Granite)\n"]
    for _, r in final_df.head(50).iterrows():
        lines.append(
            f"- **{r.get('stage_final','')}** / {r.get('tactic_final','')} / {r.get('technique_final','')} "
            f"— {r.get('evidence_final','')}  \n"
            f"  Host: {r.get('host','')}  |  Time: {r.get('timestamp_utc','')}  |  Proto: {r.get('protocol','')}  "
            f"|  Ref: {r.get('source_final','')}"
        )
    out_md.write_text("\n".join(lines), encoding="utf-8")
    print(f"[green]Wrote MD  → {out_md}[/green]")

if __name__ == "__main__":
    main()
