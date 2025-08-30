import os, argparse, json
import uvicorn
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer, util

# --- Load env ---
load_dotenv(override=True)
MODEL_PATH = os.getenv("MODEL_PATH", "artifacts/model/model_pipeline.joblib")
RAG_INDEX_DIR = os.getenv("RAG_INDEX_DIR", "artifacts/rag_index")

# --- FastAPI app ---
app = FastAPI(title="Telecom SOC Copilot", version="1.0")

# --- Request schema ---
class EventIn(BaseModel):
    msg: str
    host: str = "unknown"
    protocol: str = "?"
    rule_score: float = 0.5
    severity_num: int = 3
    hour: int = 12
    is_internal_dst: int = 1

# --- Globals ---
model = None
kb_texts, kb_metas, kb_embs = [], [], None
embedder = None

# --- Helper: Load model ---
def load_model():
    global model
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"MODEL_PATH not found: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)
    print(f"[OK] Model loaded: {MODEL_PATH}")

# --- Helper: Load RAG index ---
def load_kb():
    global kb_texts, kb_metas, kb_embs, embedder
    idx = Path(RAG_INDEX_DIR)
    if not idx.exists():
        print("[WARN] No RAG index found, run build-kb first")
        return
    kb_texts = [json.loads(l)["text"] for l in open(idx/"texts.jsonl", encoding="utf-8")]
    kb_metas = [json.loads(l) for l in open(idx/"metas.jsonl", encoding="utf-8")]
    kb_embs = np.load(idx/"kb.npy")
    embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    print(f"[OK] RAG index loaded: {len(kb_texts)} docs")

# --- Hybrid scoring ---
def score_event(ev: dict):
    x = [ev["msg"]]
    pred = float(model.predict_proba(x)[0,1])
    hybrid = 0.5*ev.get("rule_score",0.5) + 0.5*pred
    return pred, hybrid

# --- RAG retrieval ---
def rag_lookup(query: str, top_k=3):
    if kb_embs is None: return []
    q_emb = embedder.encode(query, convert_to_numpy=True, normalize_embeddings=True)
    scores = util.cos_sim(q_emb, kb_embs)[0].cpu().numpy()
    idxs = scores.argsort()[::-1][:top_k]
    return [{"text": kb_texts[i], "meta": kb_metas[i], "score": float(scores[i])} for i in idxs]

# --- FastAPI routes ---
@app.post("/score_one")
def score_one(ev: EventIn):
    pred, hybrid = score_event(ev.dict())
    evidence = rag_lookup(ev.msg)
    return {"event": ev.dict(), "pred_ml": pred, "hybrid_score": hybrid, "evidence": evidence}

@app.post("/score_batch")
def score_batch(events: list[EventIn]):
    out = []
    for ev in events:
        pred, hybrid = score_event(ev.dict())
        out.append({**ev.dict(), "pred_ml": pred, "hybrid_score": hybrid})
    return out

# --- Build KB helper ---
def build_kb(knowledge_dir: str, mitre_csv: str, outdir: str):
    from sentence_transformers import SentenceTransformer
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    docs, metas = [], []

    for p in Path(knowledge_dir).glob("*.md"):
        docs.append(p.read_text(encoding="utf-8"))
        metas.append({"source":"file","file":p.name})

    df = pd.read_csv(mitre_csv)
    for _, r in df.iterrows():
        txt = f"MITRE: Stage={r.stage} Tactic={r.tactic} Technique={r.technique} Signal={r.signal}"
        docs.append(txt)
        metas.append({"source":"mitre_csv","file":"mitre_mapping_autodraft.csv"})

    embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    embs = embedder.encode(docs, convert_to_numpy=True, normalize_embeddings=True)

    np.save(out/"kb.npy", embs)
    (out/"texts.jsonl").write_text("\n".join(json.dumps({"text":t}) for t in docs), encoding="utf-8")
    (out/"metas.jsonl").write_text("\n".join(json.dumps(m) for m in metas), encoding="utf-8")
    (out/"backend.txt").write_text("numpy", encoding="utf-8")

    print(f"[OK] KB built at {outdir}, {len(docs)} docs embedded")

# --- Main CLI ---
def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    kb = sub.add_parser("build-kb")
    kb.add_argument("--knowledge", required=True)
    kb.add_argument("--mitre", required=True)
    kb.add_argument("--out", required=True)

    serve = sub.add_parser("serve")
    serve.add_argument("--host", type=str, default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()

    if args.cmd == "build-kb":
        build_kb(args.knowledge, args.mitre, args.out)
    elif args.cmd == "serve":
        load_model()
        load_kb()
        uvicorn.run("soc_copilot:app", host=args.host, port=args.port, reload=True)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
