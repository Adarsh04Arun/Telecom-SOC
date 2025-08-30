#!/usr/bin/env python3
from pathlib import Path
import argparse, json, re, pandas as pd, numpy as np
from sentence_transformers import SentenceTransformer
try:
    import faiss; HAVE_FAISS=True
except Exception:
    HAVE_FAISS=False
from pypdf import PdfReader
from rich import print

def read_text(p: Path)->str:
    if p.suffix.lower() in [".md",".txt"]:
        return p.read_text(encoding="utf-8", errors="ignore")
    if p.suffix.lower()==".pdf":
        try:
            r=PdfReader(str(p))
            return "\n".join(page.extract_text() or "" for page in r.pages)
        except Exception: return ""
    return ""

def chunk_text(t: str, size=900, overlap=150):
    t=re.sub(r"\s+\n","\n",t); w=t.split(); out=[]; i=0
    while i<len(w):
        out.append(" ".join(w[i:i+size])); i+= (size-overlap)
    return [x for x in out if x.strip()]

def mitre_rows_to_text(csv_path: Path):
    if not csv_path.exists(): return []
    df=pd.read_csv(csv_path)
    rows=[]
    for _,r in df.iterrows():
        doc=f"MITRE Mapping: Stage={r.get('stage','')} Tactic={r.get('tactic','')} Technique={r.get('technique','')} Signal={r.get('signal','')} Host={r.get('host','')} Time={r.get('timestamp_utc','')}"
        rows.append((doc,{"source":"mitre_csv","file":csv_path.name}))
    return rows

ap=argparse.ArgumentParser()
ap.add_argument("--knowledge_dir", required=True)
ap.add_argument("--mitre_csv", required=True)
ap.add_argument("--outdir", required=True)
args=ap.parse_args()

kdir=Path(args.knowledge_dir); out=Path(args.outdir); out.mkdir(parents=True, exist_ok=True)
docs=[]; metas=[]
for p in kdir.glob("**/*"):
    if p.suffix.lower() in [".md",".txt",".pdf"]:
        raw=read_text(p)
        for i,ch in enumerate(chunk_text(raw)):
            docs.append(ch); metas.append({"source":"file","file":p.name,"chunk":i})

for txt,meta in mitre_rows_to_text(Path(args.mitre_csv)):
    docs.append(txt); metas.append(meta)

if not docs: print("[red]No docs found[/red]"); raise SystemExit(1)

print("[cyan]Embedding with all-MiniLM-L6-v2[/cyan]")
model=SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
embs=model.encode(docs, convert_to_numpy=True, normalize_embeddings=True)

if HAVE_FAISS:
    dim=embs.shape[1]; index=faiss.IndexFlatIP(dim); index.add(embs.astype(np.float32))
    faiss.write_index(index, str(out/"kb.faiss")); backend="faiss"
else:
    np.save(out/"kb.npy", embs); backend="numpy"

(out/"texts.jsonl").write_text("\n".join(json.dumps({"text":t}) for t in docs), encoding="utf-8")
(out/"metas.jsonl").write_text("\n".join(json.dumps(m) for m in metas), encoding="utf-8")
(out/"backend.txt").write_text(backend, encoding="utf-8")
print(f"[green]KB built → {out} (backend={backend}, docs={len(docs)})[/green]")
