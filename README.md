# 🛰️ Telecom SOC 

## 🔍 Overview
This project is a **Security Operations Center (SOC) Copilot**.  
It combines:
- **Hybrid Scoring** → Rules + ML model (`model_pipeline.joblib`)  
- **RAG (Retrieval-Augmented Generation)** → Knowledge base + MITRE mappings  
- **Optional IBM Granite LLM (watsonx.ai)** → Human-readable explanations and recommended actions  

Analysts can upload events, score them for suspiciousness, retrieve relevant evidence, and get **actionable incident reports**.

---

## 🚀 Features
- ✅ **Event Scoring** — Fuses rule scores and ML predictions into a `hybrid_score`  
- ✅ **Alerting** — Flags events above a threshold (`THRESH`)  
- ✅ **RAG Evidence** — Retrieves triage notes, playbooks, and MITRE mappings  
- ✅ **Copilot Explanation** — Optional integration with **IBM Granite** for concise guidance  
- ✅ **Web UI** — Built-in HTML UI (no Streamlit needed)  
- ✅ **API Endpoints** — `/score_one` and `/score_batch` (FastAPI + Swagger docs)  

---

## ⚙️ Setup

### 1. Clone & install deps
```bash
git clone <your_repo_url>
cd <your_repo_name>
pip install -r requirements.txt
```

Or install manually:
```bash
pip install fastapi uvicorn[standard] pydantic python-dotenv pandas numpy joblib sentence-transformers faiss-cpu pypdf requests ibm-watsonx-ai
```

### 2. Prepare artifacts
- **ML Model**: place your trained `model_pipeline.joblib` under `./model/`
- **Knowledge base**: put SOC playbooks / PDFs / notes under `./knowledge/`
- **MITRE CSV**: ensure you have `./docs/mitre_mapping_autodraft.csv`

### 3. Build the RAG index
```bash
python soc_copilot.py build-kb --knowledge ./knowledge --mitre ./docs/mitre_mapping_autodraft.csv --out ./rag_index
```

---

## ▶️ Run the Copilot

Start the API + web UI:
```bash
python soc_copilot.py serve --port 8080
```

Open in your browser:
```
http://localhost:8080
```

- Enter an event → press **Analyze** → see:
  - `hybrid_score` + alert flag  
  - RAG evidence (from playbooks / MITRE)  
  - Optional Granite-generated explanation  

---

## 🔌 API Usage

### Swagger docs
Once running, visit:
```
http://localhost:8080/docs
```

### Example: Score a single event
```bash
curl -X POST "http://localhost:8080/score_one" -H "Content-Type: application/json" -d '{
  "msg": "Failed SSH login from 203.0.113.10",
  "host": "WIN-HOST01",
  "protocol": "SSH",
  "rule_score": 0.6,
  "severity_num": 4,
  "hour": 10,
  "is_internal_dst": 1
}'
```

---

## 🧠 Granite Integration (Optional)
To enable IBM Granite LLM explanations, set env variables (or use `.env`):

```bash
export WATSONX_MODEL_ID=granite-13b-instruct-v2
export WATSONX_PROJECT_ID=<your_project_guid>
export WATSONX_API_KEY=<your_ibm_cloud_api_key>
export WATSONX_URL=https://eu-de.ml.cloud.ibm.com
```

Without these, the Copilot still works with **RAG-only evidence**.

---

## 🛡️ Notes
- Adjust `ALPHA` (fusion weight) and `THRESH` (alert threshold) via `.env`  
- Add more `.md`/`.pdf` under `knowledge/` and re-run `build-kb` to improve retrieval  
- For production: containerize with Docker and secure the API  

---

