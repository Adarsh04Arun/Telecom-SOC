import pandas as pd
import json
from pathlib import Path
import numpy as np

DATA_PATH = "/mnt/data/telecom_soc_events_realtime.csv"
OUT_DIR = Path("/mnt/data/ibm_dataprep_step1")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Load dataset
df = pd.read_csv(DATA_PATH)

# ---- 1) Basic shape & nulls ----
shape_info = {"rows": int(df.shape[0]), "cols": int(df.shape[1])}
nulls = df.isna().sum().to_dict()
empties = (df.astype(str).eq("").sum()).to_dict()

# ---- 2) Class balance ----
label_counts = df["label_suspicious"].value_counts(dropna=False)
label_dist = (label_counts / len(df)).round(4).to_dict()

# ---- 3) Cardinality for key categoricals ----
card = {
    "host": int(df["host"].nunique()),
    "user": int(df["user"].nunique()),
    "process": int(df["process"].nunique()),
    "event_type": int(df["event_type"].nunique()),
    "protocol": int(df["protocol"].nunique()),
    "service": int(df["service"].nunique()),
}

# ---- 4) Data dictionary proposal ----
dtypes_map = {
    "timestamp": "datetime",
    "date": "string",
    "hour": "integer",
    "host": "string",
    "user": "string",
    "process": "string",
    "event_type": "string",
    "action": "string",
    "status": "string",
    "severity": "string",
    "severity_num": "integer",
    "protocol": "string",
    "service": "string",
    "src_ip": "string",
    "dst_ip": "string",
    "is_internal_src": "integer",
    "is_internal_dst": "integer",
    "tags": "string",
    "msg": "string",
    "label_suspicious": "integer"
}

data_dict = {
    "name": "telecom_soc_events_realtime",
    "shape": shape_info,
    "null_counts": nulls,
    "empty_string_counts": empties,
    "class_balance": label_dist,
    "cardinality": card,
    "column_types": dtypes_map,
    "primary_keys_suggestion": ["timestamp","host","event_type","src_ip","dst_ip"],
    "target": "label_suspicious",
    "feature_roles": {
        "categorical": ["host","user","process","event_type","action","status","severity","protocol","service","tags"],
        "numerical": ["severity_num","hour","is_internal_src","is_internal_dst"],
        "text": ["msg"],
        "temporal": ["timestamp","date"]
    }
}

# Save data dictionary
with open(OUT_DIR / "data_dictionary_step1.json", "w", encoding="utf-8") as f:
    json.dump(data_dict, f, indent=2)

# ---- 5) Save a thin 5k sample for quick experiments ----
sample_5k = df.sample(n=min(5000, len(df)), random_state=42).reset_index(drop=True)
sample_path = OUT_DIR / "telecom_soc_events_sample_5k.csv"
sample_5k.to_csv(sample_path, index=False)

# ---- 6) Create small summary tables to display ----
summary_df = pd.DataFrame({
    "metric": ["rows","cols","pos_labels","neg_labels","pos_ratio","neg_ratio"],
    "value": [
        shape_info["rows"],
        shape_info["cols"],
        int(label_counts.get(1, 0)),
        int(label_counts.get(0, 0)),
        float(label_dist.get(1, 0.0)),
        float(label_dist.get(0, 0.0)),
    ]
})

top_event_types = df["event_type"].value_counts().head(10).reset_index()
top_event_types.columns = ["event_type","count"]

top_protocols = df["protocol"].value_counts().head(10).reset_index()
top_protocols.columns = ["protocol","count"]

import ace_tools as tools
tools.display_dataframe_to_user("Step 1 Summary", summary_df)
tools.display_dataframe_to_user("Top Event Types", top_event_types)
tools.display_dataframe_to_user("Top Protocols", top_protocols)
