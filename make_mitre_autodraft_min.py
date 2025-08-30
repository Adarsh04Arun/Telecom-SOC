#!/usr/bin/env python3
import argparse, pandas as pd
from pathlib import Path

def infer(row):
    et = str(row.get("event_type","")).lower()
    proto = str(row.get("protocol","")).upper()
    reasons = str(row.get("rule_reasons","")).lower()
    if any(k in et for k in ["autorun","scheduled_task","service_install"]) or "persistence" in reasons:
        return ("Persistence","TA0003","T1547 Boot or Logon Autostart Execution","Persistence indicator")
    if proto=="SSH":
        return ("Initial Access","TA0001","T1078 Valid Accounts","Ingress SSH / credential use")
    if proto in ("SIP","SMTP"):
        return ("Command and Control","TA0011","T1071 Application Layer Protocol",f"High-sev {proto} traffic")
    return ("Discovery","TA0007","T1046 Network Service Scanning","Suspicious network activity")

ap = argparse.ArgumentParser()
ap.add_argument("--top_csv", required=True)
ap.add_argument("--out_csv", required=True)
args = ap.parse_args()

df = pd.read_csv(args.top_csv)
if "timestamp" in df.columns:
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
rows=[]
for _,r in df.head(200).iterrows():
    stage,tactic,tech,signal = infer(r)
    rows.append({
        "timestamp_utc": r.get("timestamp",""),
        "host": r.get("host",""),
        "user": r.get("user",""),
        "stage": stage, "tactic": tactic, "technique": tech,
        "signal": signal, "protocol": r.get("protocol",""),
        "dst_ip": r.get("dst_ip",""), "hybrid_score": r.get("hybrid_score",0)
    })
out = pd.DataFrame(rows).sort_values(["timestamp_utc","hybrid_score"], ascending=[True,False])
Path(args.out_csv).parent.mkdir(parents=True, exist_ok=True)
out.to_csv(args.out_csv, index=False, encoding="utf-8")
print("[OK] Wrote:", args.out_csv, "rows:", len(out))
