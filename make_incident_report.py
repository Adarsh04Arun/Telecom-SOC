import pandas as pd
from pathlib import Path

TOP = r"C:\coding\jupyter personal\HackVerse\hybrid_out\top_alerts_tuned.csv"
MIT = r"C:\coding\jupyter personal\HackVerse\docs\mitre_mapping_rag.csv"   # <— NEW
OUT = Path(r"C:\coding\jupyter personal\HackVerse\docs"); OUT.mkdir(parents=True, exist_ok=True)

top = pd.read_csv(TOP)
mitre = pd.read_csv(MIT)

top['timestamp'] = pd.to_datetime(top['timestamp'], errors='coerce', utc=True)
ioc_ips = sorted(set(top['src_ip'].dropna().astype(str).tolist() + top['dst_ip'].dropna().astype(str).tolist()))[:50]
hosts = top['host'].dropna().astype(str).value_counts().head(10).index.tolist()
users = top['user'].dropna().astype(str).value_counts().head(10).index.tolist()

lines = []
lines.append("# Incident Investigation Summary\n")
lines.append("## Timeline (UTC)")
for t, grp in top.sort_values("timestamp").groupby(top['timestamp'].dt.floor('T')):
    lines.append(f"- {t}: {len(grp)} events")

lines.append("\n## MITRE ATT&CK Mapping (RAG-augmented)")
for _, r in mitre.head(30).iterrows():
    lines.append(f"- **{r['stage_final']}** / {r['tactic_final']} / {r['technique_final']} – {r['evidence_final']} "
                 f"(host: {r.get('host','')}, {r.get('timestamp_utc','')}; ref: {r.get('source_final','')})")

lines.append("\n## Indicators of Compromise (IOCs)")
for ip in ioc_ips:
    lines.append(f"- {ip}")

lines.append("\n## Impacted Hosts/Users")
lines.append(f"- Hosts: {', '.join(hosts)}")
lines.append(f"- Users: {', '.join(users)}")

lines.append("\n## Root-cause Hypothesis")
lines.append("- Likely SSH credential misuse, persistence via autoruns/tasks, and app-layer C2 (SMTP/SIP).")

lines.append("\n## Prioritized Remediation")
lines.append("1) Quarantine top hosts and reset credentials for accounts appearing in SSH ingress.")
lines.append("2) Remove unauthorized autoruns/scheduled tasks; monitor for re-creation.")
lines.append("3) Block suspicious egress IPs; tighten SMTP/SIP egress policies temporarily.")
lines.append("4) Enable MFA/rotate keys; raise detection thresholds on atypical protocols.")

Path(OUT/"incident_report_rag.md").write_text("\n".join(lines), encoding="utf-8")
print("[OK] docs\\incident_report_rag.md")
