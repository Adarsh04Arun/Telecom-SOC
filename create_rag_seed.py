#!/usr/bin/env python3
from pathlib import Path
base = Path(r"C:\coding\jupyter personal\HackVerse\knowledge")
base.mkdir(parents=True, exist_ok=True)

(base/"playbooks.md").write_text("""
# SOC Playbooks (Mini)
## SSH Ingress Triage
- Verify source IP reputation, geo, and prior failed logins.
- Check account MFA & recent password changes.
- Isolate host if lateral movement suspected.
- Reset credentials; rotate keys.
## Windows Persistence (Autoruns/Scheduled Tasks)
- Enumerate Run/RunOnce, Services, Scheduled Tasks.
- Remove unauthorized entries; collect binaries for scan.
- Monitor re-creation attempts; enable tamper protection.
## App-layer C2 (SMTP/SIP)
- Flag unusual egress to rare ASNs/ports.
- Throttle or block suspicious destinations.
- Capture samples for sandbox; review mail relays/VoIP logs.
""".strip(), encoding="utf-8")

(base/"mitre_notes.md").write_text("""
# MITRE Notes (Mini)
- TA0001 Initial Access → T1078 Valid Accounts (SSH use)
- TA0003 Persistence → T1547 Boot or Logon Autostart Execution
- TA0011 Command and Control → T1071 Application Layer Protocol (SMTP/SIP)
- TA0007 Discovery → T1046 Network Service Scanning
""".strip(), encoding="utf-8")

print("[OK] Seeded:", base)
