#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Omnivore ETL for MDE Investigation Packages (and friends)
--------------------------------------------------------
Recursively parses *everything it can* from an extracted MDE investigation folder
(including lots of unknown file types) and emits a unified events table + IOCs.

Specialized handlers:
  - Processes.csv -> proc_start
  - Autoruns.csv / autoruns.txt -> autorun_entry (T1547)
  - dns_client_cache.csv -> DNS_CACHE
  - network_adapters.csv -> NET_ADAPTER
  - tcp_connections_detailed.csv -> net_connection
  - Security EVTX/EVT or "security.event log" -> mde_security_evtx (mapped IDs)
Generic handlers:
  - CSV/TSV/PSV (delimiter sniffing)
  - JSON (array or NDJSON)
  - XML (best-effort)
  - TXT/LOG (netstat-like, key:value, generic lines)
  - XLSX (if openpyxl/xlrd installed)
Outputs:
  - events.csv
  - events.parquet (if pyarrow/fastparquet available)
  - iocs.json
  - skipped.json (unparsed or failures)
  - network_debug.txt (when --debug)

Usage (Windows example):
  python etl_omnivore.py ^
    --input "C:\\path\\to\\EXTRACTED_FOLDER" ^
    --host WIN-HOST01 ^
    --out "C:\\path\\to\\out" ^
    --debug
"""

import os, re, json, argparse, datetime, io, zipfile
from typing import List, Dict, Any, Optional, Tuple

try:
    import pandas as pd
except Exception as e:
    raise SystemExit("Please install pandas first: pip install pandas") from e

# ------------------------------ Config ------------------------------

UNIFIED_COLUMNS = [
    "timestamp","source","host","src_ip","dst_ip","user","process",
    "event_type","action","status","msg","severity","tags",
    "mitre_tactic","mitre_technique","score"
]

# Regex for IOCs and IPs
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b")
DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")  # SHA-256

ENDPOINT_HINT_COLS = [
    "localaddress","local address","local_ip","local","laddr","localendpoint","local endpoint",
    "remoteaddress","remote address","remote_ip","foreign address","remote","raddr","remoteendpoint","remote endpoint",
    "sourceaddress","destinationaddress","srcaddress","dstaddress","source","destination",
    "message","description","commandline","cmdline","initiatingprocesscommandline"
]

DEBUG_LINES: List[str] = []
SKIPPED: List[Dict[str, str]] = []

def dbg(s: str):
    try: DEBUG_LINES.append(str(s))
    except: pass

def write_debug(out_dir: str):
    try:
        if DEBUG_LINES:
            with open(os.path.join(out_dir, "network_debug.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(DEBUG_LINES))
    except: pass

def record_skip(path: str, reason: str):
    SKIPPED.append({"path": path, "reason": reason})

# ------------------------------ Utils ------------------------------

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()

def to_dt(x: Any) -> Optional[datetime.datetime]:
    if x is None or (isinstance(x, float) and pd.isna(x)): return None
    if isinstance(x, (datetime.datetime, datetime.date)):
        return x if isinstance(x, datetime.datetime) else datetime.datetime.combine(x, datetime.time())
    s = str(x)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try: return datetime.datetime.strptime(s[:19], fmt)
        except: pass
    v = pd.to_datetime(s, errors="coerce", utc=False)
    return None if pd.isna(v) else v.to_pydatetime()

def split_hostport(s: str) -> Tuple[str, str]:
    s = (s or "").strip()
    if not s: return "", ""
    if s.startswith("[") and "]" in s:
        host = s[1:s.index("]")]; rest = s[s.index("]")+1:].lstrip(":")
        return host, rest if rest.isdigit() else ""
    if s.count(":") > 1:
        parts = s.rsplit(":", 1)
        host = parts[0]; port = parts[1] if len(parts) == 2 and parts[1].isdigit() else ""
        return host, port
    if ":" in s:
        host, port = s.split(":", 1)
        return host, port if port.isdigit() else ""
    return s, ""

def best_ip_from_value(val: str) -> str:
    s = (val or "").strip()
    if not s: return ""
    tokens = re.split(r"[\s;,|]+", s)
    candidates = []
    for t in tokens:
        host, _ = split_hostport(t)
        candidates.append(host if host else t)
    norm = []
    for c in candidates:
        if c.startswith("::ffff:"): c = c.split("::ffff:")[-1]
        norm.append(c.strip("[]"))
    for c in norm:
        m = IPV4_RE.search(c)
        if m: return m.group(0)
    for c in norm:
        m = IPV6_RE.search(c)
        if m: return m.group(0)
    return ""

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    ips = set(IPV4_RE.findall(text or "")) | set(IPV6_RE.findall(text or ""))
    doms = set(DOMAIN_RE.findall(text or ""))
    hashs = set(HASH_RE.findall(text or ""))
    return {"ips": sorted(ips), "domains": sorted(doms), "hashes": sorted(hashs)}

def make_row(source: str, host: str, **kwargs) -> Dict[str, Any]:
    row = {k: kwargs.get(k, "") for k in UNIFIED_COLUMNS}
    row["source"] = source
    row["host"] = host
    ts = kwargs.get("timestamp")
    if isinstance(ts, (datetime.datetime, pd.Timestamp)): row["timestamp"] = ts.isoformat()
    else: row["timestamp"] = str(ts) if ts else ""
    tags = kwargs.get("tags", [])
    row["tags"] = json.dumps(tags) if isinstance(tags, (list, tuple)) else str(tags or "[]")
    row["score"] = kwargs.get("score", 0.5)
    return row

def short_msg_from_row(r: pd.Series, limit: int = 2000) -> str:
    parts = []
    for c in r.index:
        v = r.get(c, "")
        if str(v) != "": parts.append(f"{c}={v}")
    return "; ".join(parts)[:limit]

# ------------------------------ Specialized Parsers (MDE-style) ------------------------------

def parse_processes_csv(path: str, host: str, rows: List[Dict[str, Any]]):
    try: df = pd.read_csv(path)
    except: df = pd.read_csv(path, sep="\t", engine="python")
    for _, r in df.fillna("").iterrows():
        ts = to_dt(r.get("CreationTime") or r.get("StartTime") or r.get("TimeCreated") or now_iso())
        pname = r.get("ProcessName") or r.get("Image") or r.get("Process") or r.get("Name") or ""
        cmd = r.get("CommandLine") or r.get("Cmd") or ""
        user = r.get("User") or r.get("Username") or r.get("Account") or r.get("UserName") or ""
        msg = f"{pname} {cmd}".strip()
        rows.append(make_row("mde_processes", host,
            timestamp=ts, process=str(pname), user=str(user),
            event_type="proc_start", action="spawn", status="observed",
            msg=msg, severity="low", tags=["mde","process"]
        ))

def parse_autoruns_csv(path: str, host: str, rows: List[Dict[str, Any]]):
    try: df = pd.read_csv(path)
    except: df = pd.read_csv(path, sep="\t", engine="python")
    for _, r in df.fillna("").iterrows():
        ts = to_dt(r.get("Timestamp") or r.get("LastWriteTime") or now_iso())
        entry = r.get("Entry") or r.get("ImagePath") or r.get("Path") or r.get("Image") or ""
        loc = r.get("Location") or r.get("Key") or ""
        signer = r.get("Signer") or r.get("Publisher") or ""
        msg = f"{entry} @ {loc} signer={signer}".strip()
        rows.append(make_row("mde_autoruns", host,
            timestamp=ts, process=str(entry), event_type="autorun_entry", action="persist",
            status="observed", msg=msg, severity="medium", tags=["mde","autoruns"],
            mitre_tactic="Persistence", mitre_technique="T1547", score=0.7
        ))

def parse_autoruns_txt(path: str, host: str, rows: List[Dict[str, Any]]):
    import csv
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        sample = f.read(4096); f.seek(0)
        try:
            sniff = csv.Sniffer().sniff(sample, delimiters="\t,;|")
            delim = sniff.delimiter
        except: delim = "\t"
        try:
            df = pd.read_csv(f, delimiter=delim)
            cols = {c.lower(): c for c in df.columns}
            entry_col = cols.get("entry") or cols.get("image path") or cols.get("image") or cols.get("path")
            loc_col   = cols.get("location") or cols.get("key") or cols.get("category")
            sign_col  = cols.get("signer") or cols.get("publisher") or cols.get("verified")
            ts_col    = cols.get("timestamp") or cols.get("time") or cols.get("lastwritetime")
            for _, r in df.fillna("").iterrows():
                entry = str(r.get(entry_col, "")) if entry_col else ""
                loc   = str(r.get(loc_col, "")) if loc_col else ""
                signer= str(r.get(sign_col, "")) if sign_col else ""
                ts    = to_dt(r.get(ts_col)) if ts_col else None
                msg   = f"{entry} @ {loc} signer={signer}".strip()
                rows.append(make_row("mde_autoruns", host,
                    timestamp=ts or now_iso(), process=entry, event_type="autorun_entry", action="persist",
                    status="observed", msg=msg, severity="medium", tags=["mde","autoruns"],
                    mitre_tactic="Persistence", mitre_technique="T1547", score=0.7
                ))
            return
        except: pass
    # key:value fallback
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        block = {}
        def flush(b):
            if not b: return
            entry = b.get("entry") or b.get("imagepath") or b.get("image") or b.get("path") or ""
            loc   = b.get("location") or b.get("key") or b.get("category") or ""
            signer= b.get("signer") or b.get("publisher") or b.get("verified") or ""
            ts    = to_dt(b.get("timestamp") or b.get("time") or b.get("lastwritetime"))
            msg   = f"{entry} @ {loc} signer={signer}".strip()
            rows.append(make_row("mde_autoruns", host,
                timestamp=ts or now_iso(), process=entry, event_type="autorun_entry", action="persist",
                status="observed", msg=msg, severity="medium", tags=["mde","autoruns"],
                mitre_tactic="Persistence", mitre_technique="T1547", score=0.7
            ))
        for line in f:
            s = line.strip()
            if not s: flush(block); block = {}; continue
            if ":" in s:
                k, v = s.split(":", 1); block[k.strip().lower()] = v.strip()
            else:
                if "entry" not in block: block["entry"] = s
        flush(block)

def parse_dns_client_cache_csv(path: str, host: str, rows: List[Dict[str, Any]]):
    try: df = pd.read_csv(path)
    except: df = pd.read_csv(path, sep="\t", engine="python")
    cols = {c.lower(): c for c in df.columns}
    name_c = cols.get("name") or cols.get("hostname") or cols.get("entry")
    data_c = cols.get("data") or cols.get("address") or cols.get("ip") or cols.get("recorddata")
    type_c = cols.get("type"); ttl_c = cols.get("ttl") or cols.get("time to live") or cols.get("time_to_live")
    dbg(f"[DNS CACHE] {path}"); dbg(f"[DNS CACHE] columns: {list(df.columns)}")
    for _, r in df.fillna("").iterrows():
        name = str(r.get(name_c, "")) if name_c else ""
        data = str(r.get(data_c, "")) if data_c else ""
        rtype = str(r.get(type_c, "")) if type_c else ""
        ttl = str(r.get(ttl_c, "")) if ttl_c else ""
        dst_ip = best_ip_from_value(data)
        msg = f"name={name}; data={data}; type={rtype}; ttl={ttl}".strip("; ")
        rows.append(make_row("mde_dns_cache", host,
            timestamp=now_iso(), src_ip="", dst_ip=dst_ip, user="", process="",
            event_type="DNS_CACHE", action="cache_entry", status="observed",
            msg=msg, severity="low", tags=["mde","dns","cache"]
        ))

def parse_network_adapters_csv(path: str, host: str, rows: List[Dict[str, Any]]):
    try: df = pd.read_csv(path)
    except: df = pd.read_csv(path, sep="\t", engine="python")
    cols = {c.lower(): c for c in df.columns}
    ipv4_c = cols.get("ipv4address") or cols.get("ipv4") or cols.get("ipaddress") or cols.get("ip address")
    ipv6_c = cols.get("ipv6address") or cols.get("ipv6")
    dbg(f"[ADAPTERS] {path}"); dbg(f"[ADAPTERS] columns: {list(df.columns)}")
    for _, r in df.fillna("").iterrows():
        ipv4 = str(r.get(ipv4_c, "")) if ipv4_c else ""
        ipv6 = str(r.get(ipv6_c, "")) if ipv6_c else ""
        src_ip = best_ip_from_value(ipv4) or best_ip_from_value(ipv6)
        rows.append(make_row("mde_net_adapters", host,
            timestamp=now_iso(), src_ip=src_ip, dst_ip="",
            user="", process="", event_type="NET_ADAPTER", action="fact", status="observed",
            msg=short_msg_from_row(r), severity="low", tags=["mde","network","adapter"]
        ))

def parse_tcp_connections_detailed_csv(path: str, host: str, rows: List[Dict[str, Any]]):
    try: df = pd.read_csv(path)
    except: df = pd.read_csv(path, sep="\t", engine="python")
    cols = {c.lower(): c for c in df.columns}
    la = cols.get("localaddress") or cols.get("local address") or cols.get("local") or cols.get("laddr") or cols.get("localendpoint")
    ra = cols.get("remoteaddress") or cols.get("remote address") or cols.get("remote") or cols.get("raddr") or cols.get("remoteendpoint")
    st = cols.get("state")
    pn = cols.get("processname") or cols.get("image") or cols.get("name")
    ts_col = cols.get("timecreated") or cols.get("timestamp") or cols.get("creationtime") or cols.get("timecreatedutc")
    dbg(f"[TCP DETAILED] {path}"); dbg(f"[TCP DETAILED] columns: {list(df.columns)}")
    for _, r in df.fillna("").iterrows():
        src_ip = best_ip_from_value(str(r.get(la, ""))) if la else ""
        dst_ip = best_ip_from_value(str(r.get(ra, ""))) if ra else ""
        if not (src_ip and dst_ip):
            found = IPV4_RE.findall(" ".join(str(r.get(c,"")) for c in df.columns)) + IPV6_RE.findall(" ".join(str(r.get(c,"")) for c in df.columns))
            if found:
                if not src_ip: src_ip = found[0]
                for f in found[1:]:
                    if f != src_ip: dst_ip = f; break
        state = str(r.get(st, "")) if st else ""
        proc  = str(r.get(pn, "")) if pn else ""
        ts    = to_dt(r.get(ts_col)) if ts_col else None
        rows.append(make_row("mde_tcp_detailed", host,
            timestamp=ts or now_iso(), src_ip=src_ip, dst_ip=dst_ip, user="", process=proc,
            event_type="net_connection", action=state or "connect", status="observed",
            msg=short_msg_from_row(r), severity="low", tags=["mde","network","tcp"]
        ))

def parse_security_eventlog(path: str, host: str, rows: List[Dict[str, Any]]):
    try:
        from Evtx.Evtx import Evtx
        import xml.etree.ElementTree as ET
        def map_event_type(eid: str) -> str:
            return {
                "4624":"logon_success","4625":"logon_failure","4634":"logoff","4672":"privilege_assigned",
                "4688":"process_creation","4697":"service_install","4698":"scheduled_task_created",
                "4720":"user_account_created","4726":"user_account_deleted","4740":"account_lockout"
            }.get(str(eid), f"event_{eid}")
        with Evtx(path) as evtx:
            for rec in evtx.records():
                xml = rec.xml()
                ts = None; eid = ""; user = ""; msg = ""
                try:
                    root = ET.fromstring(xml)
                    sys = root.find(".//System")
                    if sys is not None:
                        eid_el = sys.find("EventID")
                        if eid_el is not None and eid_el.text: eid = eid_el.text.strip()
                        t = sys.find("TimeCreated")
                        if t is not None: ts = t.get("SystemTime")
                    kv = { (d.get('Name') or '').lower(): (d.text or '') for d in root.findall(".//EventData/Data") }
                    user = kv.get("subjectusername") or kv.get("targetusername") or kv.get("accountname") or ""
                    rend = root.find(".//RenderingInfo/Message")
                    msg = rend.text.strip() if (rend is not None and rend.text) else xml[:4000]
                except: msg = xml[:4000]
                rows.append(make_row("mde_security_evtx", host,
                    timestamp=to_dt(ts) or now_iso(), user=user, process="",
                    event_type=map_event_type(eid or ""), action="security_event", status="observed",
                    msg=msg, severity="low", tags=["mde","security","evtx"], score=0.5
                ))
    except Exception as e:
        rows.append(make_row("mde_security_evtx", host,
            timestamp=now_iso(), event_type="parser_notice", action="hint", status="skipped",
            msg=f"Could not parse Security event log '{os.path.basename(path)}'. Install python-evtx or export to CSV. Error: {e}",
            severity="low", tags=["mde","security","evtx","notice"]
        ))

# ------------------------------ Generic Parsers ------------------------------

def parse_csv_any(path: str, host: str, rows: List[Dict[str, Any]]):
    import csv
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            sample = f.read(8192); f.seek(0)
            try:
                sniff = csv.Sniffer().sniff(sample, delimiters=",\t;|")
                delim = sniff.delimiter
            except: delim = "," if "," in sample else ("\t" if "\t" in sample else ";")
            df = pd.read_csv(f, delimiter=delim)
    except Exception as e:
        record_skip(path, f"CSV parse failed: {e}"); return
    cols = {c.lower(): c for c in df.columns}
    ts_col = next((cols.get(c) for c in ("timecreated","timestamp","creationtime","time","date","timecreatedutc") if c in cols), None)
    la = next((cols.get(c) for c in ENDPOINT_HINT_COLS if c in cols and "local" in c), None)
    ra = next((cols.get(c) for c in ENDPOINT_HINT_COLS if c in cols and ("remote" in c or "foreign" in c or "dest" in c)), None)
    for _, r in df.fillna("").iterrows():
        src_ip = best_ip_from_value(r.get(la, "")) if la else ""
        dst_ip = best_ip_from_value(r.get(ra, "")) if ra else ""
        if not (src_ip and dst_ip):
            rowtxt = " ".join(str(r.get(c, "")) for c in df.columns)
            found = IPV4_RE.findall(rowtxt) + IPV6_RE.findall(rowtxt)
            if found:
                if not src_ip: src_ip = found[0]
                for f in found[1:]:
                    if f != src_ip: dst_ip = f; break
        ts = to_dt(r.get(ts_col)) if ts_col else None
        rows.append(make_row("generic_csv", host,
            timestamp=ts or now_iso(), src_ip=src_ip, dst_ip=dst_ip,
            user=str(r.get(cols.get("user",""), "")), process=str(r.get(cols.get("process",""), "")),
            event_type=str(r.get(cols.get("event_type",""), "row")), action=str(r.get(cols.get("action",""), "")) or "observed",
            status="observed", msg=short_msg_from_row(r), severity="low", tags=["generic","csv"]
        ))

def parse_json_any(path: str, host: str, rows: List[Dict[str, Any]]):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read().strip()
        if not txt: return
        if txt[0] == "[":
            data = json.loads(txt)
            iterable = data if isinstance(data, list) else [data]
        else:
            # NDJSON
            iterable = [json.loads(line) for line in txt.splitlines() if line.strip()]
    except Exception as e:
        record_skip(path, f"JSON parse failed: {e}"); return
    for obj in iterable:
        try:
            msg = json.dumps(obj)[:2000]
            # pick common keys
            ts = obj.get("TimeCreated") or obj.get("timestamp") or obj.get("time") or obj.get("date")
            user = obj.get("User") or obj.get("user") or obj.get("AccountName")
            proc = obj.get("ProcessName") or obj.get("process") or obj.get("Image")
            # scan for ips
            rowtxt = msg
            found = IPV4_RE.findall(rowtxt) + IPV6_RE.findall(rowtxt)
            src_ip = found[0] if found else ""
            dst_ip = ""
            for f in found[1:]:
                if f != src_ip: dst_ip = f; break
            rows.append(make_row("generic_json", host,
                timestamp=to_dt(ts) or now_iso(), src_ip=src_ip, dst_ip=dst_ip,
                user=str(user or ""), process=str(proc or ""), event_type=str(obj.get("event_type","json")),
                action=str(obj.get("action","observed")), status="observed", msg=msg, severity="low",
                tags=["generic","json"]
            ))
        except Exception as e:
            record_skip(path, f"JSON object skipped: {e}")

def parse_xml_any(path: str, host: str, rows: List[Dict[str, Any]]):
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(path); root = tree.getroot()
    except Exception as e:
        record_skip(path, f"XML parse failed: {e}"); return
    text = (open(path, "r", encoding="utf-8", errors="ignore").read()[:4000])
    found = IPV4_RE.findall(text) + IPV6_RE.findall(text)
    src_ip = found[0] if found else ""; dst_ip = ""
    for f in found[1:]:
        if f != src_ip: dst_ip = f; break
    rows.append(make_row("generic_xml", host,
        timestamp=now_iso(), src_ip=src_ip, dst_ip=dst_ip,
        user="", process="", event_type="xml_record", action="observed", status="observed",
        msg=text, severity="low", tags=["generic","xml"]
    ))

def parse_txt_any(path: str, host: str, rows: List[Dict[str, Any]]):
    # Try netstat-like first (two endpoints), then key:value, else generic line
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s: continue
                # endpoints
                toks = re.split(r"\s+", s)
                seen = []
                for t in toks:
                    host_t, _ = split_hostport(t)
                    ip = best_ip_from_value(host_t)
                    if ip:
                        seen.append(ip)
                        if len(seen) == 2: break
                src_ip = seen[0] if seen else ""
                dst_ip = seen[1] if len(seen) > 1 else ""
                # key:value extraction for user/process hints
                user = ""; proc = ""
                kv_pairs = re.findall(r"([A-Za-z][A-Za-z0-9_ ]{0,32}):\s*([^\s].+)", s)
                for k, v in kv_pairs:
                    lk = k.lower().strip()
                    if not user and ("user" in lk or "account" in lk): user = v.strip()
                    if not proc and ("process" in lk or "image" in lk or "exe" in lk): proc = v.strip()
                rows.append(make_row("generic_txt", host,
                    timestamp=now_iso(), src_ip=src_ip, dst_ip=dst_ip,
                    user=user, process=proc, event_type="text_line", action="observed", status="observed",
                    msg=s[:2000], severity="low", tags=["generic","txt"]
                ))
    except Exception as e:
        record_skip(path, f"TXT parse failed: {e}")

def parse_log_any(path: str, host: str, rows: List[Dict[str, Any]]):
    return parse_txt_any(path, host, rows)

def parse_xlsx_any(path: str, host: str, rows: List[Dict[str, Any]]):
    try:
        df = pd.read_excel(path)
    except Exception as e:
        record_skip(path, f"XLSX parse failed: {e}"); return
    # reuse CSV logic on dataframe
    cols = {c.lower(): c for c in df.columns}
    ts_col = next((cols.get(c) for c in ("timecreated","timestamp","creationtime","time","date","timecreatedutc") if c in cols), None)
    la = next((cols.get(c) for c in ENDPOINT_HINT_COLS if c in cols and "local" in c), None)
    ra = next((cols.get(c) for c in ENDPOINT_HINT_COLS if c in cols and ("remote" in c or "foreign" in c or "dest" in c)), None)
    for _, r in df.fillna("").iterrows():
        src_ip = best_ip_from_value(r.get(la, "")) if la else ""
        dst_ip = best_ip_from_value(r.get(ra, "")) if ra else ""
        if not (src_ip and dst_ip):
            rowtxt = " ".join(str(r.get(c, "")) for c in df.columns)
            found = IPV4_RE.findall(rowtxt) + IPV6_RE.findall(rowtxt)
            if found:
                if not src_ip: src_ip = found[0]
                for f in found[1:]:
                    if f != src_ip: dst_ip = f; break
        ts = to_dt(r.get(ts_col)) if ts_col else None
        rows.append(make_row("generic_xlsx", host,
            timestamp=ts or now_iso(), src_ip=src_ip, dst_ip=dst_ip,
            user=str(r.get(cols.get("user",""), "")), process=str(r.get(cols.get("process",""), "")),
            event_type=str(r.get(cols.get("event_type",""), "row")), action=str(r.get(cols.get("action",""), "")) or "observed",
            status="observed", msg=short_msg_from_row(r), severity="low", tags=["generic","xlsx"]
        ))

# ------------------------------ Walker ------------------------------

KNOWN_DISPATCH = [
    # precise filename ends
    ("dns_client_cache.csv", parse_dns_client_cache_csv),
    ("network_adapters.csv", parse_network_adapters_csv),
    ("tcp_connections_detailed.csv", parse_tcp_connections_detailed_csv),
]

def dispatch_file(path: str, host: str, rows: List[Dict[str, Any]], debug: bool):
    lower = os.path.basename(path).lower()
    # Specific filename endings first
    for suffix, fn in KNOWN_DISPATCH:
        if lower.endswith(suffix):
            fn(path, host, rows); return

    # Security logs (EVTX/EVT or 'security.event log')
    if lower.endswith(".evtx") or lower.endswith(".evt") or ("security" in lower and "event" in lower and lower.endswith("log")):
        parse_security_eventlog(path, host, rows); return

    # Processes
    if lower.endswith(".csv") and ("process" in lower or "proc" in lower):
        parse_processes_csv(path, host, rows); return

    # Autoruns
    if lower.endswith(".csv") and ("autorun" in lower or "startup" in lower or "autostart" in lower):
        parse_autoruns_csv(path, host, rows); return
    if lower.endswith(".txt") and ("autorun" in lower or "startup" in lower or "autostart" in lower):
        parse_autoruns_txt(path, host, rows); return

    # Network (generic CSV/TXT)
    if lower.endswith(".csv") and ("network" in lower or "netconn" in lower or "netstat" in lower or "connections" in lower):
        parse_csv_any(path, host, rows); return
    if lower.endswith(".txt") and ("network" in lower or "net" in lower or "conn" in lower):
        parse_txt_any(path, host, rows); return

    # Security CSV fallback
    if lower.endswith(".csv") and ("security" in lower or "event" in lower or "log" in lower):
        parse_csv_any(path, host, rows); return

    # Generic by extension
    if lower.endswith(".csv") or lower.endswith(".tsv") or lower.endswith(".psv"):
        parse_csv_any(path, host, rows); return
    if lower.endswith(".json") or lower.endswith(".ndjson"):
        parse_json_any(path, host, rows); return
    if lower.endswith(".xml"):
        parse_xml_any(path, host, rows); return
    if lower.endswith(".log"):
        parse_log_any(path, host, rows); return
    if lower.endswith(".txt"):
        parse_txt_any(path, host, rows); return
    if lower.endswith(".xlsx") or lower.endswith(".xls"):
        parse_xlsx_any(path, host, rows); return
    if lower.endswith(".zip"):
        # expand nested zip in-memory and parse entries
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir(): continue
                    try:
                        data = zf.read(info)
                        # write to temp in-memory buffer for dispatch by extension
                        name = info.filename
                        tmp = io.BytesIO(data)
                        # save temp to disk to reuse parsers expecting a path
                        nested_path = path + "::" + name
                        # Try by extension: we support text-like; binary evtx won't be here
                        ext = name.lower()
                        if ext.endswith(".csv") or ext.endswith(".tsv") or ext.endswith(".psv"):
                            df = pd.read_csv(io.StringIO(data.decode("utf-8", errors="ignore")))
                            for _, r in df.fillna("").iterrows():
                                rows.append(make_row("zip_csv", host,
                                    timestamp=now_iso(), msg=short_msg_from_row(r), severity="low",
                                    event_type="row", action="observed", status="observed",
                                    tags=["zip","csv"]
                                ))
                        elif ext.endswith(".json") or ext.endswith(".ndjson"):
                            try:
                                txt = data.decode("utf-8", errors="ignore")
                                if txt.strip().startswith("["):
                                    arr = json.loads(txt); iterable = arr if isinstance(arr, list) else [arr]
                                else:
                                    iterable = [json.loads(l) for l in txt.splitlines() if l.strip()]
                                for obj in iterable:
                                    rows.append(make_row("zip_json", host,
                                        timestamp=to_dt(obj.get("timestamp")) or now_iso(),
                                        msg=json.dumps(obj)[:2000], severity="low",
                                        event_type="json", action="observed", status="observed",
                                        tags=["zip","json"]
                                    ))
                            except Exception as e:
                                record_skip(nested_path, f"zip json read failed: {e}")
                        elif ext.endswith(".xml"):
                            try:
                                txt = data.decode("utf-8", errors="ignore")[:4000]
                                rows.append(make_row("zip_xml", host,
                                    timestamp=now_iso(), msg=txt, severity="low",
                                    event_type="xml_record", action="observed", status="observed",
                                    tags=["zip","xml"]
                                ))
                            except Exception as e:
                                record_skip(nested_path, f"zip xml read failed: {e}")
                        elif ext.endswith(".log") or ext.endswith(".txt"):
                            try:
                                for line in data.decode("utf-8", errors="ignore").splitlines():
                                    s = line.strip()
                                    if not s: continue
                                    rows.append(make_row("zip_txt", host,
                                        timestamp=now_iso(), msg=s[:2000], severity="low",
                                        event_type="text_line", action="observed", status="observed",
                                        tags=["zip","txt"]
                                    ))
                            except Exception as e:
                                record_skip(nested_path, f"zip txt read failed: {e}")
                        else:
                            record_skip(nested_path, "zip entry type not supported")
                    except Exception as e:
                        record_skip(path + "::" + info.filename, f"zip entry error: {e}")
        except Exception as e:
            record_skip(path, f"zip open failed: {e}")
        return

    # Unknown binary
    record_skip(path, "unknown extension / unsupported file type")

def walk_all(input_dir: str, host: str, debug: bool) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for root, _, files in os.walk(input_dir):
        for fname in files:
            path = os.path.join(root, fname)
            try:
                dispatch_file(path, host, rows, debug)
            except Exception as e:
                record_skip(path, f"dispatch error: {e}")
    return rows

# ------------------------------ Outputs ------------------------------

def build_iocs(rows: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    ips, doms, hashes, users = set(), set(), set(), set()
    for r in rows:
        text = " ".join(str(r.get(k,"")) for k in ("msg","process","user","src_ip","dst_ip"))
        found = extract_iocs_from_text(text)
        ips.update(found["ips"]); doms.update(found["domains"]); hashes.update(found["hashes"])
        if r.get("user"): users.add(str(r["user"]))
    return {"ips": sorted(ips), "domains": sorted(doms), "hashes": sorted(hashes), "users": sorted(users)}

def save_outputs(rows: List[Dict[str, Any]], out_dir: str):
    ensure_dir(out_dir)
    df = pd.DataFrame(rows, columns=UNIFIED_COLUMNS)
    try:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.sort_values("timestamp", kind="mergesort")
    except: pass
    csv_path = os.path.join(out_dir, "events.csv"); df.to_csv(csv_path, index=False)
    pq_path = None
    try:
        pq_path = os.path.join(out_dir, "events.parquet"); df.to_parquet(pq_path, index=False)
    except: pq_path = None
    iocs = build_iocs(rows)
    ioc_path = os.path.join(out_dir, "iocs.json"); open(ioc_path, "w", encoding="utf-8").write(json.dumps(iocs, indent=2))
    skipped_path = os.path.join(out_dir, "skipped.json"); open(skipped_path, "w", encoding="utf-8").write(json.dumps(SKIPPED, indent=2))
    return csv_path, pq_path, ioc_path, skipped_path, len(df)

# ------------------------------ CLI ------------------------------

def main():
    ap = argparse.ArgumentParser(description="Omnivore ETL for MDE Investigation Package")
    ap.add_argument("--input", required=True, help="Path to extracted folder")
    ap.add_argument("--host", required=True, help="Hostname tag")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--debug", action="store_true", help="Write network_debug.txt")
    args = ap.parse_args()

    rows = walk_all(args.input, args.host, args.debug)
    csv_path, pq_path, ioc_path, skipped_path, n = save_outputs(rows, args.out)

    if args.debug: write_debug(args.out)

    print(f"[OK] Parsed {n} rows")
    print(f"[OUT] events.csv     -> {csv_path}")
    print(f"[OUT] events.parquet -> {pq_path if pq_path else 'skipped (parquet engine missing)'}")
    print(f"[OUT] iocs.json      -> {ioc_path}")
    print(f"[OUT] skipped.json   -> {skipped_path}")

if __name__ == "__main__":
    main()
