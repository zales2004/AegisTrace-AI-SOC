
import os
import warnings
from datetime import datetime, timezone

import requests
import urllib3
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi import Query
from integrations.virustotal import lookup_ip, lookup_file_hash
from integrations.vt_scheduler import enqueue, get_result, start_scheduler, stop_scheduler
from integrations.file_monitor import scan_once, recent_files, file_history, start_file_monitor, stop_file_monitor
from integrations.quarantine import quarantine_file, process_auto_quarantine, audit_recent

from database.storage import initialize_database
from investigation.correlator import investigate_recent_alerts
from investigation.llm_story import generate_story, StoryValidationError
from database.wazuh_store import (
    ingest_wazuh_alerts,
    initialize_wazuh_store,
    get_wazuh_alert_history,
    get_wazuh_alert_status_counts,
    get_wazuh_alert_statuses,
    set_wazuh_alert_status,
)

initialize_database()
initialize_wazuh_store()

load_dotenv()

app = FastAPI(title="AegisTrace", version="0.1.0")

WAZUH_URL = os.getenv(
    "WAZUH_INDEXER_URL", "https://10.0.2.2:9200"
).rstrip("/")
WAZUH_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")
VERIFY_TLS = os.getenv("WAZUH_VERIFY_TLS", "false").lower() == "true"

if not VERIFY_TLS:
    # Local lab only: the Indexer currently uses a self-signed certificate.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def query_wazuh(limit=100):
    if not WAZUH_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail="Wazuh credentials are not configured in the local .env file.",
        )

    try:
        response = requests.post(
            f"{WAZUH_URL}/wazuh-alerts-*/_search",
            auth=(WAZUH_USER, WAZUH_PASSWORD),
            json={
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"match_all": {}},
            },
            verify=VERIFY_TLS,
            timeout=12,
        )

        if response.status_code in (401, 403):
            raise HTTPException(
                status_code=502,
                detail="Wazuh rejected the configured credentials or permissions.",
            )

        response.raise_for_status()
        return response.json()

    except HTTPException:
        raise
    except requests.RequestException as exc:
        # Do not return credentials or request headers to the browser.
        print(f"Wazuh query failed: {type(exc).__name__}")
        raise HTTPException(
            status_code=502,
            detail="Could not retrieve alerts from Wazuh. Check the Indexer connection.",
        ) from exc


def normalize_alert(hit):
    source = hit.get("_source", {})
    rule = source.get("rule") or {}
    agent = source.get("agent") or {}
    data = source.get("data") or {}

    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0

    if level >= 12:
        severity = "critical"
    elif level >= 8:
        severity = "high"
    elif level >= 5:
        severity = "medium"
    else:
        severity = "low"

    source_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or data.get("source_ip")
        or source.get("srcip")
    )

    mitre = rule.get("mitre") or {}
    techniques = mitre.get("id", [])
    if isinstance(techniques, str):
        techniques = [techniques]

    return {
        "id": hit.get("_id", ""),
        "timestamp": source.get("@timestamp", ""),
        "agent": agent.get("name", "Unknown"),
        "agent_id": agent.get("id", ""),
        "rule_id": str(rule.get("id", "Unknown")),
        "rule_level": level,
        "severity": severity,
        "description": rule.get("description", "No description"),
        "source_ip": source_ip or "Not recorded",
        "mitre": techniques,
        "rule_groups": rule.get("groups", []),
        "location": source.get("location", ""),
        "evidence": source.get("full_log", ""),
        "manager": (source.get("manager") or {}).get("name", ""),
        "data_source": "Wazuh",
        "raw_event": source,
    }


@app.get("/api/threat-intel/ip/{ip}")
def threat_intel_ip(ip: str):
    import ipaddress

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {"status": "rejected", "available": False,
                "message": "Invalid IP address."}

    if not address.is_global:
        return {"status": "rejected", "available": False,
                "message": "Only public IP addresses are eligible for lookup."}

    queued = enqueue("ip", str(address), "low")
    return get_result("ip", str(address))


@app.get("/api/threat-intel/hash/{sha256}")
def threat_intel_hash(sha256: str):
    value = sha256.strip().lower()
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        return {
            "status": "rejected",
            "available": False,
            "message": "Invalid SHA-256 hash. Expected 64 hexadecimal characters.",
        }
    enqueue("file", value, "file")
    return get_result("file", value)


@app.get("/api/threat-intel/status/{kind}/{indicator}")
def threat_intel_status(kind: str, indicator: str):
    if kind not in {"ip", "file"}:
        return {"status": "rejected", "available": False,
                "message": "Unsupported indicator type."}
    return get_result(kind, indicator)


@app.post("/api/files/scan")
def scan_monitored_files():
    return scan_once()


@app.get("/api/files/recent")
def files_recent(limit: int = Query(default=100, ge=1, le=500)):
    files = process_auto_quarantine(recent_files(limit))
    return {"files": files}


@app.post("/api/files/quarantine")
def manual_quarantine(payload: dict):
    path = str(payload.get("path", ""))
    digest = str(payload.get("sha256", ""))
    reason = str(payload.get("reason", "Manual analyst action"))[:500]
    # The verdict is read from the stored observation/queue, not trusted from the browser.
    matches = [item for item in recent_files(500) if item.get("path") == path and item.get("sha256") == digest]
    if not matches:
        raise HTTPException(status_code=404, detail="File/hash pair is not present in recent observations.")
    report = matches[0].get("virustotal") or {}
    if not report.get("available") or report.get("status") not in {"malicious", "suspicious"}:
        raise HTTPException(status_code=409, detail="Manual quarantine is offered only for available malicious or suspicious VirusTotal reports.")
    try:
        return quarantine_file(path, digest, report, actor="analyst", reason=reason)
    except (ValueError, OSError, RuntimeError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/files/quarantine/audit")
def quarantine_audit(limit: int = Query(default=100, ge=1, le=500)):
    return {"records": audit_recent(limit)}


@app.get("/api/files/history")
def files_history(limit: int = Query(default=200, ge=1, le=500)):
    return {"events": file_history(limit)}


@app.get("/file-history", response_class=HTMLResponse)
def file_history_page():
    return HTMLResponse(r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AegisTrace | File History</title><style>body{font-family:system-ui,sans-serif;margin:24px;background:#0b1220;color:#e5e7eb}a{color:#7dd3fc}h1{margin-bottom:4px}.muted{color:#9ca3af}table{border-collapse:collapse;width:100%;margin-top:18px}th,td{padding:10px;border-bottom:1px solid #334155;text-align:left;vertical-align:top}code{overflow-wrap:anywhere}.danger{color:#f87171;font-weight:bold}.warn{color:#fbbf24;font-weight:bold}.good{color:#86efac;font-weight:bold}</style></head><body><p><a href="/">← Back to dashboard</a></p><h1>File History</h1><p id="status" class="muted">Loading…</p><table><thead><tr><th>Observed</th><th>File</th><th>Verdict</th><th>Detections</th><th>SHA-256</th></tr></thead><tbody id="rows"></tbody></table><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function vlabel(v){if(v==='malicious')return '<b class="danger">MALICIOUS</b>';if(v==='suspicious')return '<b class="warn">SUSPICIOUS</b>';if(v==='no_detections')return '<b class="good">No detections</b>';return esc(v||'no_report');}
async function load(){try{let r=await fetch('/api/files/history?limit=300',{cache:'no-store'}),d=await r.json();if(!r.ok)throw Error(d.detail||'History unavailable');let a=d.events||[];document.getElementById('status').textContent=a.length+' file event(s)';document.getElementById('rows').innerHTML=a.map(e=>{let v=e.virustotal||{},u=typeof v.permalink==='string'&&v.permalink.startsWith('https://www.virustotal.com/gui/')?'<a href="'+esc(v.permalink)+'" target="_blank" rel="noopener noreferrer">Report</a>':'';return '<tr><td>'+esc(new Date((e.completed_at||e.observed_at)*1000).toLocaleString())+'</td><td>'+esc(e.path)+'<div class="muted">'+esc(e.size)+' bytes '+u+'</div></td><td>'+vlabel(v.status)+'<div class="muted">'+esc(v.message||'')+'</div></td><td>Malicious '+esc(v.malicious||0)+' · Suspicious '+esc(v.suspicious||0)+'</td><td><code>'+esc(e.sha256)+'</code></td></tr>'}).join('')||'<tr><td colspan="5" class="empty" style="text-align:center;padding:28px;color:#9ca3af">No file activity recorded yet.</td></tr>';}catch(e){document.getElementById('status').textContent='History error: '+e.message;}}load();setInterval(load,15000);
</script></body></html>""")

@app.on_event("startup")
def start_aegistrace_services():
    start_scheduler()
    start_file_monitor()


@app.on_event("shutdown")
def stop_aegistrace_services():
    stop_scheduler()
    stop_file_monitor()




@app.post("/api/investigation/story")
def investigation_story(payload: dict):
    """Generate a validated AI story for a current candidate chain."""
    from investigation.llm_story import generate_story, StoryValidationError

    index = payload.get("candidate_index", 0)
    limit = payload.get("limit", 500)

    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise HTTPException(
            status_code=422,
            detail="candidate_index must be a non-negative integer.",
        )

    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise HTTPException(
            status_code=422,
            detail="limit must be an integer between 1 and 500.",
        )

    try:
        result = investigate_recent_alerts(limit=limit)
        candidates = result.get("candidates", [])

        if index >= len(candidates):
            raise HTTPException(
                status_code=404,
                detail="Candidate chain not found. Refresh the investigation list.",
            )

        story = generate_story(candidates[index])
        return {
            "candidate_index": index,
            "candidate_count": len(candidates),
            "story": story,
        }

    except HTTPException:
        raise
    except StoryValidationError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"AI story failed reference validation: {exc}",
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        import traceback
        print("\\n[AEGISTRACE STORY GENERATION TRACEBACK]")
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"AI investigation failed ({type(exc).__name__}).",
        ) from exc


@app.get("/api/investigation/recent")
def investigation_recent(limit: int = Query(default=500, ge=1, le=500)):
    """Run evidence-based correlation on existing stored Wazuh alerts."""
    try:
        return investigate_recent_alerts(limit=limit)
    except Exception as exc:
        # Avoid exposing database paths or internal exception details.
        raise HTTPException(
            status_code=500,
            detail=f"Investigation failed ({type(exc).__name__}).",
        ) from exc


@app.get("/health")
def health():
    return {"status": "ok", "service": "AegisTrace"}


@app.get("/api/wazuh/alerts")
def wazuh_alerts():
    result = query_wazuh(limit=100)
    hits = result.get("hits", {}).get("hits", [])
    alerts = [normalize_alert(hit) for hit in hits]

    # Keep one queue entry per public IP, using its highest observed severity.
    import ipaddress
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ip_priorities = {}

    for alert in alerts:
        raw_ip = str(alert.get("source_ip") or "").strip()
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue

        if not address.is_global:
            continue

        ip = str(address)
        severity = str(alert.get("severity") or "low").lower()
        if severity not in severity_rank:
            severity = "low"

        previous = ip_priorities.get(ip)
        if previous is None or severity_rank[severity] < severity_rank[previous]:
            ip_priorities[ip] = severity

    for ip, severity in ip_priorities.items():
        enqueue("ip", ip, severity)

    ingestion = ingest_wazuh_alerts(alerts)

    saved_statuses = get_wazuh_alert_statuses(
        alert["id"] for alert in alerts
    )

    for alert in alerts:
        saved = saved_statuses.get(alert["id"], {})
        alert["status"] = saved.get("status", "open")
        alert["closed_at"] = saved.get("closed_at")

    return {
        "source": "Wazuh Indexer",
        "count": len(alerts),
        "status_counts": get_wazuh_alert_status_counts(),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "history_ingestion": ingestion,
        "alerts": alerts,
    }


@app.post("/api/wazuh/alerts/{wazuh_id}/status")
def update_wazuh_alert_status(wazuh_id: str, status: str):
    if status not in {"open", "closed"}:
        raise HTTPException(
            status_code=400,
            detail="Status must be open or closed.",
        )

    updated = set_wazuh_alert_status(wazuh_id, status)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Alert not found in stored history. Refresh alerts first.",
        )

    return {"id": wazuh_id, "status": status}


@app.get("/api/wazuh/history")
def wazuh_history(
    limit: int = 100,
    offset: int = 0,
    severity: str = None,
    search: str = None,
    period: str = "10d",
    status: str = "all",
):
    if period not in {"24h", "3d", "10d", "all"}:
        raise HTTPException(
            status_code=400,
            detail="Invalid period. Use 24h, 3d, 10d, or all.",
        )

    if status not in {"open", "closed", "all"}:
        raise HTTPException(
            status_code=400,
            detail="Invalid status. Use open, closed, or all.",
        )

    return get_wazuh_alert_history(
        limit=limit,
        offset=offset,
        severity=severity,
        search=search,
        period=period,
        status=status,
    )


@app.get("/history", response_class=HTMLResponse)
def history_page():
    return HTMLResponse(HISTORY_HTML)


@app.get("/investigation", response_class=HTMLResponse)
def investigation_page():
    return HTMLResponse(INVESTIGATION_HTML)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD_HTML)


HISTORY_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisTrace | History of Logs</title>
<style>
:root{color-scheme:dark;--bg:#0a0e17;--panel:#111827;--line:#263247;--muted:#98a7bd;--text:#edf3ff;--cyan:#63d9ed}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}
header{padding:22px 5%;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
main{max-width:1500px;margin:auto;padding:26px 5% 50px}
.brand{font-size:23px;font-weight:750}.brand span{color:var(--cyan)}
.muted{color:var(--muted)}
button,input,select{background:#17283b;border:1px solid #35506b;color:var(--text);padding:9px 12px;border-radius:7px}
button,a{cursor:pointer}a{color:var(--cyan)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:18px}
.filters{display:flex;gap:9px;flex-wrap:wrap;padding:14px;border-bottom:1px solid var(--line)}
#search{flex:1;min-width:200px}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:900px}
th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:11px;text-transform:uppercase}
td{font-size:12px}
.sev{font-weight:700;text-transform:uppercase}
.low{color:#9be7ce}.medium{color:#ffd58a}.high,.critical{color:#ffabb5}
tr.logrow{cursor:pointer}tr.logrow:hover{background:#172033}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:350px;overflow:auto;background:#0a0e17;padding:13px;border-radius:8px}
.detail{padding:16px}
.pager{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:14px}
</style>
</head>
<body>
<header>
  <div><div class="brand">AEGIS<span>TRACE</span></div><div class="muted">Historical security event explorer</div></div>
  <a href="/">← Back to Dashboard</a>
</header>
<main>
  <h1>History of Logs</h1>
  <p class="muted">Search and investigate alerts saved in the AegisTrace database. Select a row to inspect its original evidence.</p>
  <div class="panel">
    <div class="filters">
      <input id="search" type="search" placeholder="Search description, IP, agent, rule or evidence…">

      <select id="severity">
        <option value="">All severities</option>
        <option>critical</option>
        <option>high</option>
        <option>medium</option>
        <option>low</option>
      </select>

      <select id="period">
        <option value="24h">Last 24 hours</option>
        <option value="3d">Last 3 days</option>
        <option value="10d" selected>Last 10 days</option>
        <option value="all">All stored alerts</option>
      </select>

      <select id="alertStatus">
        <option value="all" selected>All statuses</option>
        <option value="open">Open alerts</option>
        <option value="closed">Closed alerts</option>
      </select>

      <button id="apply">Search</button>
    </div>
    <div class="filters muted" id="status">Loading history…</div>
    <div class="tablewrap">
      <table>
        <thead>
          <tr><th>Time</th><th>Severity</th><th>Rule</th><th>Description</th><th>Source IP</th><th>Agent</th></tr>
        </thead>
        <tbody id="rows"><tr><td colspan="6">Loading…</td></tr></tbody>
      </table>
    </div>
    <div class="pager">
      <button id="prev">← Previous</button>
      <span id="page">Page 1</span>
      <button id="next">Next →</button>
    </div>
  </div>
  <div class="panel detail" id="detail" hidden>
    <h2>Alert evidence</h2>
    <div id="summary"></div>
    <button id="toggleAlertStatus" type="button">Close alert</button>
    <span id="statusMessage" class="muted"></span>
    <h3>Evidence</h3><pre id="evidence"></pre>
    <h3>Original event JSON</h3><pre id="raw"></pre>
  </div>
</main>
<script>
const el=id=>document.getElementById(id);
const pageSize=25;
let offset=0,total=0,current=[];

function safe(v){
  const s=document.createElement("span");
  s.textContent=String(v??"");
  return s.innerHTML;
}

function date(v){
  try{return new Date(v).toLocaleString()}
  catch{return v||""}
}

async function load(){
  el("status").textContent="Loading history…";

  const q=new URLSearchParams({
    limit:String(pageSize),
    offset:String(offset),
    period:el("period").value,
    status:el("alertStatus").value
  });

  if(el("search").value.trim())q.set("search",el("search").value.trim());
  if(el("severity").value)q.set("severity",el("severity").value);

  try{
    const r=await fetch("/api/wazuh/history?"+q.toString(),{cache:"no-store"});
    const d=await r.json();

    if(!r.ok)throw new Error(d.detail||"Could not load history");

    total=d.total||0;
    current=d.alerts||[];

    el("status").textContent=total+" matching stored alerts";
    el("page").textContent=total
      ?("Showing "+(offset+1)+"–"+(offset+current.length)+" of "+total)
      :"No results";

    el("rows").innerHTML=current.length?current.map((a,i)=>`
      <tr class="logrow" tabindex="0" data-index="${i}">
        <td>${safe(date(a.timestamp))}</td>
        <td><span class="sev ${safe(a.severity)}">${safe(a.severity)}</span></td>
        <td>${safe(a.rule_id)} <div class="muted">Level ${safe(a.rule_level)}</div></td>
        <td>${safe(a.description)}</td>
        <td>${safe(a.source_ip||"Not recorded")}</td>
        <td>${safe(a.agent)} (${safe(a.agent_id)})</td>
      </tr>`).join("")
      :'<tr><td colspan="6">No matching alerts found.</td></tr>';

    el("prev").disabled=offset===0;
    el("next").disabled=offset+current.length>=total;
  }catch(e){
    el("status").textContent="Error: "+e.message;
  }
}

function show(a){
  let raw={};
  try{raw=JSON.parse(a.raw_json||"{}")}catch{}

  el("detail").hidden=false;
  el("summary").textContent=
    `${a.severity.toUpperCase()} · Rule ${a.rule_id} · ${a.description} · ${date(a.timestamp)} · Agent ${a.agent} · Status: ${a.status}`;

  el("toggleAlertStatus").dataset.id = a.wazuh_id;
  el("toggleAlertStatus").dataset.status = a.status;
  el("toggleAlertStatus").textContent =
    a.status === "closed" ? "Reopen alert" : "Close alert";
  el("statusMessage").textContent = "";
  el("evidence").textContent=a.evidence||"No full-log evidence recorded.";
  el("raw").textContent=JSON.stringify(raw,null,2);
  el("detail").scrollIntoView({behavior:"smooth",block:"start"});
}

el("rows").addEventListener("click",e=>{
  const tr=e.target.closest("tr[data-index]");
  if(tr)show(current[Number(tr.dataset.index)]);
});

el("rows").addEventListener("keydown",e=>{
  if(e.key==="Enter"){
    const tr=e.target.closest("tr[data-index]");
    if(tr)show(current[Number(tr.dataset.index)]);
  }
});

el("toggleAlertStatus").addEventListener("click", async () => {
  const button = el("toggleAlertStatus");
  const id = button.dataset.id;
  const nextStatus = button.dataset.status === "closed" ? "open" : "closed";

  if (!id) {
    el("statusMessage").textContent = "Select an alert first.";
    return;
  }

  button.disabled = true;
  el("statusMessage").textContent = "Saving status…";

  try {
    const response = await fetch(
      `/api/wazuh/alerts/${encodeURIComponent(id)}/status?status=${nextStatus}`,
      { method: "POST" }
    );
    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.detail || "Could not update alert status.");
    }

    offset = 0;
    await load();
    el("statusMessage").textContent = `Alert status changed to ${result.status}.`;

    const updated = current.find(a => a.wazuh_id === id);
    if (updated) show(updated);
  } catch (error) {
    el("statusMessage").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

el("apply").addEventListener("click",()=>{
  offset=0;
  load();
});

el("search").addEventListener("keydown",e=>{
  if(e.key==="Enter"){
    offset=0;
    load();
  }
});

el("severity").addEventListener("change",()=>{
  offset=0;
  load();
});

el("period").addEventListener("change",()=>{
  offset=0;
  load();
});

el("alertStatus").addEventListener("change",()=>{
  offset=0;
  load();
});

el("prev").addEventListener("click",()=>{
  offset=Math.max(0,offset-pageSize);
  load();
});

el("next").addEventListener("click",()=>{
  offset+=pageSize;
  load();
});

load();
</script>
</body>
</html>"""



INVESTIGATION_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Security Investigation | AegisTrace</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--surface:#111a2e;--surface2:#162139;--line:#283650;--text:#e8eef8;--muted:#91a1ba;--accent:#60a5fa;--green:#4ade80;--amber:#fbbf24;--red:#fb7185}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(ellipse at top left,#142344 0,transparent 42%),var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
header{height:76px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 clamp(18px,4vw,56px);gap:16px;background:#0b1020eF}
.brand{font-size:18px;font-weight:800;letter-spacing:2px}.brand span{color:var(--accent)}
.brand-sub{font-size:11px;color:var(--muted);letter-spacing:.4px}
.header-right{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.pill{border:1px solid var(--line);border-radius:999px;padding:5px 10px;color:var(--muted);font-size:11px}
main{max-width:1440px;margin:auto;padding:30px clamp(16px,4vw,56px) 60px}
.eyebrow{color:var(--accent);font-size:11px;font-weight:800;letter-spacing:1.8px;text-transform:uppercase}
h1{font-size:clamp(27px,4vw,38px);line-height:1.15;margin:9px 0 12px;letter-spacing:-.8px}
.intro{color:var(--muted);max-width:780px;margin:0}
.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;margin-bottom:26px;flex-wrap:wrap}
button{border:1px solid #4386db;background:#2563eb;color:white;border-radius:9px;padding:11px 16px;font-weight:700;font-size:13px;cursor:pointer}
button:hover{background:#3478f6}button:disabled{opacity:.55;cursor:wait}
.secondary{background:var(--surface);border-color:var(--line);color:var(--text)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap}
.notice{border:1px solid var(--line);border-radius:10px;background:#10182a;padding:13px 15px;color:var(--muted);margin-bottom:20px}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:22px}
.stat,.panel,.candidate{background:linear-gradient(145deg,#131e34,#101829);border:1px solid var(--line);border-radius:13px}
.stat{padding:16px}.stat-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}.stat-value{font-size:25px;font-weight:750;margin-top:7px;overflow-wrap:anywhere}
.section-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:25px 0 12px;flex-wrap:wrap}
h2{font-size:16px;margin:0}h3{font-size:15px;margin:0}
.muted{color:var(--muted)}.small{font-size:12px;color:var(--muted)}
.results{display:grid;gap:14px}
.empty{padding:32px 20px;text-align:center;color:var(--muted);border:1px dashed #35435d;border-radius:12px}
.candidate{padding:19px}
.candidate-top{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;flex-wrap:wrap}
.candidate-title{font-size:16px;font-weight:750;margin:7px 0}
.tags{display:flex;gap:7px;flex-wrap:wrap;margin:9px 0}
.tag{display:inline-flex;border:1px solid var(--line);border-radius:6px;padding:3px 7px;font-size:11px;color:#c8d4e7}
.tag.warn{color:var(--amber);border-color:#66552c}.tag.ok{color:var(--green);border-color:#285b48}
.candidate-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:17px}
.subpanel{border:1px solid #26334a;background:#0c1425;border-radius:9px;padding:13px;min-width:0}
.subpanel h3{margin-bottom:9px;font-size:12px;color:#c5d5ec}
.evidence{border-left:2px solid #334967;padding:0 0 13px 12px;margin-left:4px;overflow-wrap:anywhere}
.evidence:last-child{padding-bottom:0}.evidence-time{font-size:11px;color:var(--accent)}.evidence-title{font-weight:650;margin:3px 0}
ul.techniques{padding-left:18px;margin:5px 0}.techniques li{margin:5px 0}
.story-controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:16px}
.story-output{margin-top:14px;display:grid;gap:12px}
.story-output pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 ui-monospace,monospace;color:#d6e2f2;margin:0}
.story-output h3{margin-bottom:8px}
.footer-note{margin-top:26px;color:var(--muted);font-size:12px}
@media(max-width:800px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.candidate-grid{grid-template-columns:1fr}.hero{align-items:flex-start}}
@media(max-width:480px){header{padding:12px 16px;height:auto}.header-right{gap:8px}main{padding-top:22px}.stats{gap:8px}.stat{padding:12px}.stat-value{font-size:21px}}
</style>
</head>
<body>
<header>
  <div>
    <div class="brand">AEGIS<span>TRACE</span></div>
    <div class="brand-sub">SECURITY OPERATIONS · INVESTIGATION WORKSPACE</div>
  </div>
  <div class="header-right">
    <span class="pill">LOCAL ANALYSIS</span>
    <a href="/">← Back to dashboard</a>
  </div>
</header>
<main>
  <section class="hero">
    <div>
      <div class="eyebrow">AI-assisted investigation</div>
      <h1>Security Investigation</h1>
      <p class="intro">Correlate stored Wazuh alerts into evidence-linked activity sequences. Review the timeline, source records, and ATT&amp;CK metadata before drawing conclusions.</p>
    </div>
    <div class="toolbar">
      <button class="secondary" id="clearResults" type="button">Clear view</button>
      <button id="runInvestigation" type="button">▶ Run investigation</button>
    </div>
  </section>

  <div class="notice" id="status" role="status" aria-live="polite">
    Ready. Run an investigation to analyze the existing stored Wazuh alerts. No response actions will be executed.
  </div>

  <section class="stats" aria-label="Investigation summary">
    <div class="stat"><div class="stat-label">Stored alerts examined</div><div class="stat-value" id="examined">—</div></div>
    <div class="stat"><div class="stat-label">Unique source events</div><div class="stat-value" id="unique">—</div></div>
    <div class="stat"><div class="stat-label">Duplicate documents skipped</div><div class="stat-value" id="duplicates">—</div></div>
    <div class="stat"><div class="stat-label">Candidate sequences</div><div class="stat-value" id="count">—</div></div>
  </section>

  <div class="section-head">
    <div><h2>Correlated activity</h2><div class="small">Evidence-linked candidate sequences · newest investigation result</div></div>
    <span class="pill" id="freshness">Not run</span>
  </div>
  <section class="results" id="results">
    <div class="empty">No investigation results yet.<br>Choose <strong>Run investigation</strong> to begin.</div>
  </section>
  <p class="footer-note">Analyst guidance: correlation is not confirmation. A shared process, account, or source address may have a legitimate explanation. Verify the original events and environment context before classifying activity as malicious. Correlation support scores are heuristic and are not attack probabilities.</p>
</main>
<script>
const $ = id => document.getElementById(id);
const runButton = $("runInvestigation");

function node(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}
function addTag(parent, text, cls) {
  parent.appendChild(node("span", "tag" + (cls ? " " + cls : ""), text));
}

function reportCard(parent, title, subtitle) {
  const card = node("section", "subpanel");
  card.style.margin = "14px 0";
  card.style.padding = "18px";
  card.style.borderRadius = "12px";
  card.style.background = "var(--panel, rgba(127,127,127,.06))";
  card.style.border = "1px solid var(--border, rgba(127,127,127,.2))";

  const heading = node("h3", "", title);
  heading.style.margin = "0 0 12px";
  card.appendChild(heading);

  if (subtitle) {
    const note = node("p", "small", subtitle);
    note.style.margin = "0 0 12px";
    card.appendChild(note);
  }

  parent.appendChild(card);
  return card;
}

function reportText(parent, label, value) {
  if (value === undefined || value === null || value === "") return;
  const wrap = node("div");
  wrap.style.margin = "10px 0";

  if (label) {
    const heading = node("div", "small", label);
    heading.style.fontWeight = "700";
    heading.style.marginBottom = "4px";
    wrap.appendChild(heading);
  }

  const text = node("p", "", value);
  text.style.margin = "0";
  text.style.lineHeight = "1.6";
  wrap.appendChild(text);
  parent.appendChild(wrap);
}

function reportTag(parent, value, tone) {
  if (!value) return;
  const tag = node("span", "tag", value);
  tag.style.display = "inline-block";
  tag.style.margin = "0 6px 6px 0";
  if (tone === "success") tag.style.borderColor = "#27865c";
  if (tone === "warning") tag.style.borderColor = "#b7791f";
  parent.appendChild(tag);
}

function readableValue(value) {
  if (typeof value === "string" || typeof value === "number") return String(value);
  return "";
}

function renderEvidenceAssessment(panel, findings) {
  const section = reportCard(
    panel,
    "Evidence assessment",
    "What the collected events indicate. Observations are separated from conclusions."
  );

  if (!Array.isArray(findings) || !findings.length) {
    reportText(section, "", "No structured evidence findings were returned for this investigation.");
    return;
  }

  findings.forEach(item => {
    if (!item || typeof item !== "object") return;
    const card = node("div", "evidence");
    card.style.padding = "12px 0";
    card.style.borderBottom = "1px solid var(--border, rgba(127,127,127,.18))";

    const title = item.title || item.finding_id || "Evidence finding";
    const heading = node("div", "evidence-title", title);
    card.appendChild(heading);

    if (item.status) reportTag(card, String(item.status), "success");
    if (item.claim_type) reportTag(card, String(item.claim_type));

    reportText(card, "Observation", item.observation);
    reportText(card, "What this does not establish", item.limitations);
    section.appendChild(card);
  });
}

function renderTimeline(panel, timeline) {
  const section = reportCard(
    panel,
    "Investigation timeline",
    "Events are grouped from the supplied evidence. A correlation is not proof of causation."
  );

  if (!Array.isArray(timeline) || !timeline.length) {
    reportText(section, "", "No timeline entries are available.");
    return;
  }

  timeline.forEach((item, index) => {
    if (!item || typeof item !== "object") return;
    const entry = node("div", "evidence");
    entry.style.padding = "12px 0";
    entry.style.borderBottom = "1px solid var(--border, rgba(127,127,127,.18))";

    const row = node("div");
    row.style.display = "flex";
    row.style.flexWrap = "wrap";
    row.style.gap = "8px";
    row.style.alignItems = "center";

    const number = node("span", "tag", "Event group " + (index + 1));
    row.appendChild(number);
    if (item.claim_type) reportTag(row, item.claim_type);
    entry.appendChild(row);

    reportText(entry, "", item.claim || item.description || "Evidence-linked activity");

    const techniques = Array.isArray(item.technique_ids) ? item.technique_ids : [];
    if (techniques.length) {
      reportText(entry, "Supported ATT&CK techniques", techniques.join(", "));
    }

    section.appendChild(entry);
  });
}

function renderAttackMapping(panel, story) {
  const section = reportCard(
    panel,
    "MITRE ATT&CK mapping",
    "Source-associated techniques and independently supported techniques are shown separately."
  );

  const refs = story.references && typeof story.references === "object"
    ? story.references
    : {};

  const sourceIds = Array.isArray(refs.source_attack_technique_ids)
    ? refs.source_attack_technique_ids
    : [];

  const verifiedIds = Array.isArray(refs.attack_technique_ids)
    ? refs.attack_technique_ids
    : [];

  const sourceHeading = node(
    "h4",
    "",
    "Wazuh source metadata associations"
  );

  sourceHeading.style.margin = "8px 0";
  section.appendChild(sourceHeading);

  const validSourceIds = sourceIds.filter(
    id => typeof id === "string" && /^T\d{4}(?:\.\d{3})?$/.test(id)
  );

  if (validSourceIds.length) {
    const tags = node("div", "tags");

    tags.style.display = "flex";
    tags.style.flexWrap = "wrap";
    tags.style.gap = "8px";

    validSourceIds.forEach(id => reportTag(tags, id));
    section.appendChild(tags);

    reportText(
      section,
      "Provenance",
      refs.source_attack_metadata_provenance ||
      "Wazuh rule metadata. These associations provide context and do not independently prove that a technique occurred."
    );
  } else {
    reportText(
      section,
      "",
      "No ATT&CK technique IDs were supplied by the source alerts."
    );
  }

  const verifiedHeading = node(
    "h4",
    "",
    "Independently supported techniques"
  );

  verifiedHeading.style.margin = "18px 0 8px";
  section.appendChild(verifiedHeading);

  const validVerifiedIds = verifiedIds.filter(
    id => typeof id === "string" && /^T\d{4}(?:\.\d{3})?$/.test(id)
  );

  if (validVerifiedIds.length) {
    const tags = node("div", "tags");

    tags.style.display = "flex";
    tags.style.flexWrap = "wrap";
    tags.style.gap = "8px";

    validVerifiedIds.forEach(
      id => reportTag(tags, id, "success")
    );

    section.appendChild(tags);
  } else {
    reportText(
      section,
      "",
      "No technique is independently supported by the current evidence assessment. Source metadata associations should not be interpreted as confirmed attacker behavior."
    );
  }
}

function renderDefensiveAnalysis(panel, story) {
  const section = reportCard(
    panel,
    "Defensive Analysis & Remediation",
    "D3FEND catalogue references, AI suggestions and AegisTrace analyst guidance are combined here. All actions are advisory and require analyst review."
  );

  const guidance = Array.isArray(story.d3fend_guidance)
    ? story.d3fend_guidance
    : [];

  const actions = Array.isArray(story.remediation)
    ? story.remediation
    : [];

  const fallback = Array.isArray(story.analyst_guidance)
    ? story.analyst_guidance
    : [];

  let rendered = 0;

  if (guidance.length) {
    const heading = node(
      "h4",
      "",
      "D3FEND catalogue references"
    );

    heading.style.margin = "8px 0";
    section.appendChild(heading);

    guidance.forEach(item => {
      if (!item || typeof item !== "object") return;

      const card = node("div", "evidence");

      card.style.padding = "12px 0";
      card.style.borderBottom =
        "1px solid var(--border, rgba(127,127,127,.18))";

      card.appendChild(node(
        "div",
        "evidence-title",
        (item.d3fend_id ? item.d3fend_id + " — " : "") +
        (item.name || "Defensive technique")
      ));

      reportTag(card, "Official catalogue association");

      if (item.priority) {
        reportTag(card, "Priority: " + item.priority);
      }

      reportText(
        card,
        "Official D3FEND definition",
        item.official_definition
      );

      reportText(
        card,
        "AegisTrace implementation guidance",
        item.implementation_suggestion
      );

      reportText(card, "Applicability", item.applicability);

      reportText(
        card,
        "Related ATT&CK source metadata",
        Array.isArray(item.attack_technique_ids)
          ? item.attack_technique_ids.join(", ")
          : item.attack_technique_id
      );

      section.appendChild(card);
      rendered++;
    });
  }

  const combined = [...actions, ...fallback];

  if (combined.length) {
    const heading = node(
      "h4",
      "",
      "Recommended defensive actions"
    );

    heading.style.margin = "18px 0 8px";
    section.appendChild(heading);

    combined.forEach((item, index) => {
      if (!item || typeof item !== "object") return;

      const card = node("div", "evidence");

      card.style.padding = "12px 0";
      card.style.borderBottom =
        "1px solid var(--border, rgba(127,127,127,.18))";

      card.appendChild(node(
        "div",
        "evidence-title",
        (index + 1) + ". " +
        (item.action || item.title || "Review recommended")
      ));

      reportTag(
        card,
        item.source || "AegisTrace analyst guidance"
      );

      if (item.priority) {
        reportTag(
          card,
          "Priority: " + item.priority,
          "warning"
        );
      }

      reportTag(card, "Advisory only");

      reportText(
        card,
        "Why this matters",
        item.rationale || item.reason
      );

      reportText(card, "Applicability", item.applicability);

      section.appendChild(card);
      rendered++;
    });
  }

  if (!rendered) {
    reportText(
      section,
      "",
      "No specific catalogue mapping or remediation action was returned. Review the original events and surrounding host, account and process context before taking action."
    );
  }
}

function renderUncertainties(panel, uncertainties) {
  const section = reportCard(
    panel,
    "Investigation limitations",
    "Important gaps and uncertainties to consider before making a final incident determination."
  );

  if (!Array.isArray(uncertainties) || !uncertainties.length) {
    reportText(section, "", "No additional limitations were supplied.");
    return;
  }

  const list = node("ul", "techniques");
  uncertainties.forEach(item => {
    const value = readableValue(item) ||
      (item && typeof item === "object" ? readableValue(item.description || item.reason || item.note) : "");
    if (value) list.appendChild(node("li", "", value));
  });
  section.appendChild(list);
}

function renderStory(panel, story) {
  panel.replaceChildren();

  const header = reportCard(
    panel,
    "Investigation report",
    "Evidence-led analysis generated by AegisTrace. Review the findings before taking response actions."
  );

  if (story.status) reportTag(header, "Validation: " + story.status, "success");
  if (story.generation_source) reportTag(header, "Source: " + story.generation_source);

  reportText(header, "Executive summary", story.summary);

  renderEvidenceAssessment(panel, story.evidence_assessment);
  renderTimeline(panel, story.timeline);
  renderAttackMapping(panel, story);
  renderDefensiveAnalysis(panel, story);
  renderUncertainties(panel, story.uncertainties);
}
function showCandidate(c, candidateIndex) {
  const card = node("article", "candidate");
  const top = node("div", "candidate-top");
  const titleBox = node("div");
  titleBox.appendChild(node("div", "eyebrow", c.status || "Candidate sequence"));
  titleBox.appendChild(node("div", "candidate-title", c.title || "Correlated activity"));
  titleBox.appendChild(node("div", "small", (c.agent ? "Agent: " + c.agent : "Agent not identified") +
    (c.start ? " · Start: " + c.start : "") + (c.end ? " · End: " + c.end : "")));
  top.appendChild(titleBox);
  const tags = node("div", "tags");
  tags.style.display = "flex";
  tags.style.flexWrap = "wrap";
  tags.style.gap = "8px";
  addTag(tags, (c.alert_count ?? (c.evidence || []).length) + " events");
  if (c.correlation_support_score !== undefined)
    addTag(tags, "Support score: " + c.correlation_support_score + " / 100", "warn");
  top.appendChild(tags);
  card.appendChild(top);

  const summary = node("p", "muted", c.hypothesis || "Review the linked events to determine whether the sequence is expected or suspicious.");
  card.appendChild(summary);
  const grid = node("div", "candidate-grid");

  const evPanel = node("div", "subpanel");
  evPanel.appendChild(node("h3", "", "EVIDENCE TIMELINE"));
  const evidence = Array.isArray(c.evidence) ? c.evidence : [];
  if (!evidence.length) evPanel.appendChild(node("div", "small", "No evidence items returned."));
  evidence.forEach(e => {
    const item = node("div", "evidence");
    item.appendChild(node("div", "evidence-time", e.timestamp || "Timestamp unavailable"));
    item.appendChild(node("div", "evidence-title", e.description || ("Wazuh rule " + (e.rule_id || "unknown"))));
    const details = [
      e.rule_id ? "Rule: " + e.rule_id : "",
      e.severity !== undefined ? "Level: " + e.severity : "",
      e.source_ip ? "Source IP: " + e.source_ip : "",
      e.username ? "User: " + e.username : "",
      e.process_id ? "Process: " + e.process_id : ""
    ].filter(Boolean);
    item.appendChild(node("div", "small", details.join(" · ") || "Limited metadata available"));
    evPanel.appendChild(item);
  });
  grid.appendChild(evPanel);

  const context = node("div", "subpanel");
  context.appendChild(node("h3", "", "CORRELATION & TECHNIQUE CONTEXT"));
  const reasons = Array.isArray(c.link_reasons) ? c.link_reasons : [];
  context.appendChild(node("div", "small", "Link reasons"));
  if (reasons.length) {
    const list = node("ul", "techniques");
    reasons.forEach(r => list.appendChild(node("li", "", typeof r === "string" ? r : JSON.stringify(r))));
    context.appendChild(list);
  } else {
    context.appendChild(node("p", "small", "No explicit link reasons returned."));
  }
  context.appendChild(node("div", "small", "ATT&CK technique IDs from source metadata"));
  const techniques = [...new Set([
    ...(Array.isArray(c.technique_ids) ? c.technique_ids : []),
    ...evidence.flatMap(e => Array.isArray(e.technique_ids) ? e.technique_ids : [])
  ])];
  if (techniques.length) {
    const list = node("ul", "techniques");
    techniques.forEach(t => list.appendChild(node("li", "", t)));
    context.appendChild(list);
  } else {
    context.appendChild(node("p", "small", "No ATT&CK technique ID was supplied by the source alerts."));
  }
  context.appendChild(node("div", "tags"));
  addTag(context.lastChild, "Not confirmed malicious", "warn");
  grid.appendChild(context);
  card.appendChild(grid);

  const storyControls = node("div", "story-controls");
  const storyButton = node("button", "", "Generate AI investigation");
  const storyPanel = node("div", "story-output");
  storyPanel.hidden = true;

  storyButton.addEventListener("click", async () => {
    storyButton.disabled = true;
    storyButton.textContent = "Generating story…";
    storyPanel.hidden = false;
    storyPanel.replaceChildren(node("p", "small", "Requesting a validated story from the investigation API…"));

    try {
      const response = await fetch("/api/investigation/story", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({candidate_index: candidateIndex, limit: 500})
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || ("HTTP " + response.status));
      }
      if (!data.story) throw new Error("The API returned no story.");
      renderStory(storyPanel, data.story);
      if (data.candidate_count !== undefined && data.candidate_count <= candidateIndex) {
        storyPanel.prepend(node("p", "small", "Warning: the candidate list changed while this story was generated. Verify its evidence references."));
      }
    } catch (err) {
      storyPanel.replaceChildren(node("p", "small", "Story generation failed: " + err.message));
    } finally {
      storyButton.disabled = false;
      storyButton.textContent = "Generate AI investigation";
    }
  });

  storyControls.appendChild(storyButton);
  card.appendChild(storyControls);
  card.appendChild(storyPanel);

  return card;
}
function render(data) {
  $("examined").textContent = data.alerts_examined ?? "—";
  $("unique").textContent = data.unique_events_examined ?? "—";
  $("duplicates").textContent = data.duplicate_documents_skipped ?? "—";
  $("count").textContent = data.candidate_count ?? (data.candidates || []).length;
  $("freshness").textContent = "Fetched " + new Date().toLocaleTimeString();
  const results = $("results");
  results.replaceChildren();
  const candidates = Array.isArray(data.candidates) ? data.candidates : [];
  if (!candidates.length) {
    results.appendChild(node("div", "empty", "No candidate sequences were returned. This does not prove the environment is threat-free."));
    return;
  }
  candidates.forEach((c, index) => results.appendChild(showCandidate(c, index)));
}
runButton.addEventListener("click", async () => {
  runButton.disabled = true;
  $("status").textContent = "Investigating stored Wazuh alerts…";
  try {
    const response = await fetch("/api/investigation/recent?limit=500", {cache:"no-store"});
    if (!response.ok) throw new Error("Investigation API returned HTTP " + response.status);
    const data = await response.json();
    render(data);
    $("status").textContent = "Investigation completed. Review each candidate against the original evidence before reaching a conclusion.";
  } catch (err) {
    $("status").textContent = "Investigation could not be completed: " + err.message + ". Check that AegisTrace and its stored alert data are available.";
  } finally {
    runButton.disabled = false;
  }
});
$("clearResults").addEventListener("click", () => {
  ["examined","unique","duplicates","count"].forEach(id => $(id).textContent = "—");
  $("freshness").textContent = "Cleared";
  $("results").replaceChildren(node("div", "empty", "Results cleared from this view. Stored alerts and investigation records were not deleted."));
  $("status").textContent = "View cleared. Stored data has not been changed.";
});
</script>
</body>
</html>"""


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisTrace | Security Operations</title>
<style>
:root{color-scheme:dark;--bg:#0a0e17;--panel:#111827;--line:#263247;
--muted:#98a7bd;--text:#edf3ff;--cyan:#63d9ed}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{padding:24px 5%;border-bottom:1px solid var(--line);
display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.brand{font-size:23px;font-weight:750;letter-spacing:.4px}
.brand span{color:var(--cyan)}
.tagline{color:var(--muted);font-size:12px}
main{max-width:1500px;margin:auto;padding:26px 5% 50px}
.topline{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
h1{font-size:24px;margin:0 0 5px}
.sub{color:var(--muted)}
.status{border:1px solid var(--line);border-radius:999px;padding:7px 12px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;
background:#f4b860;margin-right:8px}
.metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));
gap:13px;margin:24px 0}
.metric,.panel{background:var(--panel);border:1px solid var(--line);
border-radius:13px}
.metric{padding:17px}
.metric .label{color:var(--muted);font-size:12px}
.metric .value{font-size:28px;font-weight:750;margin-top:6px}
.panel{overflow:hidden}
.panelhead{padding:17px 19px;border-bottom:1px solid var(--line);
display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.panelhead strong{font-size:15px}
.small{color:var(--muted);font-size:12px}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:850px}
th,td{text-align:left;padding:13px 15px;border-bottom:1px solid var(--line);
vertical-align:top}
th{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px}
td{font-size:12px}
tbody tr:hover{background:#172033}
.sev{display:inline-block;border-radius:5px;padding:3px 7px;
font-weight:750;text-transform:uppercase;font-size:10px}
.critical,.high{background:#54242d;color:#ffabb5}
.medium{background:#49371b;color:#ffd58a}
.low{background:#173b35;color:#9be7ce}
button{background:#17283b;border:1px solid #35506b;color:var(--text);
padding:8px 12px;border-radius:7px;cursor:pointer}
button:hover{border-color:var(--cyan)}
.error{color:#ffabb5;padding:14px 19px;display:none}
.empty{padding:28px;text-align:center;color:var(--muted)}
footer{padding:20px 5%;color:var(--muted);font-size:12px}
code{color:#9ddfee}

.charts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:18px 0}
.chartbox{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:17px;min-width:0}
.chartbox h3{font-size:14px;margin:0 0 12px}
.chartarea{height:220px;position:relative}
.filters{display:flex;gap:9px;flex-wrap:wrap;align-items:center;padding:14px 18px;border-bottom:1px solid var(--line)}
.filters input,.filters select{background:#0a0e17;color:var(--text);border:1px solid #35506b;border-radius:7px;padding:9px;max-width:100%}
.filters input{flex:1;min-width:180px}
.clickrow{cursor:pointer}
.clickrow:focus{outline:2px solid var(--cyan);outline-offset:-2px}
.clickrow.selected{background:#1a2c40}
.detail{margin-top:16px;padding:20px}

.investigation{margin:18px 0;background:var(--panel);border:1px solid var(--line);border-radius:13px;overflow:hidden}
.invbody{padding:16px 19px}
.invgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.invcard{background:#0a0e17;border:1px solid var(--line);border-radius:9px;padding:13px;overflow-wrap:anywhere}
.invcard h3{font-size:14px;margin:0 0 8px}
.invmeta{color:var(--muted);font-size:12px;margin-bottom:8px}
.invlist{margin:8px 0 0;padding-left:20px}
.invlist li{margin:6px 0;overflow-wrap:anywhere}
.invstatus{padding:12px 0;color:var(--muted)}
.invscore{font-weight:700;color:var(--cyan)}
@media(max-width:650px){.invgrid{grid-template-columns:1fr}}

.detailgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.detailitem{background:#0a0e17;border:1px solid var(--line);border-radius:8px;padding:12px;overflow-wrap:anywhere}
.detailitem .label{color:var(--muted);font-size:11px;text-transform:uppercase;margin-bottom:5px}
.detail pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:340px;overflow:auto;background:#0a0e17;padding:13px;border-radius:8px;font-size:12px}
@media(max-width:1000px){.charts{grid-template-columns:1fr 1fr}}
@media(max-width:650px){.charts,.detailgrid{grid-template-columns:1fr}}
@media(max-width:850px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
</head>
<body>
<header>
  <div>
    <div class="brand">AEGIS<span>TRACE</span></div>
    <div class="tagline">Detect the threat. Trace the evidence. Verify the response.</div>
  </div>
  <div class="status"><span class="dot" id="dot"></span><span id="connection">Connecting to Wazuh…</span></div>
</header>
<main>
  <div class="topline">
    <div>
      <h1>Security operations</h1>
      <div class="sub">Live alert feed · Real events queried from your Wazuh Indexer</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><a href="/history" style="text-decoration:none"><button type="button">History of Logs</button></a><a href="/investigation" style="text-decoration:none"><button type="button">AI Security Investigation</button></a><button id="refresh">Refresh now</button></div>
  </div>

  <section class="investigation" id="aiInvestigation" style="display:none">
    <div class="panelhead">
      <div><strong>AI Security Investigation</strong><div class="small">Evidence-linked correlation candidates from stored Wazuh alerts. Running this is on demand.</div></div>
      <button id="runInvestigation" type="button">Run Investigation</button>
    </div>
    <div class="invbody">
      <div class="invstatus" id="investigationStatus" role="status">Investigation has not been run. No analysis runs automatically.</div>
      <div class="invgrid" id="investigationResults"></div>
      <p class="small">Correlation support is a heuristic, not attack probability or model confidence. Candidates are not confirmed incidents.</p>
    </div>
  </section>

  <section class="metrics">
    <div class="metric"><div class="label">Wazuh alerts</div><div class="value" id="total">—</div></div>
    <div class="metric"><div class="label">Critical</div><div class="value" id="critical">—</div></div>
    <div class="metric"><div class="label">High</div><div class="value" id="high">—</div></div>
    <div class="metric"><div class="label">Medium</div><div class="value" id="medium">—</div></div>
    <div class="metric"><div class="label">Low</div><div class="value" id="low">—</div></div>
  </section>

  <section class="charts">
    <div class="chartbox"><h3>Alert severity distribution</h3><div class="chartarea"><canvas id="severityChart"></canvas></div></div>
    <div class="chartbox"><h3>Alert volume over time</h3><div class="chartarea"><canvas id="timelineChart"></canvas></div></div>
    <div class="chartbox"><h3>Top Wazuh rules</h3><div class="chartarea"><canvas id="rulesChart"></canvas></div></div>
  </section>

  <section class="panel" id="fileMonitorPanel" style="margin-bottom:18px">
    <div class="panelhead">
      <div><strong>File Monitoring &amp; Quarantine</strong><div class="small">Monitored files · SHA-256 · VirusTotal verdicts · analyst-controlled response</div></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap"><button id="scanFiles" type="button">Scan now</button><button id="refreshFiles" type="button">Refresh files</button></div>
    </div>
    <div class="filters"><span class="small" id="fileStatus" role="status">Loading monitored files…</span></div>
    <div class="tablewrap"><table style="min-width:900px"><thead><tr><th>File</th><th>Verdict</th><th>Detections</th><th>SHA-256</th><th>Response</th></tr></thead><tbody id="fileRows"><tr><td colspan="5" class="empty">Loading monitored files…</td></tr></tbody></table></div>
    <div style="padding:12px 18px" class="small" id="fileNotice" role="status"></div>
  </section>

  <section class="panel">
    <div class="panelhead">
      <div><strong>Recent security alerts</strong><div class="small">Up to 100 latest indexed alerts</div></div>
      <div class="small" id="updated">Waiting for first refresh…</div>
    </div>
    <div class="filters">
      <input id="search" type="search" placeholder="Search rule, IP, host or description…">
      <select id="severityFilter" aria-label="Filter severity">
        <option value="all">All severities</option><option value="critical">Critical</option>
        <option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
      </select>
      <select id="categoryFilter" aria-label="Filter category">
        <option value="all">All categories</option><option value="authentication">Authentication</option>
        <option value="security">Security detections</option><option value="compliance">Compliance / SCA</option>
        <option value="system">Service / system</option>
      </select>
      <select id="statusFilter" aria-label="Filter alert status">
        <option value="open" selected>Open alerts</option>
        <option value="closed">Closed alerts</option>
        <option value="all">All statuses</option>
      </select>
      <button id="clearFilters" type="button">Clear filters</button>
    </div>
    <div id="error" class="error"></div>
    <div class="tablewrap">
      <table>
        <thead><tr><th>Status</th><th>Severity</th><th>Time</th><th>Rule</th><th>Description</th><th>Source IP</th><th>Agent</th></tr></thead>
        <tbody id="alerts"><tr><td colspan="7" class="empty">Loading Wazuh alerts…</td></tr></tbody>
      </table>
    </div>
  </section>
  <section class="panel detail" id="detailPanel" hidden>
    <div class="panelhead" style="padding:0 0 14px">
      <div><strong>Alert investigation</strong><div class="small">Evidence from the original Wazuh event</div></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button id="dashboardToggleStatus" type="button">Close alert</button>
        <button id="closeDetail" type="button">Close details</button>
      </div>
    </div>
    <div class="detailgrid" id="detailGrid"></div>
    <section class="detailitem" id="vtIpPanel" style="margin:14px 0">
      <div class="label">VirusTotal IP reputation</div>
      <div id="vtIpContent">Select an alert to check its source IP.</div>
    </section>
    <p class="small" id="dashboardStatusMessage" role="status"></p>
    <h3>Original event evidence</h3>
    <pre id="evidenceText">Select an alert to inspect its evidence.</pre>
    <h3>Original Wazuh event (JSON)</h3>
    <pre id="rawEventText"></pre>
  </section>
  <p class="small">Data source: Wazuh Indexer · Auto-refresh: every 15 seconds · This dashboard is read-only.</p>
</main>
<footer>AegisTrace local lab · File quarantine is enabled for configured monitored files; review audit records regularly.</footer>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>

const investigationButton = document.getElementById("runInvestigation");
if (investigationButton) {
  investigationButton.addEventListener("click", async () => {
    const status = document.getElementById("investigationStatus");
    const results = document.getElementById("investigationResults");
    investigationButton.disabled = true;
    status.textContent = "Investigating stored alerts…";
    results.replaceChildren();
    try {
      const response = await fetch("/api/investigation/recent?limit=500", {cache:"no-store"});
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Investigation request failed.");
      status.textContent =
        `Source: ${data.source}. Stored alerts examined: ${data.alerts_examined}; ` +
        `unique events: ${data.unique_events_examined}; duplicate documents skipped: ` +
        `${data.duplicate_documents_skipped}; candidate chains: ${data.candidate_count}.`;
      if (!Array.isArray(data.candidates) || data.candidates.length === 0) {
        results.textContent = "No correlation candidates were returned for this run.";
        return;
      }
      for (const candidate of data.candidates) {
        const card = document.createElement("article");
        card.className = "invcard";
        const heading = document.createElement("h3");
        heading.textContent = candidate.title || "Untitled correlation candidate";
        card.appendChild(heading);

        const meta = document.createElement("div");
        meta.className = "invmeta";
        meta.textContent =
          `${candidate.agent || "Unknown agent"} · ${candidate.alert_count || 0} linked alert(s) · ` +
          `${candidate.start || "Unknown start"} → ${candidate.end || "Unknown end"}`;
        card.appendChild(meta);

        const warning = document.createElement("div");
        warning.className = "invmeta";
        warning.textContent = "Candidate only — not a confirmed attack.";
        card.appendChild(warning);

        const score = document.createElement("div");
        score.className = "invscore";
        score.textContent = `Heuristic correlation support: ${candidate.correlation_support_score ?? "N/A"}`;
        card.appendChild(score);

        const hypothesis = document.createElement("p");
        hypothesis.textContent = candidate.hypothesis || "No hypothesis supplied.";
        card.appendChild(hypothesis);

        const evidenceTitle = document.createElement("strong");
        evidenceTitle.textContent = "Evidence and source alert IDs";
        card.appendChild(evidenceTitle);

        const list = document.createElement("ul");
        list.className = "invlist";
        for (const item of (Array.isArray(candidate.evidence) ? candidate.evidence : [])) {
          const li = document.createElement("li");
          const parts = [
            item.timestamp || "Unknown time",
            `Rule ${item.rule_id || "unknown"}`,
            item.description || "No description",
            item.username ? `user ${item.username}` : "",
            item.source_ip ? `source ${item.source_ip}` : "",
            item.process_id ? `process ${item.process_id}` : "",
            `stored ID ${item.wazuh_id || "unknown"}`,
            item.source_event_id ? `source event ${item.source_event_id}` : ""
          ].filter(Boolean);
          li.textContent = parts.join(" · ");
          list.appendChild(li);
        }
        if (!list.children.length) {
          const li = document.createElement("li");
          li.textContent = "No event-level evidence was returned.";
          list.appendChild(li);
        }
        card.appendChild(list);

        const techniques = document.createElement("p");
        techniques.textContent = "ATT&CK technique IDs: " +
          ((Array.isArray(candidate.technique_ids) && candidate.technique_ids.length)
            ? candidate.technique_ids.join(", ") : "None supplied by source metadata");
        card.appendChild(techniques);
        results.appendChild(card);
      }
    } catch (error) {
      status.textContent = "Investigation failed: " + error.message;
    } finally {
      investigationButton.disabled = false;
    }
  });
}

const el = id => document.getElementById(id);
let allAlerts = [];
let selectedId = null;
let charts = {};
let refreshing = false;

function safe(value){
  const span=document.createElement("span");
  span.textContent=String(value ?? "");
  return span.innerHTML;
}
function dateText(value){
  if(!value) return "—";
  const date=new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
function categoryOf(a){
  const groups=(a.rule_groups || []).join(" ").toLowerCase();
  const description=(a.description || "").toLowerCase();
  const id=String(a.rule_id || "");
  if(/sca|cis|compliance|benchmark/.test(groups+" "+description) || /^1900[789]$/.test(id)) return "compliance";
  if(/authentication|authentication_success|authentication_failed|pam|sshd|ssh/.test(groups+" "+description)) return "authentication";
  if(/attack|exploit|malware|intrusion|web|virus|rootkit|threat/.test(groups+" "+description)) return "security";
  return "system";
}
function filteredAlerts(){
  const query=el("search").value.trim().toLowerCase();
  const severity=el("severityFilter").value;
  const category=el("categoryFilter").value;
  const status=el("statusFilter").value;
  return allAlerts.filter(a=>{
    const haystack=[a.rule_id,a.description,a.source_ip,a.agent,a.agent_id,(a.rule_groups||[]).join(" "),a.evidence].join(" ").toLowerCase();
    return (!query || haystack.includes(query)) &&
      (severity==="all" || a.severity===severity) &&
      (category==="all" || categoryOf(a)===category) &&
      (status==="all" || (a.status||"open")===status);
  });
}
function makeChart(id, config){
  const canvas=el(id);
  if(!canvas || typeof Chart==="undefined") return;
  if(charts[id]) charts[id].destroy();
  charts[id]=new Chart(canvas,config);
}
function renderCharts(){
  const counts=["critical","high","medium","low"].map(s=>allAlerts.filter(a=>a.severity===s).length);
  makeChart("severityChart",{
    type:"doughnut",
    data:{labels:["Critical","High","Medium","Low"],datasets:[{data:counts,backgroundColor:["#ff5268","#ff9c58","#f4ca64","#50d6a0"],borderColor:"#111827",borderWidth:3}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:"bottom",labels:{color:"#edf3ff",padding:12}}}}
  });

  const buckets={};
  for(const a of allAlerts){
    const d=new Date(a.timestamp);
    if(Number.isNaN(d.getTime())) continue;
    d.setMinutes(0,0,0);
    const key=d.toISOString();
    buckets[key]=(buckets[key]||0)+1;
  }
  const times=Object.keys(buckets).sort().slice(-24);
  const timelineCanvas=el("timelineChart");
  const timelineContext=timelineCanvas ? timelineCanvas.getContext("2d") : null;
  let timelineFill="rgba(99,217,237,0.10)";
  if(timelineContext){
    const gradient=timelineContext.createLinearGradient(0,0,0,220);
    gradient.addColorStop(0,"rgba(99,217,237,0.28)");
    gradient.addColorStop(0.65,"rgba(99,217,237,0.07)");
    gradient.addColorStop(1,"rgba(99,217,237,0.00)");
    timelineFill=gradient;
  }

  makeChart("timelineChart",{
    type:"line",
    data:{
      labels:times.map(t=>new Date(t).toLocaleTimeString([],{
        hour:"2-digit",minute:"2-digit"
      })),
      datasets:[{
        label:"Wazuh alerts",
        data:times.map(t=>buckets[t]),
        borderColor:"#63d9ed",
        backgroundColor:timelineFill,
        fill:true,
        tension:0.32,
        borderWidth:2.5,
        pointRadius:2,
        pointHoverRadius:5,
        pointBackgroundColor:"#0a0e17",
        pointBorderColor:"#63d9ed",
        pointBorderWidth:2,
        spanGaps:true
      }]
    },
    options:{
      responsive:true,
      maintainAspectRatio:false,
      animation:false,
      interaction:{intersect:false,mode:"index"},
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:"#111827",
          titleColor:"#edf3ff",
          bodyColor:"#cbd5e1",
          borderColor:"#35506b",
          borderWidth:1,
          padding:10,
          displayColors:false,
          callbacks:{
            label:context=>"Alerts: "+context.parsed.y
          }
        }
      },
      scales:{
        x:{
          ticks:{color:"#98a7bd",maxTicksLimit:6,maxRotation:0},
          grid:{display:false},
          border:{display:false}
        },
        y:{
          beginAtZero:true,
          grace:"10%",
          ticks:{color:"#98a7bd",precision:0,maxTicksLimit:5},
          grid:{color:"rgba(152,167,189,0.12)"},
          border:{display:false}
        }
      }
    }
  });

  const ruleCounts={};
  for(const a of allAlerts){
    const label=String(a.rule_id)+" · "+String(a.description||"Unknown rule");
    ruleCounts[label]=(ruleCounts[label]||0)+1;
  }
  const top=Object.entries(ruleCounts).sort((a,b)=>b[1]-a[1]).slice(0,7);
  makeChart("rulesChart",{
    type:"bar",
    data:{labels:top.map(x=>x[0].length>34?x[0].slice(0,34)+"…":x[0]),datasets:[{label:"Alerts",data:top.map(x=>x[1]),backgroundColor:"#63d9ed",borderRadius:5}]},
    options:{indexAxis:"y",responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{beginAtZero:true,ticks:{color:"#98a7bd",precision:0},grid:{color:"#263247"}},y:{ticks:{color:"#edf3ff",font:{size:10}},grid:{display:false}}}}
  });
}
async function loadVirusTotalIP(ip, alertId){
  const content=el("vtIpContent");
  const value=String(ip||"").trim();

  if(!value || value==="Not recorded" || value==="—"){
    content.textContent="No source IP recorded for this alert. IP reputation lookup is not applicable.";
    return;
  }

  // Public-IP eligibility is enforced by the backend as well.
  const isIPv4PrivateOrLocal =
    /^127\./.test(value) ||
    /^10\./.test(value) ||
    /^192\.168\./.test(value) ||
    /^172\.(1[6-9]|2[0-9]|3[01])\./.test(value) ||
    value==="0.0.0.0";

  if(isIPv4PrivateOrLocal || value==="::1" || value.toLowerCase()==="localhost"){
    content.textContent="Private or loopback IP ("+value+"). Public-IP reputation lookup is not applicable.";
    return;
  }

  content.textContent="Checking VirusTotal reputation for "+value+"…";

  try{
    const response=await fetch("/api/threat-intel/ip/"+encodeURIComponent(value));
    let data=await response.json();

    // Ignore results if the analyst has selected another alert.
    if(String(selectedId)!==String(alertId)) return;

    // The first request queues the lookup. Poll the queue, not VirusTotal.
    for(let attempt=0; attempt<30 &&
        (data.status==="pending" || data.status==="processing"); attempt++){
      content.textContent="VirusTotal lookup queued ("+
        data.status+"). Waiting for the shared scheduler…";
      await new Promise(resolve=>setTimeout(resolve,2000));

      if(String(selectedId)!==String(alertId)) return;

      const statusResponse=await fetch(
        "/api/threat-intel/status/ip/"+encodeURIComponent(value)
      );
      data=await statusResponse.json();
    }

    if(data.status==="pending" || data.status==="processing"){
      content.textContent="Lookup is still queued. Reopen this alert later to check again.";
      return;
    }

    // Queue responses wrap the actual report inside the result field.
    data=data.result || data;

    if(!data.available){
      content.textContent=data.message ||
        "No VirusTotal report is available for this indicator.";
      return;
    }

    const counts=[
      ["Malicious",data.malicious],
      ["Suspicious",data.suspicious],
      ["Harmless",data.harmless],
      ["Undetected",data.undetected]
    ];

    const summary=counts
      .filter(([,value])=>value!==undefined && value!==null)
      .map(([label,value])=>'<span style="margin-right:14px">'+safe(label)+': <strong>'+safe(value)+'</strong></span>')
      .join("");

    const statusText={
      malicious:"Malicious detections reported",
      suspicious:"Suspicious detections reported",
      no_detections:"No malicious detections reported"
    }[data.status] || data.status || "Report available";

    let reportLink="";
    if(typeof data.permalink==="string" &&
       data.permalink.startsWith("https://www.virustotal.com/gui/")){
      reportLink='<p><a href="'+safe(data.permalink)+'" target="_blank" rel="noopener noreferrer">Open VirusTotal report</a></p>';
    }

    const reputation=data.reputation===null || data.reputation===undefined
      ? ""
      : '<p>Community reputation: <strong>'+safe(data.reputation)+'</strong></p>';

    content.innerHTML=
      '<p><strong>'+safe(statusText)+'</strong></p>'+
      '<p>'+summary+'</p>'+
      reputation+
      reportLink+
      '<p class="small">VirusTotal results are supporting intelligence, not proof by themselves that an alert is malicious or benign.</p>';
  }catch(error){
    if(String(selectedId)!==String(alertId)) return;
    content.textContent="VirusTotal lookup failed. The original Wazuh alert is still available.";
  }
}

function showDetail(a){
  selectedId=a.id;
  el("detailPanel").hidden=false;
  const statusButton=el("dashboardToggleStatus");
  statusButton.dataset.id=a.id;
  statusButton.dataset.status=a.status||"open";
  statusButton.textContent=a.status==="closed"?"Reopen alert":"Close alert";
  el("dashboardStatusMessage").textContent="";
  loadVirusTotalIP(a.source_ip, a.id);

  const items=[
    ["Status",a.status||"open"],
    ["Severity",a.severity],["Timestamp",dateText(a.timestamp)],
    ["Rule",a.rule_id+" · Level "+a.rule_level],["Description",a.description],
    ["Source IP",a.source_ip],["Agent",a.agent+" ("+a.agent_id+")"],
    ["Rule groups",(a.rule_groups||[]).join(", ")||"Not recorded"],
    ["MITRE ATT&CK",(a.mitre||[]).join(", ")||"Not mapped"],
    ["Manager",a.manager||"Not recorded"],["Category",categoryOf(a)]
  ];
  el("detailGrid").innerHTML=items.map(([label,value])=>
    '<div class="detailitem"><div class="label">'+safe(label)+'</div><div>'+safe(value)+'</div></div>'
  ).join("");
  el("evidenceText").textContent=a.evidence || "No full_log evidence was recorded for this event.";
  el("rawEventText").textContent=JSON.stringify(a.raw_event||{},null,2);
  el("detailPanel").scrollIntoView({behavior:"smooth",block:"start"});
}
function renderTable(){
  const alerts=filteredAlerts();
  if(!alerts.length){
    el("alerts").innerHTML='<tr><td colspan="7" class="empty">No alerts match these filters.</td></tr>';
    return;
  }
  el("alerts").innerHTML=alerts.map(a=>`
    <tr class="clickrow ${a.id===selectedId?'selected':''}" tabindex="0" role="button" data-alert-id="${safe(a.id)}" aria-label="Inspect alert ${safe(a.rule_id)}">
      <td>${safe(a.status||"open")}</td>
      <td><span class="sev ${safe(a.severity)}">${safe(a.severity)}</span></td>
      <td>${safe(dateText(a.timestamp))}</td>
      <td>${safe(a.rule_id)}<div class="small">Level ${safe(a.rule_level)}</div></td>
      <td>${safe(a.description)}${a.mitre?.length?'<div class="small">ATT&CK: '+safe(a.mitre.join(", "))+'</div>':''}</td>
      <td>${safe(a.source_ip)}</td>
      <td>${safe(a.agent)}<div class="small">${safe(a.agent_id)}</div></td>
    </tr>`).join("");
}
let knownFileAlerts = new Set();
let fileRefreshBusy = false;
function aegisDangerBeep(){try{const C=window.AudioContext||window.webkitAudioContext;if(!C)return;const c=new C(),o=c.createOscillator(),g=c.createGain();o.type='sine';o.frequency.value=880;g.gain.setValueAtTime(0.0001,c.currentTime);g.gain.exponentialRampToValueAtTime(0.12,c.currentTime+0.015);g.gain.exponentialRampToValueAtTime(0.0001,c.currentTime+0.22);o.connect(g);g.connect(c.destination);o.start();o.stop(c.currentTime+0.23);o.onended=()=>c.close();}catch(_e){}}
function aegisKey(f,v){return String(f.sha256||f.path)+':'+String(v.status||'unknown')+':'+String(v.malicious||0)+':'+String(v.suspicious||0);}
function aegisPreviewActive(f,v){const k=aegisKey(f,v),store='aegis-preview:'+k;let until=Number(sessionStorage.getItem(store)||0);if(!until){until=Date.now()+10000;sessionStorage.setItem(store,String(until));}return Date.now()<until;}
function verdictLabel(v){
  if(v==='malicious') return 'MALICIOUS';
  if(v==='suspicious') return 'SUSPICIOUS';
  if(v==='no_detections') return 'No detections';
  if(v==='reported') return 'Reported';
  return 'No report / pending';
}
async function refreshFiles(){
  if(fileRefreshBusy) return;
  fileRefreshBusy=true;
  try{
    const response=await fetch('/api/files/recent?limit=100',{cache:'no-store'});
    const data=await response.json();
    if(!response.ok) throw new Error(data.detail||'Could not load monitored files');
    const allFiles=data.files||[];
    const files=allFiles.filter(f=>{const v=f.virustotal||{},s=String(v.status||'no_info');if(['pending','processing','not_queued'].includes(s))return false;return aegisPreviewActive(f,v);});
    el('fileStatus').innerHTML=(allFiles.length ? allFiles.length+' monitored file(s). ' : '')+'Completed results appear briefly. <a href="/file-history">File History</a>.';
    if(!files.length){el('fileRows').innerHTML='<tr><td colspan="5" class="empty">No active files</td></tr>';return;}
    const alerts=[];
    el('fileRows').innerHTML=files.map((f,i)=>{
      const vt=f.virustotal||{}; const status=String(vt.status||'no_info');
      const malicious=Number(vt.malicious||0), suspicious=Number(vt.suspicious||0);
      const total=malicious+suspicious+Number(vt.harmless||0)+Number(vt.undetected||0);
      const danger=vt.available && (status==='malicious'||status==='suspicious');
      const key=f.sha256+':'+status+':'+malicious+':'+suspicious;
      if(danger && !knownFileAlerts.has(key)) alerts.push({key,name:f.path.split('/').pop(),status,malicious,suspicious,total,url:vt.permalink});
      const link=(typeof vt.permalink==='string'&&vt.permalink.startsWith('https://www.virustotal.com/gui/'))?`<a href="${safe(vt.permalink)}" target="_blank" rel="noopener noreferrer">Report</a>`:'—';
      const auto=f.quarantine_status==='quarantined';
      const verdict=danger?`<span class="sev ${status==='malicious'?'critical':'medium'}">${safe(verdictLabel(status))}</span>`:safe(vt.message||verdictLabel(status));
      let action=auto?`<span class="sev high">QUARANTINED</span><div class="small">${safe(f.quarantine_path||'Moved to quarantine')}</div>`:(f.quarantine_status==='failed'?`<span class="sev medium">Quarantine failed</span><div class="small">${safe(f.quarantine_error||'Check permissions')}</div>`:'—');
      if(danger && !auto && f.path && f.sha256) action=`<button type="button" data-quarantine-index="${i}">Quarantine</button>`;
      return `<tr><td>${safe(f.path)}<div class="small">${safe(f.size)} bytes · ${link}</div></td><td>${verdict}</td><td>Malicious ${safe(malicious)} · Suspicious ${safe(suspicious)}<div class="small">Counted engines: ${safe(total)}</div></td><td><code>${safe(f.sha256)}</code></td><td>${action}</td></tr>`;
    }).join('');
    // Notify once per distinct report verdict; no popups for missing reports or errors.
    for(const a of alerts){
      knownFileAlerts.add(a.key);
      aegisDangerBeep();
      const message=`AegisTrace: ${a.status.toUpperCase()} file report for ${a.name} (${a.malicious} malicious, ${a.suspicious} suspicious).`;
      el('fileNotice').textContent=message;
      if('Notification' in window && Notification.permission==='granted'){
        const n=new Notification('AegisTrace file alert',{body:message});
        if(a.url) n.onclick=()=>window.open(a.url,'_blank','noopener');
      }
    }
    // Attach safe, indexed actions; path/hash are sent from the fetched row, not HTML attributes.
    el('fileRows').querySelectorAll('button[data-quarantine-index]').forEach(button=>button.addEventListener('click',async()=>{
      const f=files[Number(button.dataset.quarantineIndex)];
      if(!f) return;
      const reason=window.prompt('Reason for quarantine (audit record):','Analyst confirmed suspicious file');
      if(reason===null) return;
      if(!window.confirm('Move this file out of the monitored directory into AegisTrace quarantine? This does not delete it.')) return;
      button.disabled=true; el('fileNotice').textContent='Quarantine requested…';
      try{
        const r=await fetch('/api/files/quarantine',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:f.path,sha256:f.sha256,reason})});
        const d=await r.json(); if(!r.ok) throw new Error(d.detail||'Quarantine failed');
        el('fileNotice').textContent='Quarantine completed and audited: '+(d.quarantine_path||d.status);
        await refreshFiles();
      }catch(e){el('fileNotice').textContent='Quarantine not completed: '+e.message;button.disabled=false;}
    }));
  }catch(e){el('fileStatus').textContent='File monitor error: '+e.message;}
  finally{fileRefreshBusy=false;}
}
el('refreshFiles').addEventListener('click',refreshFiles);
el('scanFiles').addEventListener('click',async()=>{
  const button=el('scanFiles'); button.disabled=true; el('fileStatus').textContent='Scanning configured directories…';
  try{const r=await fetch('/api/files/scan',{method:'POST'});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Scan failed');el('fileStatus').textContent=`Scan complete: ${d.updated} updated, ${d.skipped_large} oversized skipped, ${d.errors} errors.`;await refreshFiles();}
  catch(e){el('fileStatus').textContent='Scan failed: '+e.message;}
  finally{button.disabled=false;}
});
// No permission button is injected into the dashboard. In-app alerts and sound
// remain enabled; native desktop notifications are used only if permission is already granted.
refreshFiles();
setInterval(refreshFiles,10000);

async function refresh(){
  if(refreshing) return;
  refreshing=true;
  el("refresh").disabled=true;
  el("refresh").textContent="Refreshing…";
  try{
    const response=await fetch("/api/wazuh/alerts",{cache:"no-store"});
    const data=await response.json();
    if(!response.ok) throw new Error(data.detail || "Wazuh query failed");
    allAlerts=data.alerts || [];
    el("total").textContent=allAlerts.length;
    for(const level of ["critical","high","medium","low"]){
      el(level).textContent=allAlerts.filter(a=>a.severity===level).length;
    }
    el("connection").textContent="Wazuh connected";
    el("dot").style.background="#50d6a0";
    el("error").style.display="none";
    el("updated").textContent="Updated "+new Date(data.fetched_at).toLocaleTimeString();
    renderCharts();
    renderTable();
    if(selectedId){
      const selected=allAlerts.find(a=>a.id===selectedId);
      if(selected) showDetail(selected);
      else {el("detailPanel").hidden=true;selectedId=null;}
    }
  }catch(error){
    el("connection").textContent="Connection error";
    el("dot").style.background="#ff7185";
    el("error").textContent=error.message;
    el("error").style.display="block";
  }finally{
    refreshing=false;
    el("refresh").disabled=false;
    el("refresh").textContent="Refresh now";
  }
}
el("alerts").addEventListener("click",event=>{
  const row=event.target.closest("tr[data-alert-id]");
  if(!row) return;
  const alert=allAlerts.find(a=>a.id===row.dataset.alertId);
  if(alert) showDetail(alert);
  renderTable();
});
el("alerts").addEventListener("keydown",event=>{
  if(event.key!=="Enter" && event.key!==" ") return;
  const row=event.target.closest("tr[data-alert-id]");
  if(!row) return;
  event.preventDefault();
  const alert=allAlerts.find(a=>a.id===row.dataset.alertId);
  if(alert) showDetail(alert);
  renderTable();
});
el("refresh").addEventListener("click",refresh);
el("search").addEventListener("input",renderTable);
el("severityFilter").addEventListener("change",renderTable);
el("categoryFilter").addEventListener("change",renderTable);
el("statusFilter").addEventListener("change",renderTable);
el("clearFilters").addEventListener("click",()=>{
  el("search").value="";
  el("severityFilter").value="all";
  el("categoryFilter").value="all";
  el("statusFilter").value="all";
  renderTable();
});
el("dashboardToggleStatus").addEventListener("click",async()=>{
  const button=el("dashboardToggleStatus");
  const id=button.dataset.id;

  if(!id){
    el("dashboardStatusMessage").textContent="Select an alert first.";
    return;
  }

  const nextStatus=button.dataset.status==="closed"?"open":"closed";
  button.disabled=true;
  el("dashboardStatusMessage").textContent="Saving status…";

  try{
    const response=await fetch(
      `/api/wazuh/alerts/${encodeURIComponent(id)}/status?status=${nextStatus}`,
      {method:"POST"}
    );
    const result=await response.json();

    if(!response.ok){
      throw new Error(result.detail||"Could not update alert status.");
    }

    el("dashboardStatusMessage").textContent=
      `Alert status changed to ${result.status}.`;
    await refresh();
  }catch(error){
    el("dashboardStatusMessage").textContent=error.message;
  }finally{
    button.disabled=false;
  }
});

el("closeDetail").addEventListener("click",()=>{
  el("detailPanel").hidden=true;
  selectedId=null;
  renderTable();
});
refresh();
setInterval(refresh,15000);
</script>
</body>
</html>"""
