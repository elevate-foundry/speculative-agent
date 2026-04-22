#!/usr/bin/env python3
"""
compliance_server.py — Minimal HTTP server exposing the compliance lattice via a browser UI.

GET  /          → HTML UI
POST /evaluate  → JSON { action_type, path, data_type?, jurisdiction?, flags? }
                ← JSON ComplianceDecision
GET  /audit     → last N audit log entries as JSON
"""

import json
import sys
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(__file__))
from compliance import evaluate, infer_context, DataContext, AUDIT_LOG_PATH

PORT = 8420

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Compliance Lattice</title>
<style>
  :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;
        --muted:#8b949e;--green:#3fb950;--orange:#d29922;--red:#f85149;
        --blue:#58a6ff;--purple:#bc8cff;}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:"SF Mono",ui-monospace,monospace;
       font-size:13px;line-height:1.6;padding:1.5rem}
  h1{font-size:1.1rem;color:var(--blue);margin-bottom:1.2rem;letter-spacing:.05em}
  h2{font-size:.85rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;
     margin:1.5rem 0 .6rem}
  .row{display:flex;gap:1rem;flex-wrap:wrap}
  .col{flex:1;min-width:260px}
  label{display:block;color:var(--muted);font-size:.75rem;margin-bottom:.25rem;
        text-transform:uppercase;letter-spacing:.08em}
  select,input,textarea{width:100%;background:var(--surface);border:1px solid var(--border);
    color:var(--text);padding:.45rem .6rem;border-radius:4px;font-family:inherit;font-size:12px}
  select:focus,input:focus,textarea:focus{outline:none;border-color:var(--blue)}
  textarea{resize:vertical;min-height:72px}
  .flags{display:flex;flex-wrap:wrap;gap:.5rem 1.2rem;margin-top:.4rem}
  .flags label{display:flex;align-items:center;gap:.35rem;font-size:.8rem;
               color:var(--text);text-transform:none;letter-spacing:0;cursor:pointer}
  .flags input[type=checkbox]{width:auto}
  button{background:var(--blue);color:#0d1117;border:none;padding:.5rem 1.4rem;
         border-radius:4px;cursor:pointer;font-family:inherit;font-weight:700;
         font-size:.8rem;letter-spacing:.05em;margin-top:1rem}
  button:hover{opacity:.85}
  #result{margin-top:1.4rem}
  .verdict-badge{display:inline-block;padding:.2rem .7rem;border-radius:3px;
                 font-weight:700;font-size:.75rem;letter-spacing:.08em}
  .PERMIT{background:#1c2e1c;color:var(--green);border:1px solid var(--green)}
  .CONDITIONAL{background:#2d2208;color:var(--orange);border:1px solid var(--orange)}
  .BLOCK{background:#2d1519;color:var(--red);border:1px solid var(--red)}
  .lagrangian{font-size:1.4rem;font-weight:700;margin:.5rem 0}
  .constraint-table{width:100%;border-collapse:collapse;margin-top:.8rem}
  .constraint-table th{color:var(--muted);font-size:.7rem;text-transform:uppercase;
                       letter-spacing:.08em;padding:.3rem .5rem;border-bottom:1px solid var(--border);
                       text-align:left}
  .constraint-table td{padding:.3rem .5rem;border-bottom:1px solid #21262d;font-size:.8rem;
                       vertical-align:top}
  .v-PERMIT{color:var(--green)} .v-CONDITIONAL{color:var(--orange)} .v-BLOCK{color:var(--red)}
  .justification{background:var(--surface);border:1px solid var(--border);border-radius:4px;
                 padding:.7rem;margin-top:.8rem;font-size:.8rem;color:var(--muted);
                 white-space:pre-wrap}
  .mitigations{margin-top:.7rem}
  .mit-item{background:#1c1f26;border-left:3px solid var(--orange);padding:.35rem .6rem;
            margin-bottom:.35rem;font-size:.78rem}
  .blocking-list{margin-top:.5rem}
  .block-item{background:#2d1519;border-left:3px solid var(--red);padding:.35rem .6rem;
              margin-bottom:.35rem;font-size:.78rem}
  .audit-table{width:100%;border-collapse:collapse;margin-top:.6rem;font-size:.75rem}
  .audit-table th{color:var(--muted);padding:.25rem .5rem;border-bottom:1px solid var(--border);
                  text-align:left;white-space:nowrap}
  .audit-table td{padding:.2rem .5rem;border-bottom:1px solid #21262d;max-width:220px;
                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .audit-table tr.permitted td{color:var(--text)}
  .audit-table tr.blocked td{color:var(--red)}
  .pill{display:inline-block;font-size:.65rem;padding:0 .4rem;border-radius:2px;font-weight:700}
  .pill.p{background:#1c2e1c;color:var(--green)} .pill.c{background:#2d2208;color:var(--orange)}
  .pill.b{background:#2d1519;color:var(--red)}
  #audit-panel{margin-top:2rem;border-top:1px solid var(--border);padding-top:1rem}
  .tab-bar{display:flex;gap:.5rem;margin-bottom:1rem}
  .tab{padding:.3rem .8rem;border:1px solid var(--border);border-radius:3px;cursor:pointer;
       font-size:.75rem;color:var(--muted);background:transparent}
  .tab.active{border-color:var(--blue);color:var(--blue);background:#0d1b2a}
  #spinner{display:none;color:var(--muted);margin-left:.8rem;font-size:.8rem}
  .error-msg{color:var(--red);margin-top:.5rem;font-size:.8rem}
</style>
</head>
<body>
<h1>⚖ Compliance Lattice — Tropical Semiring Decision Engine</h1>

<div class="tab-bar">
  <div class="tab active" onclick="showTab('evaluate')">Evaluate Action</div>
  <div class="tab" onclick="showTab('audit')">Audit Log</div>
</div>

<div id="tab-evaluate">
  <div class="row">
    <div class="col">
      <label>Action Type</label>
      <select id="action_type">
        <option value="bash">bash</option>
        <option value="read_file">read_file</option>
        <option value="write_file">write_file</option>
        <option value="python_exec">python_exec</option>
        <option value="noop">noop</option>
      </select>
    </div>
    <div class="col">
      <label>Jurisdiction Override</label>
      <select id="jurisdiction">
        <option value="">Auto-detect</option>
        <option value="US">US</option>
        <option value="EU">EU</option>
        <option value="CA">California (CCPA)</option>
        <option value="UK">UK</option>
        <option value="CN">China (PIPL)</option>
        <option value="BR">Brazil (LGPD)</option>
        <option value="CAD">Canada (PIPEDA)</option>
      </select>
    </div>
  </div>

  <div style="margin-top:.8rem">
    <label>Command / Path</label>
    <textarea id="path" rows="2" placeholder="e.g.  rm /eu/users/profiles.json
  or  cat /var/log/audit.jsonl
  or  import os; os.remove('/data/credit/tradeline.json')"></textarea>
  </div>

  <div style="margin-top:.8rem">
    <label>Data Type Override</label>
    <select id="data_type">
      <option value="">Auto-detect</option>
      <option value="health">health (PHI / HIPAA)</option>
      <option value="financial">financial (GLBA / FCRA)</option>
      <option value="credit">credit (FCRA / Metro II)</option>
      <option value="pii">pii (GDPR / CCPA)</option>
      <option value="credential">credential</option>
      <option value="log">log / audit</option>
      <option value="code">code</option>
    </select>
  </div>

  <div class="flags">
    <label><input type="checkbox" id="flag_pii"> Contains PII</label>
    <label><input type="checkbox" id="flag_phi"> Contains PHI</label>
    <label><input type="checkbox" id="flag_fin"> Contains financial data</label>
    <label><input type="checkbox" id="flag_audit"> Is audit log</label>
    <label><input type="checkbox" id="flag_backed"> Is backed up</label>
    <label><input type="checkbox" id="flag_consumer"> Has consumer deletion request</label>
  </div>

  <div class="row" style="margin-top:.8rem">
    <div class="col">
      <label>Record age (days, optional)</label>
      <input type="number" id="created_days" placeholder="e.g. 90">
    </div>
    <div class="col">
      <label>Required retention (days, optional)</label>
      <input type="number" id="retention_days" placeholder="e.g. 2190">
    </div>
  </div>

  <button onclick="runEval()">Evaluate ▶</button>
  <span id="spinner">evaluating…</span>
  <div id="error" class="error-msg"></div>
  <div id="result"></div>
</div>

<div id="tab-audit" style="display:none">
  <button onclick="loadAudit()">Refresh Log</button>
  <div id="audit-content" style="margin-top:1rem"></div>
</div>

<script>
function showTab(name) {
  document.getElementById('tab-evaluate').style.display = name==='evaluate'?'':'none';
  document.getElementById('tab-audit').style.display   = name==='audit'?'':'none';
  document.querySelectorAll('.tab').forEach((t,i)=>{
    t.classList.toggle('active', (i===0&&name==='evaluate')||(i===1&&name==='audit'));
  });
  if(name==='audit') loadAudit();
}

async function runEval() {
  document.getElementById('error').textContent='';
  document.getElementById('result').innerHTML='';
  document.getElementById('spinner').style.display='inline';
  const body = {
    action_type: document.getElementById('action_type').value,
    path: document.getElementById('path').value.trim(),
    jurisdiction: document.getElementById('jurisdiction').value||null,
    data_type: document.getElementById('data_type').value||null,
    contains_pii: document.getElementById('flag_pii').checked||null,
    contains_phi: document.getElementById('flag_phi').checked||null,
    contains_financial: document.getElementById('flag_fin').checked||null,
    is_audit_log: document.getElementById('flag_audit').checked||null,
    is_backed_up: document.getElementById('flag_backed').checked||null,
    has_consumer_request: document.getElementById('flag_consumer').checked||null,
    created_days_ago: document.getElementById('created_days').value?
                      parseInt(document.getElementById('created_days').value):null,
    retention_days: document.getElementById('retention_days').value?
                    parseInt(document.getElementById('retention_days').value):null,
  };
  try {
    const resp = await fetch('/evaluate', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d = await resp.json();
    if(!resp.ok) { document.getElementById('error').textContent=d.error||'Server error'; return; }
    renderDecision(d);
  } catch(e) {
    document.getElementById('error').textContent = e.message;
  } finally {
    document.getElementById('spinner').style.display='none';
  }
}

function verdictSummary(d) {
  if(!d.permitted) return 'BLOCK';
  if(d.mitigations_required && d.mitigations_required.length) return 'CONDITIONAL';
  return 'PERMIT';
}

function renderDecision(d) {
  const vs = verdictSummary(d);
  let html = `<h2>Decision</h2>
  <span class="verdict-badge ${vs}">${vs}</span>
  <div class="lagrangian">ℒ = ${d.lagrangian_value.toFixed(2)}</div>
  <div class="justification">${escHtml(d.justification)}</div>`;

  if(d.blocking_regulations&&d.blocking_regulations.length){
    html+=`<div class="blocking-list"><b style="color:var(--red)">Blocked by:</b>`;
    d.blocking_regulations.forEach(r=>{ html+=`<div class="block-item">${escHtml(r)}</div>`; });
    html+=`</div>`;
  }
  if(d.mitigations_required&&d.mitigations_required.length){
    html+=`<div class="mitigations"><b style="color:var(--orange)">Required mitigations:</b>`;
    d.mitigations_required.forEach(m=>{ html+=`<div class="mit-item">${escHtml(m)}</div>`; });
    html+=`</div>`;
  }

  html+=`<h2 style="margin-top:1.2rem">Constraint Results (${d.constraints.length} nodes)</h2>
  <table class="constraint-table">
  <thead><tr><th>Regulation</th><th>Verdict</th><th>Rationale</th></tr></thead><tbody>`;
  d.constraints.forEach(c=>{
    html+=`<tr><td><b>${escHtml(c.regulation)}</b></td>
    <td class="v-${c.verdict}">${c.verdict}</td>
    <td>${escHtml(c.rationale)}</td></tr>`;
  });
  html+=`</tbody></table>`;
  html+=`<div style="margin-top:.6rem;color:var(--muted);font-size:.72rem">
    Action ID: ${escHtml(d.action_id)} &nbsp;|&nbsp; ${escHtml(d.timestamp)}
  </div>`;
  document.getElementById('result').innerHTML=html;
}

async function loadAudit() {
  const resp = await fetch('/audit?n=50');
  const entries = await resp.json();
  if(!entries.length){ document.getElementById('audit-content').innerHTML='<span style="color:var(--muted)">No entries yet.</span>'; return; }
  let html=`<table class="audit-table"><thead><tr>
    <th>#</th><th>Time</th><th>Action</th><th>Path</th><th>Verdict</th><th>ℒ</th><th>Blocked by</th>
  </tr></thead><tbody>`;
  entries.slice().reverse().forEach((e,i)=>{
    const vs = !e.permitted?'b': (e.mitigations&&e.mitigations.length?'c':'p');
    const cls = e.permitted?'permitted':'blocked';
    html+=`<tr class="${cls}">
      <td style="color:var(--muted)">${entries.length-i}</td>
      <td style="color:var(--muted)">${e.timestamp.slice(11,19)}</td>
      <td>${escHtml(e.action_type)}</td>
      <td title="${escHtml(e.path)}">${escHtml(e.path.length>35?e.path.slice(0,35)+'…':e.path)}</td>
      <td><span class="pill ${vs}">${e.permitted?(e.mitigations&&e.mitigations.length?'COND':'PERMIT'):'BLOCK'}</span></td>
      <td>${e.lagrangian.toFixed(1)}</td>
      <td style="color:var(--red)">${(e.blocking||[]).join(', ')}</td>
    </tr>`;
  });
  html+=`</tbody></table>`;
  document.getElementById('audit-content').innerHTML=html;
}

function escHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

document.getElementById('path').addEventListener('keydown', e=>{
  if(e.key==='Enter'&&(e.metaKey||e.ctrlKey)) runEval();
});
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default access log

    def _send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", ""):
            self._send_html(HTML)
        elif parsed.path == "/audit":
            qs = parse_qs(parsed.query)
            n = int(qs.get("n", ["50"])[0])
            entries = _read_audit_tail(n)
            self._send_json(entries)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/evaluate":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
        except Exception as e:
            self._send_json({"error": f"Invalid JSON: {e}"}, 400)
            return

        action_type = req.get("action_type", "bash")
        path = req.get("path", "")
        if not path:
            self._send_json({"error": "path is required"}, 400)
            return

        try:
            ctx = infer_context(path)

            # Apply overrides from request
            if req.get("data_type"):
                ctx.data_type = req["data_type"]
            if req.get("jurisdiction"):
                ctx.subject_jurisdiction = req["jurisdiction"]
            if req.get("contains_pii") is not None:
                ctx.contains_pii = bool(req["contains_pii"])
            if req.get("contains_phi") is not None:
                ctx.contains_phi = bool(req["contains_phi"])
            if req.get("contains_financial") is not None:
                ctx.contains_financial = bool(req["contains_financial"])
            if req.get("is_audit_log") is not None:
                ctx.is_audit_log = bool(req["is_audit_log"])
            if req.get("is_backed_up") is not None:
                ctx.is_backed_up = bool(req["is_backed_up"])
            if req.get("has_consumer_request") is not None:
                ctx.has_consumer_request = bool(req["has_consumer_request"])
            if req.get("created_days_ago") is not None:
                ctx.created_days_ago = int(req["created_days_ago"])
            if req.get("retention_days") is not None:
                ctx.retention_days = int(req["retention_days"])

            payload = {"command": path, "path": path}
            decision = evaluate(action_type, payload, ctx)

            result = {
                "action_id": decision.action_id,
                "action_type": decision.action_type,
                "path": decision.path,
                "timestamp": decision.timestamp,
                "permitted": decision.permitted,
                "lagrangian_value": decision.lagrangian_value,
                "blocking_regulations": decision.blocking_regulations,
                "mitigations_required": decision.mitigations_required,
                "justification": decision.justification,
                "constraints": [
                    {
                        "regulation": c.regulation,
                        "verdict": c.verdict.name,
                        "rationale": c.rationale,
                    }
                    for c in decision.constraints
                ],
                "inferred_context": {
                    "data_type": ctx.data_type,
                    "jurisdiction": ctx.subject_jurisdiction,
                    "contains_pii": ctx.contains_pii,
                    "contains_phi": ctx.contains_phi,
                    "contains_financial": ctx.contains_financial,
                    "is_audit_log": ctx.is_audit_log,
                },
            }
            self._send_json(result)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)


def _read_audit_tail(n: int) -> list:
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    try:
        with open(AUDIT_LOG_PATH, "r") as f:
            lines = f.read().strip().splitlines()
        entries = []
        for line in lines[-n:]:
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
        return entries
    except Exception:
        return []


if __name__ == "__main__":
    server = HTTPServer(("localhost", PORT), Handler)
    print(f"Compliance Lattice UI → http://localhost:{PORT}")
    print(f"Audit log             → {AUDIT_LOG_PATH}")
    server.serve_forever()
