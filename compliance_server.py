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

# Load .env before importing anything that reads env vars (config, providers)
_env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

# Use performance budget so cloud models (OpenAI, Anthropic, Google) are included
os.environ.setdefault("AGENT_BUDGET", "performance")

sys.path.insert(0, os.path.dirname(__file__))
from compliance import (
    evaluate, infer_context, DataContext, AUDIT_LOG_PATH,
    encode_braille_word, decode_braille_word, encode_braille_binary,
    braille_word_to_bits, braille_meet, braille_join, braille_hamming,
    braille_drift, evaluate_filtration, Verdict, REGULATION_ORDER,
)

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

  if(d.braille){
    html+=`<h2 style="margin-top:1.2rem">Braille Encoding</h2>
    <div style="display:flex;align-items:center;gap:1.5rem;padding:.6rem;background:var(--surface);border:1px solid var(--border);border-radius:4px">
      <div style="font-size:2.5rem;letter-spacing:.3em;font-family:inherit">${d.braille.word||'\u2800\u2800'}</div>
      <div style="font-size:.75rem;color:var(--muted);line-height:1.8">
        <div>Ternary word: <b style="color:var(--text)">${d.braille.word||'\u2800\u2800'}</b> (${d.braille.cells||2}-cell, ${d.braille.bits_required||15}b \u2192 ${d.braille.bits_available||16}b)</div>
        <div>Binary cell: <b style="color:var(--text)">${d.braille.binary||'\u2800'}</b> (8-dot, permit/block)</div>
        <div>Bits: <code>${d.braille.bits||'00000000 00000000'}</code></div>
        <div>State integer: <code>${d.braille.state_int||0}</code> &nbsp; F=${d.braille.framework_count||9} S=${d.braille.states_per_framework||3}</div>
      </div>
    </div>`;
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

    def _send_sse(self, event: str, data: str):
        msg = f"event: {event}\ndata: {data}\n\n"
        self.wfile.write(msg.encode())
        self.wfile.flush()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", ""):
            self._send_html(HTML)
        elif parsed.path == "/race":
            qs = parse_qs(parsed.query)
            task = qs.get("task", [""])[0].strip()
            if not task:
                self._send_html(RACE_HTML)
                return
            # SSE stream
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            _run_race_sse(task, self._send_sse)
        elif parsed.path == "/audit":
            qs = parse_qs(parsed.query)
            n = int(qs.get("n", ["50"])[0])
            entries = _read_audit_tail(n)
            self._send_json(entries)
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/evaluate":
            return self._handle_evaluate()
        elif parsed.path == "/filtration":
            return self._handle_filtration()
        elif parsed.path == "/bridge":
            return self._handle_bridge()
        else:
            self.send_error(404)
            return

    def _handle_bridge(self):
        """POST /bridge — compare/merge two or more Braille words."""
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
        except Exception as e:
            self._send_json({"error": f"Invalid JSON: {e}"}, 400)
            return

        words = req.get("words")
        if not words or not isinstance(words, list) or len(words) < 2:
            self._send_json({"error": "'words' must be a list of 2+ Braille word strings"}, 400)
            return

        F = req.get("framework_count", 9)
        S = req.get("states", 3)

        try:
            # Decode all words back to verdict vectors
            decoded = {}
            for i, w in enumerate(words):
                verdicts = decode_braille_word(w, F, S)
                decoded[f"word_{i}"] = {
                    "word": w,
                    "verdicts": [v.name for v in verdicts],
                    "bits": braille_word_to_bits(w),
                }

            # Pairwise distances
            pairwise = []
            for i in range(len(words)):
                for j in range(i + 1, len(words)):
                    h = braille_hamming(words[i], words[j], F, S)
                    d = braille_drift(words[i], words[j], F, S)
                    pairwise.append({
                        "a": i, "b": j,
                        "hamming": h, "drift": round(d, 4),
                    })

            # Global meet and join
            meet_w = words[0]
            join_w = words[0]
            for w in words[1:]:
                meet_w = braille_meet(meet_w, w, F, S)
                join_w = braille_join(join_w, w, F, S)

            consensus = len(set(words)) == 1

            self._send_json({
                "words": decoded,
                "pairwise": pairwise,
                "meet": {
                    "word": meet_w,
                    "verdicts": [v.name for v in decode_braille_word(meet_w, F, S)],
                    "description": "conservative merge (strictest per framework)",
                },
                "join": {
                    "word": join_w,
                    "verdicts": [v.name for v in decode_braille_word(join_w, F, S)],
                    "description": "permissive merge (most lenient per framework)",
                },
                "consensus": consensus,
            })
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_filtration(self):
        """POST /filtration — evaluate at progressive compliance tiers."""
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
            # Apply overrides
            for key in ("data_type", "jurisdiction", "contains_pii", "contains_phi",
                        "contains_financial", "is_audit_log", "is_backed_up",
                        "has_consumer_request", "created_days_ago", "retention_days"):
                if req.get(key) is not None:
                    val = req[key]
                    if key == "jurisdiction":
                        ctx.subject_jurisdiction = val
                    elif key in ("created_days_ago", "retention_days"):
                        setattr(ctx, key, int(val))
                    elif key == "data_type":
                        ctx.data_type = val
                    else:
                        setattr(ctx, key, bool(val))

            custom_tiers = req.get("tiers")  # optional: list of lists of reg names
            payload = {"command": path, "path": path}
            tiers = evaluate_filtration(action_type, payload, ctx,
                                         tiers=custom_tiers)

            result = {
                "tiers": [
                    {
                        "regulations": t.regulations,
                        "braille": {
                            "word": t.braille.word,
                            "bits": braille_word_to_bits(t.braille.word),
                            "state_int": t.braille.state_int,
                        },
                        "lagrangian": t.lagrangian,
                        "permitted": t.permitted,
                        "blocking": t.blocking,
                    }
                    for t in tiers
                ],
                "regulation_order": list(REGULATION_ORDER),
            }
            self._send_json(result)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_evaluate(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
        except Exception as e:
            return self._send_json({"error": f"Invalid JSON: {e}"}, 400)

        action_type = req.get("action_type", "bash")
        path = req.get("path", "")
        if not path:
            return self._send_json({"error": "path is required"}, 400)

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

            bw = encode_braille_word(decision.constraints)
            bb = encode_braille_binary(decision.constraints)

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
                "braille": {
                    "word": bw.word,
                    "binary": bb,
                    "bits": braille_word_to_bits(bw.word),
                    "state_int": bw.state_int,
                    "cells": bw.cells,
                    "bits_required": bw.bits_required,
                    "bits_available": bw.bits_available,
                    "framework_count": bw.framework_count,
                    "states_per_framework": bw.states_per_framework,
                },
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


RACE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Speculative Race — Live CoT</title>
<style>
  :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;
        --muted:#8b949e;--green:#3fb950;--orange:#d29922;--red:#f85149;
        --blue:#58a6ff;}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:"SF Mono",ui-monospace,monospace;
       font-size:12px;line-height:1.55;display:flex;flex-direction:column;height:100vh;overflow:hidden}
  #header{padding:.6rem 1rem;border-bottom:1px solid var(--border);
          display:flex;align-items:center;gap:1rem;flex-shrink:0}
  #header h1{font-size:.9rem;color:var(--blue);letter-spacing:.06em}
  #task-input{flex:1;background:var(--surface);border:1px solid var(--border);
              color:var(--text);padding:.35rem .6rem;border-radius:4px;font-family:inherit;font-size:12px}
  #task-input:focus{outline:none;border-color:var(--blue)}
  #go-btn{background:var(--blue);color:#0d1117;border:none;padding:.35rem 1rem;
          border-radius:4px;font-family:inherit;font-size:12px;cursor:pointer;font-weight:700;white-space:nowrap}
  #go-btn:disabled{opacity:.4;cursor:default}
  #lagrangian-bar{padding:.35rem 1rem;background:#0a0e14;border-bottom:1px solid var(--border);
                  font-size:.75rem;color:var(--muted);display:flex;gap:1.5rem;flex-shrink:0;flex-wrap:wrap}
  .l-chip{display:inline-flex;align-items:center;gap:.3rem}
  .l-score{font-weight:700;font-variant-numeric:tabular-nums}
  #arena{display:flex;flex:1;overflow:hidden;gap:0}
  .col-wrap{display:flex;flex-direction:column;flex:1;min-width:220px;
            border-right:1px solid var(--border);overflow:hidden}
  .col-wrap:last-child{border-right:none}
  .col-header{padding:.4rem .6rem;background:#0a0e14;border-bottom:1px solid var(--border);
              display:flex;justify-content:space-between;align-items:center;flex-shrink:0}
  .col-name{font-weight:700;font-size:.78rem;letter-spacing:.04em}
  .col-meta{font-size:.7rem;color:var(--muted)}
  .col-body{flex:1;overflow-y:auto;padding:.5rem .6rem;white-space:pre-wrap;word-break:break-word;font-size:11.5px}
  .token{animation:fadein .08s ease}
  @keyframes fadein{from{opacity:0}to{opacity:1}}
  .verdict-PERMIT{color:var(--green)}
  .verdict-CONDITIONAL{color:var(--orange)}
  .verdict-BLOCK{color:var(--red)}
  .badge{display:inline-block;padding:1px 5px;border-radius:3px;font-size:.7rem;font-weight:700}
  .badge-PERMIT{background:#1a3d20;color:var(--green)}
  .badge-CONDITIONAL{background:#3d2c0a;color:var(--orange)}
  .badge-BLOCK{background:#3d0f0a;color:var(--red)}
  .badge-WINNER{background:#1a2a3d;color:var(--blue);margin-left:.4rem}
  .done-overlay{position:sticky;bottom:0;background:#0a0e14;border-top:1px solid var(--border);
                padding:.25rem .6rem;font-size:.7rem;display:flex;gap:.8rem;color:var(--muted)}
  #status-bar{padding:.3rem 1rem;background:#0a0e14;border-top:1px solid var(--border);
              font-size:.72rem;color:var(--muted);flex-shrink:0}
</style>
</head>
<body>
<div id="header">
  <h1>⬡ Speculative Race</h1>
  <input id="task-input" type="text" placeholder="Enter task for all models to race on…"
         value="What is the tropical semiring? Explain in 3 sentences then output a noop action.">
  <button id="go-btn" onclick="startRace()">Race ▶</button>
</div>
<div id="lagrangian-bar">
  <span style="color:var(--muted)">ℒ distribution:</span>
  <span class="l-chip">L0 <span class="l-score" id="lc-L0" style="color:var(--green)">—</span></span>
  <span class="l-chip">L1 <span class="l-score" id="lc-L1" style="color:var(--orange)">—</span></span>
  <span class="l-chip">L2 <span class="l-score" id="lc-L2" style="color:var(--red)">—</span></span>
  <span class="l-chip">L3 <span class="l-score" id="lc-L3" style="color:#f85149;font-weight:900">—</span></span>
  <span id="race-status" style="margin-left:auto"></span>
</div>
<div id="arena"></div>
<div id="status-bar">Ready — enter a task and click Race ▶</div>

<script>
const COLORS = ['#58a6ff','#3fb950','#bc8cff','#d29922','#f78166','#39d353','#ffa657','#79c0ff'];
let evtSource = null;
let cols = {};
let startTs = null;
let winnerName = null;
let lCounts = {L0:0,L1:0,L2:0,L3:0};

function lagrangianClass(l) {
  if (l === 0) return 'L0';
  if (l <= 0.5) return 'L1';
  if (l < 2.0)  return 'L2';
  return 'L3';
}

function startRace() {
  const task = document.getElementById('task-input').value.trim();
  if (!task) return;
  if (evtSource) { evtSource.close(); evtSource = null; }

  // Reset state
  document.getElementById('arena').innerHTML = '';
  cols = {}; lCounts = {L0:0,L1:0,L2:0,L3:0}; winnerName = null; startTs = Date.now();
  ['L0','L1','L2','L3'].forEach(c => document.getElementById('lc-'+c).textContent = '0');
  document.getElementById('go-btn').disabled = true;
  document.getElementById('race-status').textContent = '⟳ racing…';
  document.getElementById('status-bar').textContent = 'Race started — waiting for models…';

  const url = '/race?task=' + encodeURIComponent(task);
  evtSource = new EventSource(url);

  evtSource.addEventListener('init', e => {
    const d = JSON.parse(e.data);
    d.models.forEach((name, i) => {
      const color = COLORS[i % COLORS.length];
      cols[name] = createColumn(name, color);
    });
    document.getElementById('status-bar').textContent =
      `Racing ${d.models.length} models — task: "${task.slice(0,80)}"`;
  });

  evtSource.addEventListener('token', e => {
    const d = JSON.parse(e.data);
    if (!cols[d.model]) return;
    const body = cols[d.model].body;
    const span = document.createElement('span');
    span.className = 'token';
    span.textContent = d.token;
    body.appendChild(span);
    body.scrollTop = body.scrollHeight;
    cols[d.model].tokens++;
    cols[d.model].meta.textContent = `${cols[d.model].tokens} tok`;
  });

  evtSource.addEventListener('done', e => {
    const d = JSON.parse(e.data);
    if (!cols[d.model]) return;
    const elapsed = ((Date.now() - startTs)/1000).toFixed(2);
    const c = cols[d.model];
    const cls = lagrangianClass(d.lagrangian || 0);
    lCounts[cls]++;
    document.getElementById('lc-'+cls).textContent = lCounts[cls];

    // Score badge
    const badge = document.createElement('div');
    badge.className = 'done-overlay';
    const verdict = d.lagrangian === 0 ? 'PERMIT' : d.lagrangian <= 0.5 ? 'CONDITIONAL' : 'BLOCK';
    badge.innerHTML =
      `<span>ℒ=${(d.lagrangian||0).toFixed(2)}</span>` +
      `<span class="badge badge-${verdict}">${verdict}</span>` +
      `<span>${d.elapsed_ms ? (d.elapsed_ms/1000).toFixed(2)+'s' : elapsed+'s'}</span>` +
      `<span>score=${d.score ? d.score.toFixed(2) : '?'}</span>` +
      (d.winner ? `<span class="badge badge-WINNER">⚡ WINNER</span>` : '');
    c.wrap.appendChild(badge);
    c.meta.textContent = `${c.tokens} tok · done`;
    if (d.winner) {
      winnerName = d.model;
      c.header.style.background = '#0d2137';
      document.getElementById('race-status').textContent = `⚡ Winner: ${d.model.split('/').pop().slice(0,20)}`;
    }
  });

  evtSource.addEventListener('braid_token', e => {
    const d = JSON.parse(e.data);
    if (!cols['__braid__']) {
      cols['__braid__'] = createColumn('⬡ Braid Synthesis', '#e2b96f', true);
      document.getElementById('race-status').textContent = '⬡ braiding…';
    }
    const body = cols['__braid__'].body;
    const span = document.createElement('span');
    span.className = 'token';
    span.textContent = d.token;
    body.appendChild(span);
    body.scrollTop = body.scrollHeight;
    cols['__braid__'].tokens++;
    cols['__braid__'].meta.textContent = `${cols['__braid__'].tokens} tok`;
  });

  evtSource.addEventListener('braid_done', e => {
    const d = JSON.parse(e.data);
    if (!cols['__braid__']) return;
    const c = cols['__braid__'];
    const verdict = d.lagrangian === 0 ? 'PERMIT' : d.lagrangian <= 0.5 ? 'CONDITIONAL' : 'BLOCK';
    const badge = document.createElement('div');
    badge.className = 'done-overlay';
    badge.innerHTML =
      `<span style="color:#e2b96f;font-weight:700">⬡ BRAID</span>` +
      `<span>ℒ=${(d.lagrangian||0).toFixed(2)}</span>` +
      `<span class="badge badge-${verdict}">${verdict}</span>` +
      `<span>${d.tokens||0} tok</span>`;
    c.wrap.appendChild(badge);
    c.meta.textContent = `${c.tokens} tok · done`;
    document.getElementById('race-status').textContent = '⬡ braid complete';
  });

  evtSource.addEventListener('end', e => {
    const d = JSON.parse(e.data);
    document.getElementById('go-btn').disabled = false;
    document.getElementById('status-bar').textContent =
      `Race complete — winner: ${(d.winner||'?').split('/').pop()} ` +
      `· ${d.model_count} models · ${((Date.now()-startTs)/1000).toFixed(1)}s`;
    if (!d.winner) document.getElementById('race-status').textContent = 'done';
    evtSource.close(); evtSource = null;
  });

  evtSource.onerror = () => {
    document.getElementById('go-btn').disabled = false;
    document.getElementById('race-status').textContent = 'error';
    document.getElementById('status-bar').textContent = 'SSE connection error — is the server running?';
    if (evtSource) { evtSource.close(); evtSource = null; }
  };
}

function createColumn(name, color, isBraid) {
  const arena = document.getElementById('arena');
  const wrap = document.createElement('div');
  wrap.className = 'col-wrap';
  if (isBraid) {
    wrap.style.borderLeft = '2px solid #e2b96f';
    wrap.style.minWidth = '300px';
  }

  const hdr = document.createElement('div');
  hdr.className = 'col-header';
  const short = name.split('/').pop().split(':')[0].slice(0,22);
  const nameEl = document.createElement('span');
  nameEl.className = 'col-name';
  nameEl.style.color = color;
  nameEl.textContent = short;
  const meta = document.createElement('span');
  meta.className = 'col-meta';
  meta.textContent = '0 tok';
  hdr.appendChild(nameEl);
  hdr.appendChild(meta);

  const body = document.createElement('div');
  body.className = 'col-body';
  body.style.color = color;

  wrap.appendChild(hdr);
  wrap.appendChild(body);
  arena.appendChild(wrap);
  return { wrap, header: hdr, body, meta, tokens: 0 };
}

// Allow Enter key to start race
document.getElementById('task-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') startRace();
});
</script>
</body>
</html>"""


def _run_race_sse(task: str, send_sse) -> None:
    """
    Discover models, run supervise_race, and stream tokens as SSE events.
    Runs synchronously (blocks the handler thread) since HTTPServer is
    single-threaded per connection anyway.
    """
    import asyncio
    import threading

    import time

    try:
        from config import discover_and_warmup, OLLAMA_BASE
        from supervisor import score_reasoning, ModelStream, stream_model, _assign_colors
        from executor import parse_action_from_text
        from agent import SYSTEM_PROMPT
    except Exception as e:
        send_sse("end", json.dumps({"error": str(e), "winner": None, "model_count": 0}))
        return

    loop = asyncio.new_event_loop()
    race_done = threading.Event()
    result_holder = {}
    streams_holder = {}   # model_name -> ModelStream, populated async
    emitted = {}          # model_name -> int tokens already forwarded

    def run_loop():
        async def _race():
            # Discover models inside the loop (discover_and_warmup is async)
            models, hw = await discover_and_warmup(verbose=False)
            if not models:
                result_holder["error"] = "no models available"
                return

            model_names = [m.name for m in models]
            result_holder["model_names"] = model_names
            send_sse("init", json.dumps({"models": model_names}))

            _assign_colors(model_names)
            cancel_event = asyncio.Event()
            streams = {m.name: ModelStream(model_name=m.name, provider=m.provider) for m in models}
            streams_holder.update(streams)
            emitted.update({n: 0 for n in model_names})

            tasks = {
                m.name: asyncio.create_task(
                    stream_model(m.name, task, streams[m.name], cancel_event,
                                 ollama_base=OLLAMA_BASE,
                                 system_prompt=SYSTEM_PROMPT,
                                 live_output=False,
                                 provider_config=getattr(m, "provider_config", None),
                                 max_tokens=2048))
                for m in models
            }
            await asyncio.gather(*tasks.values(), return_exceptions=True)

            best = max(streams.values(),
                       key=lambda s: score_reasoning(s.text) if s.text else 0.0,
                       default=None)
            result_holder["streams"] = list(streams.values())
            if best and best.text:
                action = parse_action_from_text(best.text, best.model_name)
                result_holder["winner"] = action

        loop.run_until_complete(_race())
        race_done.set()

    t = threading.Thread(target=run_loop, daemon=True)
    t.start()

    # Poll streams mid-race and forward new tokens live
    while not race_done.is_set():
        time.sleep(0.04)
        for name, s in streams_holder.items():
            n = emitted.get(name, 0)
            new_tokens = s.tokens[n:]
            for tok in new_tokens:
                try:
                    send_sse("token", json.dumps({"model": name, "token": tok}))
                except Exception:
                    pass
            emitted[name] = n + len(new_tokens)

    # Drain any remaining tokens after race finished
    for name, s in streams_holder.items():
        n = emitted.get(name, 0)
        for tok in s.tokens[n:]:
            try:
                send_sse("token", json.dumps({"model": name, "token": tok}))
            except Exception:
                pass

    streams = result_holder.get("streams", [])
    winner_action = result_holder.get("winner")
    winner_name = winner_action.model_source if winner_action else None

    for s in streams:
        from supervisor import score_reasoning
        score = score_reasoning(s.text) if s.text else 0.0
        lagrangian = 0.0
        try:
            from compliance import infer_context
            from executor import parse_action_from_text
            action = parse_action_from_text(s.text, s.model_name) if s.text else None
            if action and action.payload:
                path = action.payload.get("command", action.payload.get("path", ""))
                ctx = infer_context(path, task)
                decision = evaluate(action.action_type, action.payload, ctx)
                lagrangian = decision.lagrangian_value
        except Exception:
            pass
        try:
            send_sse("done", json.dumps({
                "model": s.model_name,
                "score": score,
                "elapsed_ms": s.elapsed_ms,
                "lagrangian": lagrangian,
                "winner": s.model_name == winner_name,
                "error": s.error,
            }))
        except Exception:
            pass

    # Braid phase — synthesise all responses using the winner model
    if winner_name and streams:
        try:
            from supervisor import braid_responses
            from agent import SYSTEM_PROMPT as _SP

            braid_tokens = []

            async def _braid():
                async for tok in braid_responses(
                    streams, winner_action, task, _SP,
                    ollama_base=OLLAMA_BASE, max_tokens=1024,
                ):
                    braid_tokens.append(tok)
                    try:
                        send_sse("braid_token", json.dumps({"token": tok}))
                    except Exception:
                        break

            loop.run_until_complete(_braid())
            braid_text = "".join(braid_tokens)
            # Compliance check on braid's proposed action
            braid_lagrangian = 0.0
            try:
                braid_action = parse_action_from_text(braid_text, winner_name)
                if braid_action and braid_action.payload:
                    path = braid_action.payload.get("command", braid_action.payload.get("path", ""))
                    ctx = infer_context(path, task)
                    decision = evaluate(braid_action.action_type, braid_action.payload, ctx)
                    braid_lagrangian = decision.lagrangian_value
            except Exception:
                pass
            send_sse("braid_done", json.dumps({
                "model": winner_name,
                "lagrangian": braid_lagrangian,
                "tokens": len(braid_tokens),
            }))
        except Exception as e:
            send_sse("braid_done", json.dumps({"error": str(e), "model": winner_name}))

    try:
        send_sse("end", json.dumps({
            "winner": winner_name,
            "model_count": len(streams),
        }))
    except Exception:
        pass


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
