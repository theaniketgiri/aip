#!/usr/bin/env python3
"""
AIP Interactive Demo — Web-based GUI
Run: python app.py
Open: http://localhost:5050
"""

import sys
import json
import time
from pathlib import Path
from datetime import datetime, timezone

# Add project root
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import uvicorn

from aip_protocol import (
    AgentPassport,
    create_envelope,
    sign_envelope,
    verify_intent,
    RevocationStore,
)
from aip_protocol.crypto import public_key_to_b64
from aip_protocol.envelope import envelope_to_json

# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(title="AIP Interactive Demo")
store = RevocationStore()

# ─── Agent Registry ───────────────────────────────────────────────────────────

agents: dict[str, dict] = {}


def register_agent(name: str, domain: str, actions: list[str], denied: list[str], limit: float):
    passport = AgentPassport.create(
        domain=domain,
        agent_name=name,
        allowed_actions=actions,
        denied_actions=denied,
        monetary_limit_per_txn=limit,
    )
    agents[name] = {
        "passport": passport,
        "name": name,
        "domain": domain,
        "did": passport.agent_id,
        "public_key": public_key_to_b64(passport.public_key),
        "actions": actions,
        "denied": denied,
        "limit": limit,
        "status": "active",
    }
    return agents[name]


# Pre-register demo agents
register_agent("analyst-bot", "acme-capital.com", ["research", "analyze", "read_data"], ["delete_records", "trade"], 0)
register_agent("trading-bot", "acme-capital.com", ["trade", "analyze", "read_data"], ["delete_records"], 10000)
register_agent("audit-bot", "acme-capital.com", ["read_data", "generate_report"], ["trade", "delete_records", "transfer_funds"], 0)


# ─── API Models ───────────────────────────────────────────────────────────────

class VerifyRequest(BaseModel):
    agent_name: str
    action: str
    parameters: dict = {}


class RevokeRequest(BaseModel):
    agent_name: str
    reason: str = "manual_revocation"


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_PAGE


@app.get("/api/agents")
async def get_agents():
    result = []
    for name, info in agents.items():
        passport = info["passport"]
        is_revoked = store.is_revoked(passport.agent_id)
        is_suspended = store.is_suspended(passport.agent_id) if is_revoked else False
        result.append({
            "name": name,
            "domain": info["domain"],
            "did": info["did"],
            "public_key": info["public_key"][:32] + "...",
            "actions": info["actions"],
            "denied": info["denied"],
            "limit": info["limit"],
            "status": "suspended" if is_suspended else ("revoked" if is_revoked else "active"),
        })
    return result


@app.post("/api/verify")
async def verify_action(req: VerifyRequest):
    if req.agent_name not in agents:
        raise HTTPException(404, f"Agent '{req.agent_name}' not found")

    info = agents[req.agent_name]
    passport = info["passport"]

    start = time.perf_counter_ns()

    envelope = create_envelope(
        passport=passport,
        action=req.action,
        target="demo-system",
        parameters=req.parameters,
    )
    signed = sign_envelope(envelope, passport.private_key)
    result = verify_intent(
        envelope=signed,
        public_key=passport.public_key,
        revocation_store=store,
    )

    elapsed_us = (time.perf_counter_ns() - start) / 1000

    envelope_json = json.loads(envelope_to_json(signed, pretty=True))

    return {
        "valid": result.valid,
        "tier": result.tier_used.value,
        "errors": [e.value for e in result.errors],
        "detail": result.detail,
        "trust_score": result.trust_score,
        "verification_time_us": round(elapsed_us, 1),
        "agent_did": passport.agent_id,
        "action": req.action,
        "parameters": req.parameters,
        "envelope": envelope_json,
    }


@app.post("/api/revoke")
async def revoke_agent(req: RevokeRequest):
    if req.agent_name not in agents:
        raise HTTPException(404, f"Agent '{req.agent_name}' not found")
    passport = agents[req.agent_name]["passport"]
    store.revoke(
        agent_id=passport.agent_id,
        reason=req.reason,
        revoked_by=f"did:web:{agents[req.agent_name]['domain']}",
    )
    return {"status": "revoked", "agent": passport.agent_id, "reason": req.reason}


@app.post("/api/reinstate")
async def reinstate_agent(req: RevokeRequest):
    if req.agent_name not in agents:
        raise HTTPException(404, f"Agent '{req.agent_name}' not found")
    passport = agents[req.agent_name]["passport"]
    store.reinstate(agent_id=passport.agent_id)
    return {"status": "reinstated", "agent": passport.agent_id}


# ─── HTML Page ────────────────────────────────────────────────────────────────

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIP Interactive Demo — Agent Verification</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0a0f;--surface:#12121a;--surface2:#1a1a2e;--surface3:#22223a;
  --border:#2a2a40;--border-active:#4a4a6a;
  --text:#e4e4ef;--text-dim:#8888a0;--text-muted:#5a5a72;
  --green:#00e676;--green-bg:rgba(0,230,118,0.08);--green-border:rgba(0,230,118,0.2);
  --red:#ff1744;--red-bg:rgba(255,23,68,0.08);--red-border:rgba(255,23,68,0.2);
  --yellow:#ffea00;--yellow-bg:rgba(255,234,0,0.08);
  --blue:#448aff;--blue-bg:rgba(68,138,255,0.08);--blue-border:rgba(68,138,255,0.25);
  --cyan:#18ffff;--purple:#b388ff;
  --radius:12px;--radius-sm:8px;
}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}
.mono{font-family:'JetBrains Mono',monospace}

/* Header */
header{padding:32px 40px 24px;border-bottom:1px solid var(--border);background:linear-gradient(180deg,rgba(68,138,255,0.04) 0%,transparent 100%)}
header h1{font-size:28px;font-weight:700;letter-spacing:-0.5px}
header h1 span{color:var(--blue);font-weight:800}
header p{color:var(--text-dim);font-size:14px;margin-top:6px}

/* Layout */
.container{max-width:1400px;margin:0 auto;padding:32px 40px}
.grid{display:grid;grid-template-columns:380px 1fr;gap:32px;align-items:start}

/* Agent Cards */
.agents-panel h2{font-size:15px;font-weight:600;text-transform:uppercase;letter-spacing:1.5px;color:var(--text-dim);margin-bottom:16px}
.agent-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:12px;transition:all 0.3s ease;cursor:pointer;position:relative;overflow:hidden}
.agent-card::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--blue);transition:all 0.3s}
.agent-card.selected{border-color:var(--blue-border);background:var(--blue-bg)}
.agent-card.selected::before{background:var(--blue);box-shadow:0 0 12px var(--blue)}
.agent-card.revoked{opacity:0.6;border-color:var(--red-border)}
.agent-card.revoked::before{background:var(--red)}
.agent-card .name{font-size:16px;font-weight:600;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.agent-card .did{font-size:11px;color:var(--text-muted);font-family:'JetBrains Mono',monospace;margin-bottom:12px}
.agent-card .meta{display:flex;flex-wrap:wrap;gap:6px}
.tag{font-size:11px;padding:3px 8px;border-radius:4px;font-weight:500;font-family:'JetBrains Mono',monospace}
.tag.allowed{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}
.tag.denied{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}
.tag.limit{background:var(--yellow-bg);color:var(--yellow);border:1px solid rgba(255,234,0,0.2)}
.status-badge{font-size:10px;padding:2px 8px;border-radius:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
.status-badge.active{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}
.status-badge.revoked{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}

/* Right Panel */
.action-panel{display:flex;flex-direction:column;gap:24px}
.panel-section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px}
.panel-section h3{font-size:14px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);margin-bottom:16px;display:flex;align-items:center;gap:8px}

/* Action Builder */
.action-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}
.action-btn{padding:12px 16px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface2);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px;cursor:pointer;transition:all 0.2s;text-align:left;display:flex;align-items:center;gap:8px}
.action-btn:hover{border-color:var(--blue-border);background:var(--blue-bg);transform:translateY(-1px)}
.action-btn.active{border-color:var(--blue);background:var(--blue-bg);box-shadow:0 0 20px rgba(68,138,255,0.1)}
.action-btn .icon{font-size:16px}

/* Amount Input */
.amount-row{display:flex;gap:10px;align-items:center;margin-bottom:16px}
.amount-row label{font-size:13px;color:var(--text-dim);min-width:60px}
.amount-input{flex:1;padding:10px 14px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface2);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:14px;outline:none;transition:border-color 0.2s}
.amount-input:focus{border-color:var(--blue)}

/* Verify Button */
.verify-btn{width:100%;padding:14px;border-radius:var(--radius-sm);border:none;background:linear-gradient(135deg,#448aff,#2979ff);color:white;font-family:'Inter',sans-serif;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.3s;letter-spacing:0.3px}
.verify-btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(68,138,255,0.3)}
.verify-btn:active{transform:translateY(0)}
.verify-btn:disabled{opacity:0.4;cursor:not-allowed;transform:none}

/* Kill Switch */
.kill-switch-area{display:flex;gap:10px}
.kill-btn{flex:1;padding:12px;border-radius:var(--radius-sm);border:1px solid var(--red-border);background:var(--red-bg);color:var(--red);font-family:'Inter',sans-serif;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.3s}
.kill-btn:hover{background:var(--red);color:white;box-shadow:0 0 30px rgba(255,23,68,0.3)}
.reinstate-btn{flex:1;padding:12px;border-radius:var(--radius-sm);border:1px solid var(--green-border);background:var(--green-bg);color:var(--green);font-family:'Inter',sans-serif;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.3s}
.reinstate-btn:hover{background:var(--green);color:#000;box-shadow:0 0 30px rgba(0,230,118,0.3)}

/* Verification Result */
.result-card{border-radius:var(--radius);padding:20px;animation:slideIn 0.4s ease;margin-bottom:12px;position:relative;overflow:hidden}
.result-card::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%}
.result-card.pass{background:var(--green-bg);border:1px solid var(--green-border)}
.result-card.pass::before{background:var(--green);box-shadow:0 0 8px var(--green)}
.result-card.fail{background:var(--red-bg);border:1px solid var(--red-border)}
.result-card.fail::before{background:var(--red);box-shadow:0 0 8px var(--red)}
.result-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.result-status{font-size:18px;font-weight:700;display:flex;align-items:center;gap:8px}
.result-time{font-size:12px;color:var(--text-dim);font-family:'JetBrains Mono',monospace}
.result-details{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.result-detail{font-size:12px}
.result-detail .label{color:var(--text-muted);margin-bottom:2px}
.result-detail .value{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text)}

/* Envelope Viewer */
.envelope-toggle{font-size:12px;color:var(--blue);cursor:pointer;margin-top:10px;font-weight:500;display:flex;align-items:center;gap:4px}
.envelope-toggle:hover{text-decoration:underline}
.envelope-viewer{margin-top:10px;padding:14px;background:var(--bg);border-radius:var(--radius-sm);border:1px solid var(--border);overflow-x:auto;display:none}
.envelope-viewer.open{display:block;animation:slideIn 0.3s ease}
.envelope-viewer pre{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--cyan);line-height:1.5;white-space:pre-wrap}

/* Log */
.log-area{max-height:600px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border) transparent}
.log-empty{text-align:center;padding:40px;color:var(--text-muted);font-size:14px}
.log-empty .icon{font-size:32px;margin-bottom:12px;display:block}

/* Animations */
@keyframes slideIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
.pulse{animation:pulse 1.5s infinite}

/* Scrollbar */
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

/* Responsive */
@media(max-width:900px){.grid{grid-template-columns:1fr}.action-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<header>
  <h1><span>AIP</span> Interactive Demo</h1>
  <p>Agent Intent Protocol — Identity, verification, and kill-switch for AI agents. Click an agent, pick an action, verify.</p>
</header>

<div class="container">
<div class="grid">
  <!-- Left: Agent Cards -->
  <div class="agents-panel">
    <h2>🤖 Agent Passports</h2>
    <div id="agents-list"></div>

    <div class="panel-section" style="margin-top:16px">
      <h3>🔴 Kill Switch</h3>
      <div class="kill-switch-area">
        <button class="kill-btn" onclick="killAgent()">⚠ Revoke Agent</button>
        <button class="reinstate-btn" onclick="reinstateAgent()">✓ Reinstate</button>
      </div>
    </div>
  </div>

  <!-- Right: Action Builder + Results -->
  <div class="action-panel">
    <div class="panel-section">
      <h3>⚡ Action Builder</h3>
      <div id="no-agent-msg" style="color:var(--text-muted);font-size:14px;text-align:center;padding:20px">
        ← Select an agent to begin
      </div>
      <div id="action-builder" style="display:none">
        <div class="action-grid" id="action-buttons"></div>
        <div class="amount-row" id="amount-row" style="display:none">
          <label>Amount $</label>
          <input type="number" class="amount-input" id="amount-input" value="5000" placeholder="Enter amount">
        </div>
        <button class="verify-btn" id="verify-btn" onclick="runVerification()" disabled>
          Sign & Verify Intent
        </button>
      </div>
    </div>

    <div class="panel-section">
      <h3>📋 Verification Log</h3>
      <div class="log-area" id="log-area">
        <div class="log-empty">
          <span class="icon">🔐</span>
          Run a verification to see results here
        </div>
      </div>
    </div>
  </div>
</div>
</div>

<script>
let selectedAgent = null;
let selectedAction = null;
let agentsData = [];
let logStarted = false;

const ACTIONS_CONFIG = {
  "research":        { icon: "🔍", label: "Research", monetary: false },
  "analyze":         { icon: "📊", label: "Analyze", monetary: false },
  "read_data":       { icon: "📖", label: "Read Data", monetary: false },
  "trade":           { icon: "📈", label: "Trade", monetary: true },
  "generate_report": { icon: "📄", label: "Generate Report", monetary: false },
  "delete_records":  { icon: "🗑️", label: "Delete Records", monetary: false },
  "transfer_funds":  { icon: "💸", label: "Transfer Funds", monetary: true },
  "send_email":      { icon: "📧", label: "Send Email", monetary: false },
};

async function loadAgents() {
  const res = await fetch("/api/agents");
  agentsData = await res.json();
  renderAgents();
}

function renderAgents() {
  const container = document.getElementById("agents-list");
  container.innerHTML = agentsData.map(a => {
    const isSelected = selectedAgent === a.name;
    const cls = [
      "agent-card",
      isSelected ? "selected" : "",
      a.status === "revoked" ? "revoked" : ""
    ].filter(Boolean).join(" ");

    const statusCls = a.status === "active" ? "active" : "revoked";
    const statusLabel = a.status === "active" ? "● Active" : "⊘ Revoked";

    return `
      <div class="${cls}" onclick="selectAgent('${a.name}')">
        <div class="name">
          ${a.name}
          <span class="status-badge ${statusCls}">${statusLabel}</span>
        </div>
        <div class="did">${a.did}</div>
        <div class="meta">
          ${a.actions.map(act => `<span class="tag allowed">${act}</span>`).join("")}
          ${a.denied.map(act => `<span class="tag denied">✗ ${act}</span>`).join("")}
          ${a.limit > 0 ? `<span class="tag limit">$${a.limit.toLocaleString()}/txn</span>` : ""}
        </div>
      </div>
    `;
  }).join("");
}

function selectAgent(name) {
  selectedAgent = name;
  selectedAction = null;
  renderAgents();

  document.getElementById("no-agent-msg").style.display = "none";
  document.getElementById("action-builder").style.display = "block";

  const agent = agentsData.find(a => a.name === name);
  // Show ALL possible actions (allowed + denied + some extras)
  const allActions = [...new Set([...agent.actions, ...agent.denied, "trade", "delete_records", "transfer_funds"])];

  const container = document.getElementById("action-buttons");
  container.innerHTML = allActions.map(action => {
    const cfg = ACTIONS_CONFIG[action] || { icon: "⚙️", label: action, monetary: false };
    const isDenied = agent.denied.includes(action);
    const isAllowed = agent.actions.includes(action);
    const style = isDenied ? 'border-color:var(--red-border);color:var(--red)' : (isAllowed ? '' : 'border-color:var(--yellow);color:var(--yellow)');
    return `<button class="action-btn" onclick="selectAction('${action}')" id="btn-${action}" style="${style}">
      <span class="icon">${cfg.icon}</span> ${cfg.label}
    </button>`;
  }).join("");

  document.getElementById("verify-btn").disabled = true;
  document.getElementById("amount-row").style.display = "none";
}

function selectAction(action) {
  selectedAction = action;
  // Highlight selected
  document.querySelectorAll(".action-btn").forEach(b => b.classList.remove("active"));
  document.getElementById(`btn-${action}`).classList.add("active");
  document.getElementById("verify-btn").disabled = false;

  const cfg = ACTIONS_CONFIG[action] || { monetary: false };
  document.getElementById("amount-row").style.display = cfg.monetary ? "flex" : "none";
}

async function runVerification() {
  if (!selectedAgent || !selectedAction) return;

  const btn = document.getElementById("verify-btn");
  btn.disabled = true;
  btn.textContent = "Verifying...";

  const params = {};
  const cfg = ACTIONS_CONFIG[selectedAction] || {};
  if (cfg.monetary) {
    params.amount = parseFloat(document.getElementById("amount-input").value) || 0;
  }

  try {
    const res = await fetch("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agent_name: selectedAgent,
        action: selectedAction,
        parameters: params,
      }),
    });
    const data = await res.json();
    addResult(data);
    await loadAgents(); // refresh status
  } catch(e) {
    console.error(e);
  }

  btn.disabled = false;
  btn.textContent = "Sign & Verify Intent";
}

function addResult(data) {
  const log = document.getElementById("log-area");
  if (!logStarted) {
    log.innerHTML = "";
    logStarted = true;
  }

  const cls = data.valid ? "pass" : "fail";
  const statusIcon = data.valid ? "✅" : "❌";
  const statusText = data.valid ? "VERIFIED" : "BLOCKED";
  const statusColor = data.valid ? "var(--green)" : "var(--red)";
  const amountStr = data.parameters.amount ? ` — $${data.parameters.amount.toLocaleString()}` : "";
  const errStr = data.errors.length ? data.errors.join(", ") : "—";
  const id = "env-" + Date.now();

  const card = document.createElement("div");
  card.className = `result-card ${cls}`;
  card.innerHTML = `
    <div class="result-header">
      <div class="result-status" style="color:${statusColor}">
        ${statusIcon} ${statusText}
      </div>
      <div class="result-time">${data.verification_time_us.toLocaleString()}μs</div>
    </div>
    <div class="result-details">
      <div class="result-detail">
        <div class="label">Agent</div>
        <div class="value">${data.agent_did.split(":").pop()}</div>
      </div>
      <div class="result-detail">
        <div class="label">Action</div>
        <div class="value">${data.action}${amountStr}</div>
      </div>
      <div class="result-detail">
        <div class="label">Tier</div>
        <div class="value">${data.tier}</div>
      </div>
      <div class="result-detail">
        <div class="label">${data.valid ? "Detail" : "Error"}</div>
        <div class="value" style="color:${statusColor}">${data.valid ? data.detail : errStr}</div>
      </div>
    </div>
    <div class="envelope-toggle" onclick="toggleEnvelope('${id}')">▶ View Signed Envelope (JSON)</div>
    <div class="envelope-viewer" id="${id}">
      <pre>${JSON.stringify(data.envelope, null, 2)}</pre>
    </div>
  `;

  log.prepend(card);
}

function toggleEnvelope(id) {
  const el = document.getElementById(id);
  el.classList.toggle("open");
  const toggle = el.previousElementSibling;
  toggle.textContent = el.classList.contains("open") ? "▼ Hide Envelope" : "▶ View Signed Envelope (JSON)";
}

async function killAgent() {
  if (!selectedAgent) return;
  if (!confirm(`Revoke ${selectedAgent}? This will block ALL actions.`)) return;

  await fetch("/api/revoke", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_name: selectedAgent, reason: "manual_kill_switch" }),
  });

  await loadAgents();
  renderAgents();
}

async function reinstateAgent() {
  if (!selectedAgent) return;

  await fetch("/api/reinstate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_name: selectedAgent }),
  });

  await loadAgents();
  renderAgents();
}

// Init
loadAgents();
</script>
</body>
</html>"""


if __name__ == "__main__":
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║  AIP Interactive Demo                        ║")
    print("  ║  Open: http://localhost:5050                 ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()
    uvicorn.run(app, host="0.0.0.0", port=5050, log_level="warning")
