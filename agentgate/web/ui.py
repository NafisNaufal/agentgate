"""The Demo Console page: one embedded HTML document, no build step, no CDN.

Kept as a single string so the console has no static-file serving and no asset paths
to get wrong. The CSP in app.py permits inline style and script and nothing external.
"""

PAGE = r"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentGate Demo Console</title>
<style>
  :root{
    --bg:#0f1115; --panel:#171a21; --line:#272c36; --text:#e6e9ef; --dim:#9aa4b2;
    --allow:#3fb950; --block:#f85149; --approval:#d29922; --sanitize:#39c5cf; --ask:#bc8cff;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
  header{display:flex;align-items:center;gap:1rem;padding:.9rem 1.25rem;border-bottom:1px solid var(--line);flex-wrap:wrap}
  header h1{font-size:15px;margin:0;letter-spacing:.02em}
  header .sp{flex:1}
  main{max-width:1100px;margin:0 auto;padding:1.25rem;display:grid;gap:1.25rem}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1rem 1.1rem}
  .panel h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin:0 0 .8rem}
  .row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
  button{background:#232833;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:.45rem .8rem;font:inherit;cursor:pointer}
  button:hover:not(:disabled){border-color:#3a414f}
  button:disabled{opacity:.45;cursor:not-allowed}
  button.primary{background:#1f6feb;border-color:#1f6feb}
  button.danger{background:#3d1d1f;border-color:#5c2b2e}
  input,textarea,select{background:#0d1017;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:.5rem .65rem;font:inherit;width:100%}
  textarea{resize:vertical;min-height:60px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
  .scroll{overflow-x:auto}
  .tag{display:inline-block;padding:.1rem .45rem;border-radius:5px;font-size:11px;font-weight:700;letter-spacing:.03em}
  .ALLOW{background:rgba(63,185,80,.15);color:var(--allow)}
  .BLOCK{background:rgba(248,81,73,.15);color:var(--block)}
  .NEED_APPROVAL{background:rgba(210,153,34,.15);color:var(--approval)}
  .SANITIZE{background:rgba(57,197,207,.15);color:var(--sanitize)}
  .ASK_USER{background:rgba(188,140,255,.15);color:var(--ask)}
  .dim{color:var(--dim)}
  .step{border:1px solid var(--line);border-radius:8px;padding:.7rem .85rem;margin-bottom:.6rem;background:#12151b}
  .step ul{margin:.45rem 0 0;padding-left:1.1rem}
  .step li{color:var(--dim)}
  code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
  pre{background:#0d1017;border:1px solid var(--line);border-radius:6px;padding:.55rem;overflow:auto;margin:.5rem 0 0}
  .note{border-left:3px solid var(--approval);padding:.5rem .75rem;background:rgba(210,153,34,.07);border-radius:0 6px 6px 0;color:var(--dim)}
  .err{border-left-color:var(--block);background:rgba(248,81,73,.07)}
  .login{max-width:22rem;margin:14vh auto}
  .hide{display:none}
  .dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:.35rem}
  .on{background:var(--allow)} .off{background:var(--block)} .warn{background:var(--approval)}
</style>

<div id="loginView" class="login panel">
  <h2>AgentGate Demo Console</h2>
  <p class="dim">This console can run guarded scenarios and connect a Gmail account. It requires the shared password.</p>
  <div class="row" style="margin-top:.8rem">
    <input id="pw" type="password" placeholder="Password" autocomplete="current-password">
  </div>
  <div class="row" style="margin-top:.6rem">
    <button class="primary" onclick="login()">Sign in</button>
    <span id="loginMsg" class="dim"></span>
  </div>
</div>

<div id="appView" class="hide">
  <header>
    <h1>AgentGate <span class="dim">Demo Console</span></h1>
    <span class="sp"></span>
    <span id="hdrModel" class="dim"></span>
    <button onclick="logout()">Sign out</button>
  </header>
  <main>
    <section class="panel">
      <h2>Status</h2>
      <div id="status" class="dim">loading…</div>
    </section>

    <section class="panel">
      <h2>Gmail</h2>
      <div id="gmail" class="dim">loading…</div>
    </section>

    <section class="panel">
      <h2>Run</h2>
      <div class="row">
        <select id="scenario" style="max-width:26rem"></select>
        <button class="primary" id="runScenario" onclick="runScenario()">Run scenario</button>
      </div>
      <p class="dim" id="scenarioHint" style="margin:.5rem 0 0"></p>
      <div style="margin-top:.9rem">
        <textarea id="task" placeholder="Or describe a task in natural language…"></textarea>
        <div class="row" style="margin-top:.5rem">
          <button id="runChat" onclick="runChat()">Run task</button>
          <span id="chatHint" class="dim"></span>
        </div>
      </div>
      <p class="dim" style="margin:.9rem 0 0">Every run is dry-run: the console evaluates and routes, and never executes an action.</p>
    </section>

    <section class="panel">
      <h2>DA evaluation</h2>
      <div class="row">
        <button id="runEval" onclick="runEval()">Run all cases</button>
        <input id="evalOnly" placeholder="or filter by id, e.g. DATA" style="max-width:16rem">
        <span id="evalHint" class="dim"></span>
      </div>
      <p class="dim" style="margin:.5rem 0 0">
        DA's independently-authored cases, replayed through the live engine. Disagreements
        are reported as mismatches, not reconciled — that is the point of test data the
        detector authors did not write.
      </p>
      <div id="evalOut" class="scroll" style="margin-top:.8rem"></div>
    </section>

    <section class="panel">
      <h2>Decisions <span id="jobMeta" class="dim" style="text-transform:none;letter-spacing:0"></span></h2>
      <div id="steps" class="dim">No run yet.</div>
    </section>

    <section class="panel">
      <h2>Approval queue</h2>
      <div id="approvals" class="dim">loading…</div>
    </section>

    <section class="panel">
      <h2>Audit log</h2>
      <div id="audit" class="scroll dim">loading…</div>
    </section>
  </main>
</div>

<script>
let CSRF = "";
let pollTimer = null, currentJob = null;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

async function api(path, opts = {}) {
  const o = Object.assign({headers: {}}, opts);
  if (o.method === "POST") {
    o.headers["Content-Type"] = "application/json";
    o.headers["X-AgentGate-CSRF"] = CSRF;
  }
  const r = await fetch(path, o);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { show(false); throw new Error("session expired"); }
  if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
  return data;
}

function show(authed) {
  $("loginView").classList.toggle("hide", authed);
  $("appView").classList.toggle("hide", !authed);
}

async function login() {
  $("loginMsg").textContent = "checking…";
  try {
    const r = await api("/api/login", {method: "POST", body: JSON.stringify({password: $("pw").value})});
    CSRF = r.csrf; $("pw").value = ""; $("loginMsg").textContent = "";
    show(true); boot();
  } catch (e) { $("loginMsg").textContent = e.message; }
}
async function logout() { try { await api("/api/logout", {method: "POST"}); } catch {} CSRF = ""; show(false); }

async function boot() { await Promise.all([loadStatus(), loadScenarios(), loadApprovals(), loadAudit()]); }

async function loadStatus() {
  const s = await api("/api/status");
  if (s.csrf) CSRF = s.csrf;
  $("hdrModel").textContent = s.detector_model;
  const a = s.audit;
  const counts = a.available
    ? Object.entries(a.by_decision).map(([k, v]) => `<span class="tag ${esc(k)}">${esc(k)} ${v}</span>`).join(" ") || '<span class="dim">no actions yet</span>'
    : `<span class="dim">unavailable — ${esc(a.detail)}</span>`;
  $("status").innerHTML =
    `<div class="row"><span><span class="dot ${a.available?"on":"off"}"></span>Audit store</span>
     <span><span class="dot ${s.planner_available?"on":"warn"}"></span>LLM planner ${s.planner_available?"configured":"not configured"}</span>
     <span class="dim">${esc(s.tools.length)} registered tools</span></div>
     <div style="margin-top:.6rem">${counts}</div>`;
  $("chatHint").textContent = s.planner_available ? "" : "Set AGENTGATE_LLM_API_KEY to enable free-text tasks.";
  $("runChat").disabled = !s.planner_available;
  $("evalHint").textContent = s.eval_cases ? `${s.eval_cases} cases · ~400s each on this box` : "eval set not found";
  renderGmail(s);
  // A reload must not orphan a run that is still going server-side.
  if (s.active_job && s.active_job !== currentJob) {
    currentJob = s.active_job;
    $("runScenario").disabled = $("runEval").disabled = true;
    poll();
  }
}

function renderGmail(s) {
  const g = s.gmail;
  let html = "";
  if (!g.configured) {
    html = `<div class="note">${esc(g.detail)}</div>`;
  } else if (g.connected) {
    html = `<div class="row"><span><span class="dot on"></span>Connected</span>
      <span class="dim">${esc((g.scopes||[]).join(", "))}</span></div>
      <div class="dim" style="margin-top:.4rem">Access token valid ${esc(g.access_token_valid_for)}s; refresh ${g.can_refresh ? "available" : "missing"}.</div>
      <div class="row" style="margin-top:.6rem"><button class="danger" onclick="gmailDisconnect()">Disconnect</button></div>`;
  } else if (!s.oauth_capable_origin) {
    html = `<div class="note">Google only allows http:// OAuth redirects to localhost.
      This console is at <code>${esc(s.origin)}</code>. Reach it through an SSH tunnel
      (<code>ssh -L 8080:127.0.0.1:8080 …</code>) and connect from
      <code>http://localhost:8080</code>, or serve it over HTTPS.</div>`;
  } else {
    html = `<div class="row"><span><span class="dot off"></span>Not connected</span>
      <button class="primary" onclick="gmailConnect()">Connect Gmail</button></div>`;
  }
  $("gmail").innerHTML = html;
}

async function gmailConnect() {
  try { const r = await api("/api/gmail/connect", {method: "POST"}); window.location.href = r.url; }
  catch (e) { $("gmail").innerHTML = `<div class="note err">${esc(e.message)}</div>`; }
}
async function gmailDisconnect() {
  try { await api("/api/gmail/disconnect", {method: "POST"}); loadStatus(); }
  catch (e) { $("gmail").innerHTML = `<div class="note err">${esc(e.message)}</div>`; }
}

async function loadScenarios() {
  const {scenarios} = await api("/api/scenarios");
  $("scenario").innerHTML = scenarios.map(s => `<option value="${esc(s.name)}">${esc(s.title)}</option>`).join("");
  window._scenarios = scenarios;
  hintScenario();
  $("scenario").onchange = hintScenario;
}
function hintScenario() {
  const s = (window._scenarios || []).find(x => x.name === $("scenario").value);
  $("scenarioHint").textContent = s ? `${s.steps} steps · expected: ${s.expected}` : "";
}

async function runEval() {
  const only = $("evalOnly").value.trim();
  $("runEval").disabled = true;
  $("evalOut").innerHTML = '<span class="dim">starting…</span>';
  try {
    const r = await api("/api/eval", {method: "POST", body: JSON.stringify({only})});
    currentJob = r.job.id; poll();
  } catch (e) {
    $("evalOut").innerHTML = `<div class="note err">${esc(e.message)}</div>`;
    $("runEval").disabled = false;
  }
}

function renderEval(job) {
  const rows = job.steps;
  const done = rows.length, total = job.total || 0;
  const matched = rows.filter(r => r.match).length;
  const pct = total ? Math.round(done / total * 100) : 0;
  const head = job.status === "running"
    ? `case ${done}/${total} (${pct}%) · ${matched}/${done} matching · ${Math.round(job.elapsed)}s elapsed`
    : `${matched}/${done} match the expected decision · ${Math.round(job.elapsed)}s`;
  if (!done) {
    $("evalOut").innerHTML = `<span class="dim">evaluating case 1/${total}… roughly 400s each without a GPU.</span>`;
    return;
  }
  const body = rows.map(r => `<tr>
    <td><code>${esc(r.id)}</code></td>
    <td>${esc(r.title)}</td>
    <td><span class="tag ${esc(r.expected)}">${esc(r.expected)}</span></td>
    <td><span class="tag ${esc(r.actual)}">${esc(r.actual)}</span></td>
    <td class="dim">${esc(r.expected_risk)} → ${esc(r.actual_risk)}</td>
    <td>${r.match ? '<span class="dim">match</span>' : '<b style="color:var(--block)">MISMATCH</b>'}</td>
  </tr>`).join("");
  const misses = rows.filter(r => !r.match).map(r => `<div class="step">
    <div class="row"><code>${esc(r.id)}</code> <span class="dim">${esc(r.title)}</span></div>
    <div class="dim">expected ${esc(r.expected)} (${esc(r.expected_risk)}), got ${esc(r.actual)} (${esc(r.actual_risk)})</div>
    <ul>${r.reasons.map(x => `<li>${esc(x)}</li>`).join("")}</ul>
    ${r.triggered_policies.length ? `<div class="dim">policies: ${esc(r.triggered_policies.join(", "))}</div>` : ""}
  </div>`).join("");
  $("evalOut").innerHTML = `<div class="dim" style="margin-bottom:.5rem">${head}</div>
    <table><tr><th>ID</th><th>Case</th><th>Expected</th><th>Actual</th><th>Risk</th><th></th></tr>${body}</table>
    ${misses ? `<h2 style="margin-top:1rem">Mismatch detail</h2>${misses}` : ""}`;
}

async function runScenario() { await startRun({scenario: $("scenario").value}); }
async function runChat() {
  const task = $("task").value.trim();
  if (!task) return;
  await startRun({task});
}

async function startRun(body) {
  $("runScenario").disabled = $("runChat").disabled = true;
  $("steps").innerHTML = '<span class="dim">starting…</span>';
  try {
    const r = await api("/api/run", {method: "POST", body: JSON.stringify(body)});
    currentJob = r.job.id;
    poll();
  } catch (e) {
    $("steps").innerHTML = `<div class="note err">${esc(e.message)}</div>`;
    $("runScenario").disabled = false; loadStatus();
  }
}

function poll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    if (!currentJob) return;
    try {
      const job = await api("/api/jobs/" + currentJob);
      if (job.kind === "eval") renderEval(job); else renderJob(job);
      if (job.status === "running" || job.status === "queued") { poll(); }
      else {
        $("runScenario").disabled = false; $("runEval").disabled = false;
        loadStatus(); loadApprovals(); loadAudit();
      }
    } catch (e) { $("steps").innerHTML = `<div class="note err">${esc(e.message)}</div>`; }
  }, 2000);
}

function renderJob(job) {
  $("jobMeta").textContent = `— ${job.label} · ${job.status} · ${job.elapsed}s`;
  if (job.error) { $("steps").innerHTML = `<div class="note err">${esc(job.error)}</div>`; return; }
  if (!job.steps.length) {
    $("steps").innerHTML = `<span class="dim">evaluating… six detector calls per action, this is slow on CPU-only inference.</span>`;
    return;
  }
  $("steps").innerHTML = job.steps.map(s => {
    if (s.rejected_reason) {
      return `<div class="step"><span class="tag BLOCK">REJECTED</span> <code>${esc(s.action_type)}</code>
        <div class="dim">${esc(s.rejected_reason)}</div></div>`;
    }
    const ents = s.sensitive_entities.map(e => `${esc(e.kind)}·${esc(e.severity)}`).join(", ");
    return `<div class="step">
      <div class="row"><span class="tag ${esc(s.decision)}">${esc(s.decision)}</span>
        <code>${esc(s.action_type)}</code>
        <span class="dim">risk ${esc(s.risk_level)} · score ${esc(s.risk_score)} · ${Math.round(s.eval_ms)}ms</span></div>
      <ul>${s.reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul>
      ${s.triggered_policies.length ? `<div class="dim" style="margin-top:.35rem">policies: ${esc(s.triggered_policies.join(", "))}</div>` : ""}
      ${ents ? `<div class="dim">entities: ${ents}</div>` : ""}
      ${s.sanitized_payload ? `<pre>${esc(s.sanitized_payload)}</pre>` : ""}
      ${s.outcome ? `<div class="dim" style="margin-top:.35rem">${esc(s.outcome.status)} — ${esc(s.outcome.message)}</div>` : ""}
    </div>`;
  }).join("") + (job.final_message ? `<div class="dim">Result: ${esc(job.result_status)} — ${esc(job.final_message)}</div>` : "");
}

async function loadApprovals() {
  const {approvals} = await api("/api/approvals");
  if (!approvals.length) { $("approvals").textContent = "Nothing waiting for review."; return; }
  $("approvals").innerHTML = approvals.map(a => `<div class="step">
    <div class="row"><span class="tag NEED_APPROVAL">NEED_APPROVAL</span>
      <code>${esc(a.action_type)}${a.tool_name ? " · " + esc(a.tool_name) : ""}</code>
      <span class="dim">risk ${esc(a.risk_level)} · ${esc(a.risk_score)}</span></div>
    <ul>${(a.reasons || []).map(r => `<li>${esc(r)}</li>`).join("")}</ul>
    ${a.sanitized_payload ? `<pre>${esc(a.sanitized_payload)}</pre>` : ""}
    <div class="row" style="margin-top:.55rem">
      <button onclick="review('${esc(a.audit_id)}','approved')">Approve</button>
      <button class="danger" onclick="review('${esc(a.audit_id)}','rejected')">Reject</button>
      <span class="dim">records the reviewer decision; it does not execute the action</span>
    </div></div>`).join("");
}

async function review(id, verdict) {
  try { await api("/api/review", {method: "POST", body: JSON.stringify({audit_id: id, verdict})}); }
  catch (e) { alert(e.message); }
  loadApprovals(); loadAudit();
}

async function loadAudit() {
  const {rows} = await api("/api/audit?limit=50");
  if (!rows.length) { $("audit").textContent = "No audit rows yet."; return; }
  $("audit").innerHTML = `<table><tr><th>When</th><th>Stage</th><th>Action</th><th>Decision</th>
    <th>Risk</th><th>Execution</th><th>Reviewer</th></tr>` + rows.map(r => `<tr>
    <td class="dim">${esc(new Date(r.at * 1000).toLocaleTimeString())}</td>
    <td class="dim">${esc(r.stage)}</td>
    <td><code>${esc(r.action_type)}${r.tool_name ? " · " + esc(r.tool_name) : ""}</code></td>
    <td><span class="tag ${esc(r.decision)}">${esc(r.decision)}</span></td>
    <td class="dim">${esc(r.risk_level)} ${esc(r.risk_score)}</td>
    <td class="dim">${esc(r.execution_status)}</td>
    <td class="dim">${esc(r.reviewer_status)}</td></tr>`).join("") + `</table>`;
}

$("pw").addEventListener("keydown", e => { if (e.key === "Enter") login(); });
(async () => { try { const s = await api("/api/status"); CSRF = s.csrf || ""; show(true); boot(); } catch { show(false); } })();
</script>
</html>
"""
