# AgentGate Quickstart

Two ways to try it. **Run it locally** if you want to change code or iterate — on an
Apple Silicon Mac the detector model is GPU-accelerated and roughly an order of
magnitude faster than the shared server, which is CPU-only. **Use the shared console**
if you only want to see it work.

---

## A. Run it locally

### 1. Prerequisites

| Need | Why | Install |
|---|---|---|
| Python 3.10+ | the engine | `python3 --version` |
| Postgres | audit log is mandatory (PRD F14) | `brew install postgresql@16 && brew services start postgresql@16` |
| Ollama | runs the six detectors | https://ollama.com/download |

### 2. Install

```bash
git clone https://github.com/NafisNaufal/agentgate.git
cd agentgate
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

### 3. Database and model

```bash
createdb agentgate
ollama pull qwen2.5:7b        # ~4.7 GB, one time
```

Leave `ollama serve` running in another terminal if it isn't already a service.

### 4. Configure

```bash
export AGENTGATE_AUDIT_DSN="postgresql://$(whoami)@localhost:5432/agentgate"
export OLLAMA_HOST=http://localhost:11434
export AGENTGATE_LLM_DETECTOR_MODEL=qwen2.5:7b
export AGENTGATE_LLM_DETECTOR_TIMEOUT=600
```

AgentGate does not read `.env` automatically — export these, or put them in a file and
`source` it. Copy `.env.example` for the full list.

`AGENTGATE_AUDIT_DSN` is required. Auditing is mandatory and fails loudly: an unset or
unreachable DSN stops the engine at startup rather than producing decisions nobody
recorded. If you see `Audit store unavailable`, that is the design working.

### 5. Verify

```bash
./scripts/setup.sh                                   # checks all five prerequisites
.venv/bin/python -m unittest discover -s tests       # 182 tests, no network needed
```

### 6. Run something

```bash
.venv/bin/python -m agentgate list                   # the four scenarios
.venv/bin/python -m agentgate tools                  # registered tool catalog

.venv/bin/python -m agentgate run booking_message    # ALLOW -> SANITIZE -> NEED_APPROVAL
.venv/bin/python -m agentgate run sensitive_code     # BLOCK on secrets
.venv/bin/python -m agentgate run ambiguous_cleanup  # ASK_USER on low confidence
.venv/bin/python -m agentgate run productivity_archive
```

Every run is dry-run. Nothing executes unless you pass `--execute`.

Evaluate a single ad-hoc action:

```bash
.venv/bin/python -m agentgate eval API_CALL \
  --tool-name gmail_send --target-system Gmail \
  --payload "Hi john@example.com, pay at http://pay.example.com/invoice"
```

Add `--json` to `run` or `eval` for structured output.

### 7. The web console (optional)

```bash
export AGENTGATE_WEB_PASSWORD='pick-something-long'
.venv/bin/python -m agentgate serve
```

Open http://localhost:8080. Scenario runner, free-text task box, live decision cards,
approval queue and audit log.

---

## B. Use the shared console on the dev server

Needs SSH access to the dev box. Ask Nafis for the console password.

```bash
ssh -f -N -L 8080:127.0.0.1:8080 -p 11096 dev@proxy.bccdev.id
open http://localhost:8080
```

The tunnel is required, not a convenience: the provider only forwards SSH to that host,
so nothing else reaches it. It is also what makes Gmail OAuth work, since Google only
accepts plain-`http` redirects to `localhost`.

Two things to expect there: the box has **no GPU**, so one action takes roughly 400
seconds (six detector calls, run sequentially), and runs are serialized — if someone
else is running, yours queues.

---

## What you are looking at

```
task -> planner -> proposal -> ActionRequest -> DecisionEngine -> audit -> router -> executor
```

The planner proposes; AgentGate decides. Five possible decisions:

| Decision | Meaning |
|---|---|
| `ALLOW` | safe to execute |
| `SANITIZE` | execute, but only the redacted payload |
| `NEED_APPROVAL` | a human reviews before anything runs |
| `ASK_USER` | intent is ambiguous; clarify before deciding |
| `BLOCK` | never execute |

Worth knowing while you read output:

- **Two different models are involved.** The local Ollama model is the *detector*. The
  free-text planner is a separate remote model and needs `AGENTGATE_LLM_API_KEY`;
  without it the scenarios still work, since they replay recorded proposals.
- **Detection is entirely LLM-driven.** Pattern matching survives in exactly one place,
  `sanitizer.py`, because redaction has to replace exact character spans.
- **Detector outages fail closed** to `NEED_APPROVAL`, never to `ALLOW`.
- **Slow is expected on CPU.** Six detector calls per action. Raise
  `AGENTGATE_LLM_DETECTOR_TIMEOUT` rather than assuming something hung.

## If something breaks

| Symptom | Cause |
|---|---|
| `Audit store unavailable` | Postgres down or `AGENTGATE_AUDIT_DSN` unset |
| `LLM detector is unavailable` | `ollama serve` not running, or model not pulled |
| Everything returns `NEED_APPROVAL` | detectors failing closed — check Ollama |
| A run seems to hang | it probably hasn't; see the timing note above |
| `AGENTGATE_WEB_PASSWORD must be set` | the console never runs unauthenticated |

More detail: [README.md](../README.md) for the full reference, [TUTORIAL.md](../TUTORIAL.md)
for executor walkthroughs, and [docs/ds/](ds/) for the design decisions behind the engine.
