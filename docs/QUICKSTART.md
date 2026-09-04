# AgentGate Quickstart

Two ways to try it:

- **[A. Run it locally on Windows](#a-run-it-locally-windows)** — most of the team.
- [macOS / Linux](#b-run-it-locally-macos--linux) is at the bottom.

All PowerShell commands below assume you are in the repository root.

---

## A. Run it locally (Windows)

### 1. Prerequisites

| Need | Why | Install |
|---|---|---|
| Python 3.10+ | the engine | [python.org/downloads](https://www.python.org/downloads/) — tick **"Add python.exe to PATH"** |
| PostgreSQL 16 | audit log is mandatory (PRD F14) | `winget install PostgreSQL.PostgreSQL.16` |
| Ollama | runs the six detectors | [ollama.com/download](https://ollama.com/download/windows) |

Check Python — on Windows the launcher is `py`, not `python3`:

```powershell
py --version
```

The Postgres installer asks for a password for the `postgres` superuser. **Write it
down**, you need it in step 4. It also installs `psql.exe` under
`C:\Program Files\PostgreSQL\16\bin`, which is not on PATH by default. Add it for this
session:

```powershell
$env:Path += ";C:\Program Files\PostgreSQL\16\bin"
```

Ollama installs as a background service and starts on login, so there is usually no
`ollama serve` to run. Confirm it is up:

```powershell
Invoke-RestMethod http://localhost:11434/api/tags
```

AgentGate dispatches its six detectors concurrently, but Ollama's own default
effectively serves one request at a time, so without raising Ollama's parallelism the
concurrent dispatch has nothing to parallelize against. Because Ollama runs as a
background service, not a process your shell starts, a session-only `$env:` will not
reach it - set it persistently and restart Ollama:

```powershell
setx OLLAMA_NUM_PARALLEL 6
```

Then quit Ollama from the system tray and reopen it (or sign out and back in) so it
picks up the new value. Confirm the model is using it: `ollama ps` while a request is
running shouldn't show requests queuing.

### 2. Install AgentGate

```powershell
git clone https://github.com/NafisNaufal/agentgate.git
cd agentgate
py -m venv .venv
.venv\Scripts\pip.exe install -e ".[dev]"
```

Everything from here uses `.venv\Scripts\python.exe`. Alternatively activate the venv
once and just type `python`:

```powershell
.venv\Scripts\Activate.ps1
```

If that is blocked by execution policy, allow it for this session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 3. Database and model

```powershell
psql -U postgres -c "CREATE DATABASE agentgate;"
ollama pull qwen2.5:7b
```

`ollama pull` downloads ~4.7 GB once. `psql` prompts for the superuser password from
step 1.

### 4. Configure

```powershell
$env:AGENTGATE_AUDIT_DSN        = "postgresql://postgres:YOUR_PASSWORD@localhost:5432/agentgate"
$env:OLLAMA_HOST                = "http://localhost:11434"
$env:AGENTGATE_LLM_DETECTOR_MODEL   = "qwen2.5:7b"
$env:AGENTGATE_LLM_DETECTOR_TIMEOUT = "600"
```

Replace `YOUR_PASSWORD` with the Postgres password you set. If it contains `@`, `:`
or `/`, percent-encode those (`@` → `%40`).

`$env:` variables last only for the current PowerShell window. To avoid retyping them,
save the four lines to `env.ps1` in the repo root and dot-source it each session:

```powershell
. .\env.ps1
```

`env.ps1` is gitignored, so your password will not be committed.

**`AGENTGATE_AUDIT_DSN` is required.** Auditing is mandatory and fails loudly: an unset
or unreachable DSN stops the engine at startup rather than producing decisions nobody
recorded. `Audit store unavailable` is the design working, not a bug.

### 5. Verify

```powershell
.\scripts\setup.ps1
.venv\Scripts\python.exe -m unittest discover -s tests
```

`setup.ps1` checks Python, Ollama, the model, the audit database, then runs the 182
tests and a live prompt-injection smoke test. The tests themselves need no network,
model, or database.

### 6. Run something

```powershell
.venv\Scripts\python.exe -m agentgate list
.venv\Scripts\python.exe -m agentgate tools

.venv\Scripts\python.exe -m agentgate run booking_message      # ALLOW -> SANITIZE -> NEED_APPROVAL
.venv\Scripts\python.exe -m agentgate run sensitive_code       # BLOCK on secrets
.venv\Scripts\python.exe -m agentgate run ambiguous_cleanup    # ASK_USER on low confidence
.venv\Scripts\python.exe -m agentgate run productivity_archive
```

Every run is dry-run. Nothing executes unless you pass `--execute`.

Evaluate a single ad-hoc action:

```powershell
.venv\Scripts\python.exe -m agentgate eval API_CALL `
  --tool-name gmail_send --target-system Gmail `
  --payload "Hi john@example.com, pay at http://pay.example.com/invoice"
```

Add `--json` to `run` or `eval` for structured output. In PowerShell the line
continuation character is a backtick `` ` ``, not `\`.

### 7. Chat with it

```powershell
.venv\Scripts\python.exe -m agentgate chat
```

An interactive REPL, like Claude Code's own chat: type a message, a live LLM planner
proposes the next tool call, and it still goes through the full detector + policy +
risk pipeline before anything happens. `NEED_APPROVAL` pauses right there and asks
`Approve? [y/N]`; `ASK_USER` prints the planner's question and takes your typed answer.
`BLOCK` always stops the turn — there is no way to approve past it.

By default the planner driving the chat is the same local Ollama model the detectors
use (`AGENTGATE_LLM_PROVIDER=ollama`, no API key, no network latency). Set
`AGENTGATE_LLM_PROVIDER` to `openrouter` / `openai` / `gemini` / `anthropic` plus
`AGENTGATE_LLM_API_KEY` to use a remote model instead. Add `--no-execute` to dry-run
the whole conversation without performing any real action.

---

## B. Run it locally (macOS / Linux)

```bash
brew install postgresql@16 && brew services start postgresql@16   # macOS
git clone https://github.com/NafisNaufal/agentgate.git && cd agentgate
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

createdb agentgate
export OLLAMA_NUM_PARALLEL=6   # set before ollama serve/pull; see note below
ollama pull qwen2.5:7b

export AGENTGATE_AUDIT_DSN="postgresql://$(whoami)@localhost:5432/agentgate"
export AGENTGATE_LLM_DETECTOR_MODEL=qwen2.5:7b
export AGENTGATE_LLM_DETECTOR_TIMEOUT=600

./scripts/setup.sh
.venv/bin/python -m agentgate run booking_message
```

On Apple Silicon the detector model is GPU-accelerated, so runs are far quicker than
on the shared server. AgentGate also dispatches its six detectors concurrently, but
that only helps once Ollama itself is configured to serve more than one request at a
time - its default effectively serializes them. `OLLAMA_NUM_PARALLEL` must be set in
the environment `ollama serve` starts from (if Ollama runs as a `brew services` /
launchd background process instead of a foreground `ollama serve`, set it with
`launchctl setenv OLLAMA_NUM_PARALLEL 6` and restart the service). Measured 25-40%
reduction in live guarded P95 on an Apple M4 with this set versus not; see
[docs/ds/01](ds/01-research-and-latency-budget.md) for the numbers.

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

Worth knowing while reading output:

- **Two different models can be involved.** The local Ollama model is always the
  *detector*, no matter what. `run`'s scenarios replay recorded proposals by default
  (no planner LLM at all) and `run --planner llm` / `chat` add a free-text planner on
  top — local via Ollama by default, or remote with `AGENTGATE_LLM_API_KEY`.
- **Detection is entirely LLM-driven.** Pattern matching survives in exactly one place,
  `sanitizer.py`, because redaction has to replace exact character spans.
- **Detector outages fail closed** to `NEED_APPROVAL`, never to `ALLOW`.
- **Slow is expected without a GPU.** Six detector calls per action. Raise
  `AGENTGATE_LLM_DETECTOR_TIMEOUT` rather than assuming it hung.

## If something breaks

| Symptom | Cause |
|---|---|
| `Audit store unavailable` | Postgres not running, or `AGENTGATE_AUDIT_DSN` unset/wrong password |
| `LLM detector is unavailable` | Ollama service not running, or model not pulled |
| Everything returns `NEED_APPROVAL` | detectors failing closed — check Ollama |
| `psql` / `ollama` not recognised | not on PATH; see step 1, or reopen the terminal after installing |
| `Activate.ps1 cannot be loaded` | execution policy; see step 2 |
| `ModuleNotFoundError: agentgate` | using global Python instead of `.venv\Scripts\python.exe` |
| A run seems to hang | it probably has not; see the timing note above |
| `Planner unavailable` in `chat` | Ollama not running/model not pulled (local), or `AGENTGATE_LLM_API_KEY` unset (remote) |

More detail: [README.md](../README.md) for the full reference, [TUTORIAL.md](../TUTORIAL.md)
for executor walkthroughs, and [docs/ds/](ds/) for the design decisions behind the engine.
