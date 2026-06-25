# AgentGate

**Framework-agnostic pre-action guardrail engine for AI agent tool actions.**

AgentGate evaluates every proposed tool call *before* it touches a real API, browser,
file, or external system. The agent's LLM only *proposes*; AgentGate *decides*
(`ALLOW` / `BLOCK` / `NEED_APPROVAL` / `SANITIZE` / `ASK_USER`); a Decision Router
*enforces*; and every step is audited.

> This repository is the **DS-owned core** (the "brain" + CLI demo + evaluation +
> benchmark). Real external connectors (Gmail/GitHub/Stripe/Playwright) and the audit
> database are the Data Engineer track and plug into the `Executor` interface — see
> [DS ↔ DE boundary](#ds--de-boundary). Nothing here requires an API key to run.

---

## Quick start

No dependencies, no API key. Python 3.10+.

```bash
# List the demo scenarios
python -m agentgate list

# Replay a scenario end-to-end through the guardrail
python -m agentgate run booking_message
python -m agentgate run sensitive_code
python -m agentgate run productivity_archive --approve-all

# Evaluate a single ad-hoc action
python -m agentgate eval API_CALL --domain code_security --target-system GitHub \
  --payload "deploy key AKIAIOSFODNN7EXAMPLE" --risk-hint external_send

# Labeled evaluation suite (detector recall, unsafe auto-allow, routing accuracy)
python -m agentgate eval-suite

# Raw-vs-guarded latency benchmark
python -m agentgate benchmark --repeats 40

# Tests
python -m unittest discover -s tests
```

---

## Core concept (PRD §4)

```
1. User gives a task.
2. LLM planner proposes a tool call.            ← planner/ (replay or real LLM)
3. Runtime builds an ActionRequest.             ← planner/base.py  (F3 shared DS/DE contract)
4. AgentGate evaluates the ActionRequest.       ← engine.py + decision.py
5. Decision Router enforces the decision.       ← router.py
6. API/Browser Executor runs only if allowed.   ← executors/  (DE plugs in here)
7. Audit Log records request/decision/result.   ← audit.py
```

**Main rule:** no real API or browser action runs before AgentGate evaluation.

## How a decision is made

```
ActionRequest
   │
   ├─▶ detectors/      PII · secrets · source-code · payment/phishing · prompt-injection · action-intent
   │       └─ findings (entities + risk contribution + tags)
   │       (action-intent infers bulk/destructive/external-send from the text, so the
   │        guardrail does not rely on the untrusted planner to flag its own risk)
   │
   ├─▶ risk.py         noisy-OR combine → score → LOW/MEDIUM/HIGH/CRITICAL band
   │
   ├─▶ policy/         declarative JSON packs (booking / code_data / productivity / global)
   │       └─ triggered rules → suggested decision + risk floor
   │
   └─▶ decision.py     strongest of (policy decision, risk-band decision)
           → DecisionResponse(decision, risk_level, risk_score, reasons,
                              triggered_policies, sensitive_entities,
                              sanitized_payload, next_step, audit_id)
```

Decision precedence (strongest wins): `BLOCK > NEED_APPROVAL > ASK_USER > SANITIZE > ALLOW`.

## Project layout

```
agentgate/
  schemas.py        ActionRequest / DecisionResponse contracts
  action_space.py   registered action vocabulary + validator
  detectors/        the six detectors (incl. action-intent: bulk/destructive/external)
  policy/           policy engine + JSON packs/
  risk.py           risk scoring (noisy-OR + bands)
  sanitizer.py      redaction for SANITIZE decisions
  decision.py       DecisionEngine: detectors + policy + risk → DecisionResponse
  approval.py       approval queue / SafetyGuard
  audit.py          append-only JSONL audit log + completeness metric
  router.py         Decision Router / enforcement
  engine.py         AgentGate facade (evaluate + audit + latency timing)
  executors/        Executor interface (base) + MockExecutor   ← DE seam
  planner/          Planner interface + ReplayPlanner + optional LLMPlanner
  loop.py           custom function-calling loop (built from scratch)
  benchmark.py      raw-vs-guarded latency benchmark
  evaluation.py     EvalBoard: metrics over a labeled set
  cli.py            CLI demo
scenarios/          3 demo scenarios + eval_set.json
tests/              unittest suite (also runs under pytest)
sprint_story/       per-sprint DS narrative + slide outline
```

## Schemas

**ActionRequest** — `action_type`, `domain`, `target_system`, `tool_name`, `target`,
`payload_summary`, `content_context`, `risk_hint[]`, `rollback_available`, `confidence`.

**DecisionResponse** — `decision`, `risk_level`, `risk_score`, `reasons[]`,
`triggered_policies[]`, `sensitive_entities[]`, `sanitized_payload`, `next_step`, `audit_id`.

## DS ↔ DE boundary

DS builds the decision engine against the `Executor` interface
(`agentgate/executors/base.py`). The DE track implements real connectors behind the
same `execute(req, payload=None) -> ExecutionResult` signature:

```python
from agentgate.executors import Executor, ExecutionResult

class GmailExecutor(Executor):
    def supports(self, req): return req.target_system == "Gmail"
    def execute(self, req, *, payload=None) -> ExecutionResult:
        ...  # real Gmail API call
        return ExecutionResult(ok=True, output=..., via="api")
```

The shared **ActionRequest** schema (PRD F3) is the contract between the two tracks.
Until DE's connectors land, `MockExecutor` returns deterministic, latency-simulated
results so the full loop, audit, and benchmark all work today.

## Optional: real LLM planner

The demo runs key-free via scenario replay. To use a live planner instead:

```bash
export AGENTGATE_LLM_PROVIDER=openrouter   # or openai | gemini | anthropic
export AGENTGATE_LLM_API_KEY=sk-...
export AGENTGATE_LLM_MODEL=openai/gpt-4o-mini   # optional
```

The LLM only proposes actions; AgentGate's decisions are unaffected by which model is used.

## Evaluation & benchmark notes (honesty)

- `eval-suite` runs a **small curated** labeled set (`scenarios/eval_set.json`). The
  100% scores reflect those curated cases — they are a regression guard, not a claim of
  perfect real-world recall. Growing this set toward the PRD's synthetic test set is the
  natural next step (DA owns scenario authoring).
- The benchmark's raw-vs-guarded overhead is measured **holding execution constant**, so
  the number reflects the guardrail's latency tax, not the (separate) safety value of
  preventing executions.

## Status vs PRD

Implemented (DS scope): F2 custom loop · F3 ActionRequest builder · F4 core evaluation ·
F5 sensitive-data detection · F9 decision router & SafetyGuard · F10 approval queue ·
F11 latency profiler · F12 raw-vs-guarded benchmark · F14 audit log · F15 policy packs ·
F16 evaluation · CLI demo (part of F13).

Out of scope here (other tracks / post-MVP): real API/browser executors & audit DB (DE),
Browser Snapshot Builder via Playwright (DE), web Demo Console (FE/PD), Chrome extension /
MCP / LangGraph adapters (post-MVP).
