# AgentGate

**Framework-agnostic pre-action guardrail engine for AI agent tool actions.**

AgentGate evaluates every proposed tool call *before* it touches a real API, browser,
file, or external system. The agent's LLM only *proposes*; AgentGate *decides*
(`ALLOW` / `BLOCK` / `NEED_APPROVAL` / `SANITIZE` / `ASK_USER`); a Decision Router
*enforces*; and every step is audited.

> This repository is the **DS-owned core** (the "brain": detectors, policy, risk,
> decision engine, sanitizer, approval logic, audit logging, custom loop, tool
> registry, CLI, benchmark, evaluation). Real execution (Gmail/GitHub/Stripe/
> Playwright), the real audit database, and independent scenario QA are **not** DS's
> job — see [Ownership: DS vs DA vs DE](#ownership-ds-vs-da-vs-de) below. Nothing here
> requires an API key to run.

---

## Quick start

No dependencies, no API key. Python 3.10+.

```bash
# --- These work standalone today (pure DS decision logic, no Executor needed) ---
python -m agentgate list                    # list the demo scenarios
python -m agentgate tools                   # list the registered tool catalog
python -m agentgate eval-suite              # labeled evaluation (F16)
python -m agentgate eval API_CALL --domain code_security --target-system GitHub \
  --payload "deploy key AKIAIOSFODNN7EXAMPLE" --risk-hint external_send

# Tests (4 expected failures are intentional — see below, not a bug)
python -m unittest discover -s tests

# --- These require a real Executor and are BLOCKED until DE implements one ---
# They print a clear "Blocked: needs DE" message and exit 1 rather than crash.
python -m agentgate run booking_message
python -m agentgate benchmark --repeats 40
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
  tools.py          tool registry (tool_name catalog + safety-default enrichment)
  detectors/        the six detectors (incl. action-intent: bulk/destructive/external)
  policy/           policy engine + JSON packs/
  risk.py           risk scoring (noisy-OR + bands)
  sanitizer.py      redaction for SANITIZE decisions
  decision.py       DecisionEngine: detectors + policy + risk → DecisionResponse
  approval.py       approval queue / SafetyGuard
  audit.py          append-only JSONL audit log + completeness metric (DE: real DB)
  router.py         Decision Router / enforcement
  engine.py         AgentGate facade (evaluate + audit + latency timing)
  executors/        Executor interface (base) + MockExecutor   ← DE placeholder, raises
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

## Ownership: DS vs DA vs DE

This repo is DS's deliverable. It is **not** a finished product — two pieces are
deliberately left as placeholders for teammates, so the repo itself documents the
team boundary rather than just a slide. The "PRD sprint" column below cites the
project's milestone calendar (Start 19 Jun 2026 → Launch 2 Oct 2026) so DA/DE know
*when* each item is expected, not just *what* it is.

### ✅ DS — built, tested, working now
Detectors (6), policy engine + 4 packs, risk scoring, decision engine, sanitizer,
approval queue, audit *logging logic*, decision router, custom function-calling loop,
tool registry (enrichment logic), ActionRequest/DecisionResponse schema, action-space
validator, CLI, benchmark harness code, evaluation harness code. 32 tests (28 passing
standalone).

### 🔧 DE — placeholder in this repo, TODO for you
| What | Where | Status | PRD sprint |
|---|---|---|---|
| Real API connectors (Gmail, GitHub, Stripe, Telegram) | new files under `agentgate/executors/` | not implemented | Sprint 1 (baseline) → Sprint 3 (stabilize) |
| Playwright browser executor | new file under `agentgate/executors/` | not implemented | Sprint 1 (skeleton) → Sprint 1B (pilot) → Sprint 2 (full pipeline) → Sprint 3 (stabilize) |
| Real audit database (SQLite/Postgres) | `agentgate/audit.py` (`AuditLog`) | JSONL file placeholder | Sprint 1 (prototype) → Sprint 4 (finalize schema) |

**Start here:** `agentgate/executors/mock.py` — it currently raises
`NotImplementedError` with a message pointing at exactly what to implement. Subclass
`Executor` from `agentgate/executors/base.py`:

```python
from agentgate.executors import Executor, ExecutionResult

class GmailExecutor(Executor):
    def supports(self, req): return req.target_system == "Gmail"
    def execute(self, req, *, payload=None) -> ExecutionResult:
        ...  # real Gmail API call
        return ExecutionResult(ok=True, output=..., via="api")
```

Wire it into `agentgate/cli.py` (`_build()` and `cmd_plan`) and `agentgate/benchmark.py`
(`run_benchmark`'s default executor) in place of `MockExecutor`. Once done, remove the
four `@unittest.expectedFailure` decorators in `tests/test_agentgate.py`
(`TestLoopAndAudit` + `TestBenchmark`) — they'll go from "expected failure" to a real
pass, which is your signal it's wired correctly.

The shared **ActionRequest** schema (PRD F3) is the contract between DS and DE — you
don't need to change anything upstream of the Executor interface.

### 🔧 DA — placeholder in this repo, TODO for you
| What | Where | Status | PRD sprint |
|---|---|---|---|
| Independent scenario labeling / QA | `scenarios/eval_set.json` | DS-authored, self-labeled — needs independent review | Sprint 1 (initial inventory) → Sprint 1B (review pilot logs) → Sprint 2 (manual scenario QA) → Sprint 3 (validate consistency) |
| Tool catalog / API feasibility cross-check | `agentgate/tools.py` (`_DEFAULT_TOOLS`) | DS-authored from PRD, not DA-verified | Phase 1 (research) → Sprint 2 (API matrix) |
| Domain & risk taxonomy validation | `agentgate/schemas.py` (`ACTION_TYPES`, `RISK_HINTS`) | DS-authored, needs sign-off | Phase 0 / Phase 2 (taxonomy drafting) → Sprint 2 (domain coverage) |
| Failure-case analysis / risk taxonomy report | n/a | not started | Sprint 3 → Sprint 4 (evaluation report, domain risk taxonomy) |

`eval_set.json` has an `"_ownership_note"` field at the top explaining exactly what's
expected. Run `python -m agentgate eval-suite` to see current DS-graded results, then
add/relabel cases DS wouldn't have thought of.

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
F11 latency profiler (coarse; PRD asks for per-stage — TODO) · F12 raw-vs-guarded
benchmark · F14 audit log (logic; DE owns real DB) · F15 policy packs · F16 evaluation ·
CLI demo (part of F13).

Not built here (other tracks / post-MVP, see Ownership section above): real API/browser
executors & audit DB (DE), Browser Snapshot Builder via Playwright (DE), independent
scenario QA / taxonomy validation (DA), web Demo Console (FE/PD), Chrome extension /
MCP / LangGraph adapters (post-MVP).
