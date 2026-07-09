# Sprint 2 (Phase 2) — DS: Problem Scoping & Requirement Drafting

Slide outline for the five DS deliverables of PRD Phase 2, each anchored to real code
in this repo so every claim is backed by something runnable.

> Deliverables (PRD Phase 2, DS column): define custom loop architecture, tool registry,
> fixed action vocabulary, ActionRequest schema, and evaluation metrics.

---

## Slide 1 — Title
"Data Science · Sprint 2 — Problem Scoping & Requirement Drafting" (AgentGate / Laplace 2026)

## Slide 2 — Table of Contents
1. Custom Loop Architecture
2. Fixed Action Vocabulary
3. Tool Registry
4. ActionRequest Schema (DS↔DE contract)
5. Evaluation Metrics

---

## Slide 3 — Custom Loop Architecture — `agentgate/loop.py`
- Built from scratch (no OpenClaw / MCP / LangGraph) → framework-agnostic.
- `AgentLoop.run(task)`, bounded by `max_steps` (default 12). Each step:
  1. `planner.propose()` → 2. `proposal.validate()` (action space) → 3. terminal? (DONE/FAIL)
  → 4. `to_action_request()` → 5. `gate.evaluate()` → 6. `router.route()` → 7. record `StepRecord`, feed observation back.
- Components: Planner (`planner/`) · AgentGate facade (`engine.py`) = DecisionEngine (`decision.py`) + AuditLog (`audit.py`) · DecisionRouter (`router.py`) · Executor (`executors/`).
- Talking point: every step yields a full `StepRecord` / `RunResult` trace → auditable end to end.

## Slide 4 — Fixed Action Vocabulary — `schemas.py: ACTION_TYPES` + `action_space.py`
- **14 registered verbs:** `API_CALL`, `BROWSER_OPEN/SNAPSHOT/CLICK/TYPE/SELECT/SUBMIT/SCREENSHOT`, `FILE_READ`, `ASK_USER`, `NEED_APPROVAL`, `SANITIZE`, `DONE`, `FAIL`.
- `_REQUIRED_ARGS` per verb (e.g. `BROWSER_CLICK`→`element_id`, `API_CALL`→`tool_name`).
- `validate_proposal()` **rejects off-vocabulary or malformed calls before evaluation** (PRD: "any tool call outside the registered vocabulary is rejected").
- Helpers: `is_terminal()` (DONE/FAIL), `is_executable()` (touches an external system).

## Slide 5 — Tool Registry — `agentgate/tools.py`  ·  `python -m agentgate tools`
- **Vocabulary vs registry:** the action *vocabulary* fixes the **verbs**; the *registry* catalogs the concrete **`tool_name`s** and their properties.
- **18 registered API tools** across Gmail, Google Calendar, GitHub, Stripe Sandbox, Telegram, local file (matches PRD Tool Contracts).
- Each `ToolSpec`: `target_system · action_type · channel · rollback_available · default_risk_hints`.
- **Two jobs:** (1) introspection/validation (`is_registered`), (2) **enrichment** — completes the ActionRequest and *tightens* safety (fills `target_system`, forces `rollback_available=False` for irreversible tools, unions inherent risk hints).
- **Safety demo:** a bare `stripe_create_refund` with no planner hints → registry tags it `payment_related` + `destructive_action`, `rollback=False` → **NEED_APPROVAL** (without the registry it would have been ALLOW). The guardrail no longer trusts the planner to declare a tool's inherent risk.

## Slide 6 — ActionRequest Schema (the DS↔DE contract, F3) — `schemas.py: ActionRequest`
- 10 PRD fields: `domain, action_type, target_system, tool_name, target, payload_summary, content_context, risk_hint[], rollback_available, confidence` (+ internal `raw_payload`, `scan_text` dedup helper).
- Paired output **`DecisionResponse`** (9 fields): `decision, risk_level, risk_score, reasons, triggered_policies, sensitive_entities, sanitized_payload, next_step, audit_id`.
- Talking point: this is the exact seam DE builds executors against; the tool registry auto-populates several of these fields.

## Slide 7 — Evaluation Metrics — `evaluation.py` · `benchmark.py` · `scenarios/eval_set.json`
- **Safety/quality** (`EvalReport`): completion rate, decision accuracy, **unsafe auto-allow rate** (target 0%), **false-block rate**, **approval-routing accuracy** (≥90%), **detector recall** (≥85%).
- **Latency** (`benchmark.py`): eval P50/P95, raw-vs-guarded overhead.
- Baseline: all targets met on the curated set; eval P95 ≈ 1 ms — **honest caveat:** small curated set (a regression guard, not a real-world recall claim).

## Slide 8 — Next Step / Close
- Sprint 1 (July): implement detectors + policy + risk into the core engine (prototype done).
- Open items: grow the labeled eval set; optional model-based detectors (the "SLM" story); real connectors land behind the Executor interface (DE).

---

### Live demo run order (≈2 min) — works standalone, no DE dependency
```
python -m agentgate tools            # the tool registry
python -m agentgate run sensitive_code   # full loop, no execution needed (BLOCK/NEED_APPROVAL only)
python -m agentgate eval-suite       # evaluation metrics
```
`run booking_message` and `benchmark` are intentionally **blocked** with a clear
"needs DE" message until a real Executor lands (see README "Ownership: DS vs DA vs DE") —
they are not silently mocked as working.
