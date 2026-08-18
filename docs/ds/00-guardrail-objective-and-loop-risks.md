# Phase 0 — Guardrail Objective & Custom-Loop Risks

**Sprint:** Phase 0 (Jun 19–21) · **Owner:** Data Science
**PRD row:** "Review agentic tool-calling architecture; define custom loop risks and core guardrail objective."

## 1. Core guardrail objective

AgentGate is a **pre-action** guardrail. Its single job is to answer one question for
every proposed tool call, before that call reaches an API, a browser, a file, or any
external system:

> Given this proposed action and its payload, should it execute as-is, execute
> redacted, wait for a human, ask the user, or not run at all?

Three properties define the objective, in priority order:

1. **No execution before evaluation.** There is no code path where an executor runs
   without a `DecisionResponse` first. This is the product; everything else is detail.
2. **The model suggests, AgentGate decides.** The planner is untrusted. It may lie
   about its own risk, propose off-vocabulary verbs, or be prompt-injected. None of
   that can widen what the guardrail permits.
3. **Fast enough to sit in front of every call.** A guardrail the team disables
   because it is slow has a real-world safety value of zero. See the latency budget in
   [01-research-and-latency-budget.md](01-research-and-latency-budget.md).

### What it is not

- Not a chatbot, and not tied to any one agent framework (no OpenClaw / MCP /
  LangGraph dependency in the MVP path).
- Not a DLP/SIEM/compliance product. It covers the three PRD domains only: booking
  messaging, internal code/data protection, productivity assistant.
- Not a replacement for the human reviewer on high-impact actions. `NEED_APPROVAL`
  and `ASK_USER` are required outcomes, not optional enhancements.

## 2. Why a custom function-calling loop

The PRD requires the loop be built from scratch (F2). The reason is evaluative, not
NIH: if the loop came from a framework, we could not prove *where* the guardrail sits
relative to execution, and the framework's own tool-dispatch could bypass it. Owning
`propose -> validate -> evaluate -> enforce -> observe` end to end is what makes
"no execution before evaluation" checkable rather than aspirational.

## 3. Custom-loop risks and how the design answers each

| # | Risk | Consequence if unhandled | Mitigation in code |
|---|---|---|---|
| R1 | Planner proposes a verb outside the action space | Undefined behavior; unreviewable action surface | `action_space.validate_proposal()` rejects the step; the loop records it and continues (`agentgate/loop.py`) |
| R2 | Planner self-reports low risk to get waved through | Guardrail trusts the attacker's own label | Risk hints are *merged* from detector tags and registered `ToolSpec` metadata, never taken from the planner alone (`policy/engine.py::_matches`, `planner/base.py`) |
| R3 | Arguments mutate between evaluation and execution | The guardrail approves X and the executor runs Y | Arguments are SHA-256 fingerprinted at build time and rechecked before dispatch (`router.py::_arguments_match_request`) |
| R4 | Planner call times out, errors, or returns unparseable output | One bad call kills the whole run | The loop catches it, marks the step failed, and ends the run cleanly instead of raising |
| R5 | Detector runtime unavailable | Silent fallback would let unsafe actions through | Fails **closed**: `LLMUnavailable` forces a `HIGH` risk floor and `NEED_APPROVAL` (`decision.py`) |
| R6 | Executor output carries injected instructions back to the planner | Indirect prompt injection through tool results | Executor output is re-evaluated before it becomes an observation, then sanitized or quarantined (`loop.py::_screen_execution_observation`) |
| R7 | Loop never terminates | Runaway spend and unbounded side effects | Hard `max_steps` cap (default 12), plus terminal `DONE`/`FAIL` verbs |
| R8 | Secrets leak into logs, run output, or the audit trail | The guardrail becomes the leak | Every serialization path passes through `sanitize()` / `safe_value()`; audit rows store redacted request and response (`audit.py`) |
| R9 | A decision is produced but never recorded | No forensic trail; PRD audit-completeness metric unmeasurable | Auditing is mandatory and fails loudly; an unauditable decision is not returned (`decision.py`, `audit.py`) |

## 4. Trust boundaries

```
UNTRUSTED                          TRUSTED
─────────                          ───────
Planner output (proposals)   ->    Action Space Validator
Executor output (results)    ->    Observation screening
Page/browser content         ->    Simplified snapshot only, never raw HTML
                                   ├─ ToolSpec registry metadata
                                   ├─ Policy packs
                                   └─ Detector findings
```

Anything on the left may be adversarial. Anything on the right is authored by the
team and versioned in this repository.
