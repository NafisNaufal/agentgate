# Phase 3 — CLI Demo Contract, I/O Formats & Raw-vs-Guarded Benchmark Plan

**Sprint:** Phase 3 (Jul 6–12) · **Owner:** Data Science
**PRD row:** "Define CLI demo contract, scenario input format, decision output format, and raw-vs-guarded benchmark plan."

## 1. CLI demo contract

The CLI is the developer and DS surface. It exercises the same `DecisionEngine` the
web Demo Console will call, so a result reproduced here is a result the console will
show.

| Command | Contract |
|---|---|
| `list` | Print every packaged scenario with its expected safety behavior |
| `tools` | Print the registered tool catalog with irreversibility and default risk hints |
| `run <scenario>` | Drive the full loop over a scenario; dry-run unless `--execute` |
| `eval <ACTION_TYPE>` | Evaluate a single ad-hoc action; never executes |

Flags on `run`: `--json` (structured output), `--planner {replay,llm}`,
`--execute` (opt in to real side effects).

**Exit statuses** (`run --execute`): `0` completed · `1` failed/blocked ·
`2` awaiting approval or user confirmation. Dry runs always exit `0`; the decisions
are the output, not the exit code.

**Safety invariants the CLI must preserve.** Dry-run is the default. `--planner llm`
changes who proposes, never what is permitted. Every printed string — reasons, task
text, outcome messages — passes through `sanitize()` before it reaches a terminal.

## 2. Scenario input format

A scenario is a JSON file in `agentgate/scenarios/`, replayed by `ReplayPlanner` so
demos are reproducible and need no API key.

```jsonc
{
  "name": "booking_message",              // CLI identifier
  "title": "Booking-style reservation message review",
  "domain": "booking_style",
  "description": "...",                   // what the scenario demonstrates
  "expected": "ALLOW -> SANITIZE -> NEED_APPROVAL",   // asserted safety behavior
  "task": "Send a payment confirmation message ...",  // natural-language goal
  "steps": [
    {
      "action_type": "BROWSER_TYPE",      // required, from the action vocabulary
      "arguments": {"element_id": "1", "value": "..."},
      "domain": "booking_style",
      "target_system": "browser",
      "risk_hint": ["external_send"],     // planner's claim; merged, never trusted alone
      "rationale": "Type a greeting ...",
      "confidence": 0.88,
      "rollback_available": true
    }
  ]
}
```

`expected` is prose for the demo, not an assertion the runner enforces — machine-
checked expectations live in the DA eval set, which is authored independently of the
detectors it tests.

The three required MVP scenarios (PRD Sprint 1B) are present: `booking_message`,
`sensitive_code`, `productivity_archive`.

## 3. Decision output format

`run --json` and `eval --json` emit the `DecisionResponse` fields verbatim, bounded
and sanitized. Human-readable output is the same data laid out per step:

```
  [3] BROWSER_SUBMIT   -> NEED_APPROVAL  risk=HIGH score=0.7 412.55ms
        • Payment-related content detected
        • Browser form submission requires human approval
        policies: booking.external_payment_send, global.browser_submit
        awaiting_approval — Action requires human approval
```

Run status values: `dry_run_complete` (every step `ALLOW`) ·
`dry_run_intervention` (the guardrail intervened at least once) · `completed` ·
`blocked` · `awaiting_approval` · `ask_user` · `execution_failed` · `failed` ·
`max_steps_reached`.

## 4. Raw-vs-guarded benchmark plan

The plan; the harness itself is Sprint 2 (PRD DS row: "latency profiler, and
raw-vs-guarded benchmark harness").

**Question.** Does routing every tool call through AgentGate cost enough to make the
agent feel slow? PRD target: guarded API actions add **≤ 20%** over raw execution.

**Method.** For each case in a curated action set, run both arms against identical
inputs and alternate arm order to cancel warm-up drift:

- **Raw arm** — call the executor directly, no evaluation.
- **Guarded arm** — `evaluate()` → route → execute.

**Design decisions.**

- *N = 30 runs per case*, reporting P50/P95 rather than a mean, because the detector
  tail is the number that decides whether the guardrail is usable.
- *Discard the first run per case.* Model load and connection setup are a one-off
  startup cost, not per-action overhead, and including them overstates the tax.
- *Cases must cover both arms of the branch*: actions with no findings (fast path)
  and actions with findings that trigger sanitization (slow path). Reporting only
  clean actions would flatter the result.
- *Separate the stages.* Report detector time, policy+scoring time, and audit-write
  time individually, not just the total — a regression is only actionable if it is
  attributable.

**Report shape.**

| Case | Raw P50 | Raw P95 | Guarded P50 | Guarded P95 | Overhead % | Slowest stage |
|---|---|---|---|---|---|---|

**Interpretation guardrail.** Overhead as a percentage is misleading for very fast
raw actions — a 2 ms file read guarded to 400 ms is 20,000% overhead and completely
irrelevant to how the product feels. Report **absolute added milliseconds** alongside
the percentage, and judge the PRD's 20% target against real API actions (network
round-trips of 100 ms+), which is the comparison the target was written for.
