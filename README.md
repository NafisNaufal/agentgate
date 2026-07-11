# AgentGate

**A pre-action guardrail for AI agent tool calls.**

Modern AI agents don't just answer questions — they take real actions: sending
emails, clicking buttons, reading files, calling APIs. AgentGate sits between an
agent deciding to act and the action actually happening: every proposed tool call is
evaluated first, and only safe ones proceed.

```
task → planner proposes a tool call → AgentGate evaluates it → router enforces
       → allow / block / need approval / sanitize / ask user
```

This is an early prototype. The propose → evaluate → enforce lifecycle works end to
end today with a small rule-based evaluator; a full detector suite, policy engine,
tool registry, and real execution layer are in active development. See
[Status](#status) below for what's built vs planned.

## Quick start

Pure Python, no third-party dependencies, no API key required.

```bash
python -m agentgate run booking_message
python -m agentgate eval API_CALL --payload "key AKIAIOSFODNN7EXAMPLE"
python -m unittest discover -s tests
```

## How it works

- **`schemas.py`** — the two contracts everything is built around: `ActionRequest`
  (a proposed action, normalized) and `DecisionResponse` (allow/block/approve/
  sanitize/ask, with reasons).
- **`action_space.py`** — a closed vocabulary of action verbs (`API_CALL`,
  `BROWSER_CLICK`, `FILE_READ`, …); anything outside it is rejected before
  evaluation.
- **`planner/`** — proposes the next action. Two implementations: a deterministic
  scenario-replay planner (used in tests/demos, no API key needed) and an optional
  live LLM planner (Gemini/OpenAI/Anthropic/OpenRouter via one env var).
- **`baseline.py`** — the evaluator. Currently a small set of rule-based checks
  (secret-like patterns, payment language, bulk operations, destructive verbs)
  proving the evaluation concept; this is the piece that grows into a full
  detector + policy engine.
- **`router.py`** — enforces the decision so a risky action is never silently
  allowed to proceed.
- **`loop.py`** — the function-calling loop tying it together, built from scratch
  rather than depending on a specific agent framework.
- **`tools.py`** — the shape of a tool registry (what a registered tool records:
  target system, whether it's reversible, its inherent risk). Defined with a
  couple of illustrative entries; not yet consulted by the loop or planner.

## Project layout

```
agentgate/
  schemas.py        ActionRequest / DecisionResponse contracts
  action_space.py    registered action vocabulary + validator
  baseline.py        rule-based action evaluator
  router.py          decision enforcement
  loop.py            function-calling loop
  tools.py           tool registry shape (defined, not yet wired in)
  planner/           planner interface, replay planner, optional LLM planner
  cli.py             CLI demo (run / eval)
scenarios/           example scenario for the replay planner
tests/               unittest suite
```

## Design notes

A few decisions worth writing down before more gets built on top of them.

**Known risks in a custom agent loop, and how each is handled here:**
- *An untrusted planner proposes something unsafe, or doesn't flag its own risk* —
  by design, the planner only proposes; `baseline.py` (soon a full detector suite)
  makes the safety call independently, so nothing depends on the planner being
  honest about risk.
- *Malformed or off-vocabulary tool calls* — rejected by `action_space.py` before
  they ever reach evaluation.
- *A run that never terminates* — bounded by `max_steps`, plus explicit `DONE`/
  `FAIL` terminal actions.
- *The planner itself fails* (a live LLM call times out or errors) — caught in
  `loop.py` and turned into a failed run with a clear reason, not an uncaught
  exception.
- *Schema drift as more pieces get added* — the `ActionRequest` /
  `DecisionResponse` contract in `schemas.py` is meant to stay stable; detectors,
  policies, and real connectors are expected to build against it rather than
  change it.

**Latency budget:** guardrail evaluation should stay well under the tool-call
latency it's gating — target is P95 ≤ 250ms for rule-based evaluation (the current
baseline evaluator runs in low single-digit milliseconds), so the guardrail doesn't
become the bottleneck once real execution is wired in.

**Evaluation metrics (defined here, measured once the harness exists):** completion
rate, decision accuracy against labeled cases, unsafe auto-allow rate (target 0%),
false-block rate, approval-routing accuracy, and sensitive-data detection recall.

**Raw-vs-guarded benchmark plan:** once a real executor exists, compare P50/P95
latency of running an action directly against running it through `evaluate()` first;
target overhead is small enough (roughly ≤20%) that the guardrail doesn't make the
agent feel slower than it has to.

## Status

**Working now:** the full lifecycle (propose → validate → evaluate → enforce) runs
end to end via the CLI and is covered by tests. The action vocabulary, contracts,
and planner interface are stable. The tool registry's shape is defined (`tools.py`)
with illustrative entries, ahead of being wired into the planner.

**In progress / planned next:**
- A full detector suite (PII, secrets, source code, payment/phishing, prompt
  injection) replacing the current rule-based baseline evaluator.
- A declarative policy engine and domain-specific policy packs.
- Wiring the tool registry into the planner, with a full tool catalog and
  per-tool safety defaults (e.g. an irreversible tool auto-tagged as such even
  if nothing in its payload looks risky).
- Real execution connectors (Gmail, GitHub, Stripe, browser automation) behind a
  stable executor interface — the evaluation logic above does not depend on how
  actions are ultimately executed, so this plugs in without changing anything
  upstream.
- Persistent audit storage and an evaluation harness with labeled test data
  reviewed independently of whoever implements the detectors, to keep the
  accuracy numbers honest.

The design goal throughout is that later pieces (detectors, policies, real
connectors) slot into the existing `ActionRequest` → `DecisionResponse` contract
without changing the pieces built so far.

## Optional: live LLM planner

```bash
export AGENTGATE_LLM_PROVIDER=gemini   # or openai | anthropic | openrouter
export AGENTGATE_LLM_API_KEY=...
```

The LLM only proposes actions — it never decides whether one is safe.
