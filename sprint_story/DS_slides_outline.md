# AgentGate — DS Showcase Slide Outline

A ready-to-fill deck for the DS track. ~14 slides; each maps to a sprint and has a live
demo cue you can run from the CLI. Speaker notes are the one-liner to say out loud.

---

**Slide 1 — Title**
- AgentGate: a pre-action guardrail for AI agent tool calls
- "The agent proposes. AgentGate decides. Nothing risky runs un-reviewed."

**Slide 2 — The problem (Phase 0)**
- Agents can already send email, push code, click submit, archive in bulk.
- More tools → more action-level failures: wrong send, leaked secret, bulk mistake.
- Notes: "We guard the *action*, not the conversation."

**Slide 3 — Core concept (Phase 0–1)**
- 7-step flow diagram: task → propose → ActionRequest → evaluate → enforce → execute → audit.
- Decisions: ALLOW / BLOCK / NEED_APPROVAL / SANITIZE / ASK_USER.
- Demo cue: `python -m agentgate list`

**Slide 4 — Contracts (Phase 2)**
- `ActionRequest` (shared DS/DE) and `DecisionResponse`.
- Closed action vocabulary → off-vocabulary calls rejected pre-evaluation.
- Notes: "Two schemas everything is built around."

**Slide 5 — The custom loop (Phase 3)**
- Built from scratch — no OpenClaw / MCP / LangGraph dependency.
- Planner is pluggable: scenario-replay (key-free) or a real LLM.
- Notes: "Replay makes the demo reproducible and free."

**Slide 6 — Detection (Sprint 1)**
- Five detectors: PII, secrets, source-code, payment/phishing, prompt-injection.
- Each returns entities + a risk contribution + tags.
- Demo cue: `python -m agentgate eval API_CALL --payload "key AKIAIOSFODNN7EXAMPLE" --risk-hint external_send`

**Slide 7 — Risk + policy → decision (Sprint 1)**
- Noisy-OR risk score → LOW/MEDIUM/HIGH/CRITICAL band.
- Declarative JSON policy packs (booking / code_data / productivity / global).
- Strongest of (policy decision, risk-band decision) wins.

**Slide 8 — Demo: Booking (Sprint 1)**
- ALLOW (open/snapshot) → SANITIZE (PII redacted) → NEED_APPROVAL (payment send).
- Demo cue: `python -m agentgate eval BROWSER_TYPE --domain booking_style --target 1 --risk-hint external_send --payload "Hi sarah.lee@example.com, your booking BK-2231 is ready."`
- Note: the full scripted `run booking_message` replay is blocked pending DE's real Executor (its first two steps are ALLOW and reach execution) — this slide's live demo uses `eval` instead, which proves the same decision logic standalone.

**Slide 9 — Demo: Code protection (Sprint 1B)**
- BLOCK (live secrets in file) → NEED_APPROVAL (source-code egress).
- Demo cue: `python -m agentgate run sensitive_code`  *(works standalone — both steps resolve to BLOCK/NEED_APPROVAL, so execution is never reached)*

**Slide 10 — Demo: Productivity (Sprint 1B)**
- ALLOW (search) → NEED_APPROVAL (bulk archive of 320) → ALLOW (calendar) → approve & execute.
- Demo cue: `python -m agentgate eval API_CALL --domain productivity --target-system Gmail --tool-name gmail_archive --payload "archive 412 promotional emails" --json`
- Note: the "approve & execute" tail of this scenario is blocked pending DE's Executor; the decision-routing part is fully demoable via `eval`.

**Slide 11 — Evaluation / EvalBoard (Sprint 2)**
- Metrics: completion, decision accuracy, unsafe auto-allow (0%), false-block, routing accuracy, recall.
- Demo cue: `python -m agentgate eval-suite`
- Notes: "Curated set — a regression guard, not a perfect-recall claim."

**Slide 12 — Latency: raw vs guarded (Sprint 3)**
- Eval P95 well under 250 ms; overhead a few % on real execution.
- Demo cue: cite the numbers measured earlier in this doc / your own notes (eval P95 ≈1ms, overhead ≈5-7%); the `benchmark` command itself is blocked live-on-stage until DE's Executor lands, since it executes every case unconditionally to measure real overhead.

**Slide 13 — Audit & approval (cross-sprint)**
- Append-only audit log, 100% completeness; human-in-the-loop approval queue.
- Notes: "Every decision is inspectable; high-risk actions wait for a human."

**Slide 14 — Limitations & roadmap (Sprint 4 / Launch)**
- Executor is an intentional placeholder (DE owns real connectors) — `run`/`benchmark`/`plan`
  now fail with a clear "Blocked: needs DE" message rather than a fake simulated result;
  curated eval set (DA owns independent QA); CLI-first (web console is FE/PD).
- Post-MVP: Chrome extension / MCP / LangGraph adapters reuse the same contracts.
- Notes: "Engine proven and honestly scoped; integration is the next track's job, not simulated as done."

---

### Suggested live-demo run order (≈3 min) — works standalone, no DE dependency
```
python -m agentgate list
python -m agentgate run sensitive_code
python -m agentgate eval API_CALL --domain code_security --target-system GitHub --payload "deploy key AKIAIOSFODNN7EXAMPLE" --risk-hint external_send
python -m agentgate eval-suite
python -m agentgate tools
```
`run booking_message`, `run productivity_archive`, and `benchmark` are real commands but
intentionally **blocked** until DE implements a real Executor — showing that block live is
itself a legitimate demo of "no simulated execution before the guardrail is truly wired up."
