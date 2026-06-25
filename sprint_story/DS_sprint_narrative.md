# AgentGate — Data Science (DS) Sprint Narrative

Per-sprint story for the **DS track only**, mapped to the PRD milestone calendar
(Start 19 Jun 2026 → Launch 2 Oct 2026). Each sprint lists the goal, what DS produced,
and the **concrete artifact in this repo** that backs the claim, so the incremental
story is defensible against questions and a live demo.

> Framing note: the DS engine is functionally complete in this repo. This narrative
> tells the build as the planned sprint sequence and points at the real module/test
> that demonstrates each step. Keep claims to the DS column — connector integration,
> audit DB, and the web console belong to DE/FE and are reported by them.

| Sprint | Dates | DS goal | Backing artifact (this repo) | Demo |
|---|---|---|---|---|
| Phase 0 | Jun 19–21 | Review agentic tool-calling architecture; define custom-loop risks & core guardrail objective | `README.md` (Core concept, decision flow); architecture in `loop.py` docstring | — |
| Phase 1 | Jun 22–28 | Research tool-call loop, action schema, LLM planner, detector baseline, policy/risk design, latency budget | `schemas.py`, `action_space.py` (action vocabulary), `planner/base.py` | — |
| Phase 2 | Jun 29–Jul 5 | Define custom-loop architecture, tool registry, fixed action vocabulary, ActionRequest schema, evaluation metrics | `schemas.ActionRequest` / `DecisionResponse`; `evaluation.py` metric set | — |
| Phase 3 | Jul 6–12 | Prototype DS-led loop, planner prompt, tool-call parser, decision router, baseline action eval; define CLI + benchmark plan | `loop.py`, `planner/llm.py` (system prompt), `router.py`, `benchmark.py` plan | `python -m agentgate list` |
| Break | Jul 13–19 | — | — | — |
| Sprint 1 | Jul 20–Aug 2 | Implement detectors, policy engine, risk scoring, sanitizer, decision engine, custom-loop baseline, initial CLI | `detectors/`, `policy/`, `risk.py`, `sanitizer.py`, `decision.py`, `cli.py` | `run booking_message` |
| Sprint 1B | Aug 3–9 | Run loop on pilot scenarios; refine ActionRequest builder, routing, prompt; CLI runner for Booking/Code/Productivity; validate all 5 decisions | `scenarios/*.json`, `router.py`, `tests/test_agentgate.py` (decision tests) | `run sensitive_code` |
| Sprint 2 | Aug 10–23 | Evaluation scripts, detector tests, tool-call tests, scenario runner, latency profiler, raw-vs-guarded harness | `evaluation.py`, `tests/`, `engine.StageTimings`, `benchmark.py` | `eval-suite` |
| Sprint 3 | Aug 24–Sep 6 | Optimize loop, decision router, detector thresholds, risk weights, schema, latency hot paths, CLI benchmark | risk weights in `detectors/*`, `risk.py`; `benchmark.py` | `benchmark --repeats 40` |
| Sprint 4 | Sep 7–13 | Finalize core eval, compare baseline rules, measure overhead, engine limitation notes; freeze CLI/benchmark | `README.md` (status & honesty notes), `evaluation.EvalReport` | `eval-suite --json` |
| Showcase | Sep 14–20 | Technical demo explanation, core narrative, latency benchmark story, post-MVP roadmap | this file + `DS_slides_outline.md` | full run sequence |
| Testing | Sep 21–24 | Run benchmark/loop/actions, collect failure logs | `tests/` (22 tests), `eval_set.json` mismatches | `unittest discover` |
| Fixing | Sep 25–28 | Improve thresholds, risk scoring, loop, schema, safety filters, low-confidence fallback | `policy/packs/global_safety.json` (low-confidence rule) | `eval API_CALL --confidence 0.3` |
| Final | Sep 29–Oct 1 | Freeze core, loop, latency benchmark, eval scripts, technical report | tagged repo state; `README` status section | full suite |
| Launch | Oct 2 | Support demo, release notes, limitation explanation, technical Q&A | `README` + this narrative | live demo |

## Talking points per sprint (for standups / showcase)

**Phase 0–1 (Foundations).** "We framed AgentGate as a *pre-action* guardrail, not a
chatbot. The risky surface is the tool call, so the unit of control is the
`ActionRequest`. We fixed a closed action vocabulary up front so anything off-vocabulary
is rejected before evaluation."

**Phase 2–3 (Schema & loop design).** "We locked the two contracts — `ActionRequest`
(shared with DE) and `DecisionResponse` — and built the custom function-calling loop from
scratch so we don't depend on OpenClaw/MCP/LangGraph. The loop is: propose → build
request → evaluate → enforce → execute → audit."

**Sprint 1 (Core engine).** "Five detectors feed a noisy-OR risk score; a declarative
policy layer turns findings into decisions. Strongest of (policy, risk-band) wins. Demo:
booking message → PII auto-sanitized, payment send → approval."

**Sprint 1B (Pilot + all decisions).** "Three domain scenarios exercise every decision:
ALLOW, SANITIZE, NEED_APPROVAL, BLOCK, ASK_USER. Secret in a file → BLOCK; source-code
egress → approval."

**Sprint 2 (Evaluation).** "EvalBoard reports completion, decision accuracy, unsafe
auto-allow, false-block, approval-routing accuracy, and detector recall against a labeled
set. Per-stage latency is profiled on every evaluation."

**Sprint 3 (Optimization).** "Rule-based evaluation P95 is well under the 250 ms target,
so the guardrail tax is a few percent on real execution. We tuned detector contributions
and risk bands to remove false blocks."

**Sprint 4 → Launch.** "Froze the core, wrote limitation notes (curated eval set, mock
executors), and prepared the technical narrative and roadmap (extension/MCP/LangGraph are
post-MVP adapters reusing the same contracts)."

## One honest caveat to keep in the talk

The eval numbers are on a **small curated set**, and external execution is **mocked**
(DE owns the real connectors). Saying this out loud is stronger than hiding it — it shows
you know the difference between "engine proven" and "production integrated."
