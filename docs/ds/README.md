# AgentGate — Data Science Design Docs

Design and research artifacts for the DS column of the AgentGate PRD, Phase 0 through
Sprint 1B. These record the decisions behind the code in `agentgate/`; the PRD itself
is the source of scope and is kept out of this repository.

| Doc | PRD sprint | Covers |
|---|---|---|
| [00 — Guardrail objective & custom-loop risks](00-guardrail-objective-and-loop-risks.md) | Phase 0 (Jun 19–21) | Core objective, why a custom loop, the nine loop risks and their mitigations, trust boundaries |
| [01 — Detector baseline, scoring & latency budget](01-research-and-latency-budget.md) | Phase 1 (Jun 22–28) | Regex → hybrid → full-LLM detector decision, noisy-OR risk scoring, decision resolution, per-stage latency budget |
| [02 — Architecture, contracts & evaluation metrics](02-architecture-and-evaluation-metrics.md) | Phase 2 (Jun 29–Jul 5) | Loop architecture, action vocabulary, ActionRequest/DecisionResponse schemas, tool registry, evaluation metrics |
| [03 — CLI contract, I/O formats & benchmark plan](03-cli-contract-and-benchmark-plan.md) | Phase 3 (Jul 6–12) | CLI demo contract, scenario input format, decision output format, raw-vs-guarded benchmark plan |

## Sprint 1 and 1B

Sprint 1 (Jul 20–Aug 2) and Sprint 1B (Aug 3–9) were implementation sprints; their
deliverables are the code itself rather than separate documents.

| PRD deliverable | Where it lives |
|---|---|
| Detectors | `agentgate/detectors/` |
| Policy engine + domain packs | `agentgate/policy/`, `agentgate/policy/packs/` |
| Risk scoring | `agentgate/risk.py` |
| Sanitizer | `agentgate/sanitizer.py` |
| Decision engine | `agentgate/decision.py` |
| Custom function-calling loop | `agentgate/loop.py` |
| ActionRequest builder | `agentgate/planner/base.py` |
| Decision routing | `agentgate/router.py` |
| CLI demo + scenario runner | `agentgate/cli.py`, `agentgate/scenarios/` |
| Audit log (F14) | `agentgate/audit.py` |
| Independent eval set | `benchmarks/da_eval_runner.py`, `benchmarks/data/` |

All five decision outputs — `ALLOW`, `BLOCK`, `NEED_APPROVAL`, `SANITIZE`,
`ASK_USER` — are exercised by the test suite and by the three pilot scenarios
(booking, code protection, productivity), per the Sprint 1B DS row.

## Out of scope before Sprint 2

Deliberately not built yet, per the PRD milestone table:

- Latency profiler and raw-vs-guarded benchmark **harness** (Sprint 2 DS) — the
  *plan* is in doc 03, and the loop already records per-step `eval_ms`.
- Approval **queue** with reviewer state (Sprint 2+). Sprint 1B requires the
  `NEED_APPROVAL` routing decision, which exists; the queue and reviewer workflow are
  FE/DE surfaces.
- MCP, LangGraph, OpenClaw, and browser-extension adapters — post-MVP by PRD decision.
