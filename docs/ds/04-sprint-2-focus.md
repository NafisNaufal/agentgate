# Sprint 2 - Data Science Focus

**Sprint:** Sprint 2 - Start Initialization for Development

**Source:** AgentGate PRD, Sprint 2 DS milestone

This document records the current Data Science work focus. The PRD remains the source
of truth for the complete project scope and acceptance criteria.

## DS Deliverables

### Evaluation

- Prepare evaluation scripts for the curated action set.
- Measure detector recall, unsafe auto-allow rate, false block rate, policy coverage,
  approval routing accuracy, task success, and audit completeness.
- Keep detector-focused evaluation separate from the packaged scenario contracts.

### Tests and scenarios

- Add detector test cases for sensitive data, secrets, source code, phishing/payment
  risk, prompt injection, bulk actions, destructive actions, and external sends.
- Add tool-call tests covering the fixed action space and `ActionRequest` construction.
- Maintain reproducible scenarios for booking-style messaging, code protection,
  productivity workflows, and low-confidence clarification.
- Check every scenario step against its expected `DecisionResponse` decision and risk
  level.

### Performance

- Build the latency profiler for detector, policy, risk scoring, decision, and audit
  stages.
- Build the raw-vs-guarded benchmark harness for comparable API and browser actions.
- Report P50 and P95 latency, absolute added milliseconds, overhead percentage, and the
  slowest stage.
- Include both clean actions and actions that produce findings or sanitization.
- Judge the PRD's 20% overhead target primarily against realistic network-backed API
  actions, while reporting absolute latency for very fast local actions.

## Run the benchmark

The deterministic benchmark is safe for CI and uses six local detector stages plus an
in-process executor. Its executor latency is configurable so the report can show how
the guardrail behaves relative to a fast local action or a network-like action:

```bash
python3 benchmarks/raw_vs_guarded.py \
  --runs 30 \
  --warmups 1 \
  --executor-latency-ms 100 \
  --json-out artifacts/raw-vs-guarded.json
```

The command prints a human-readable table. `--json` prints the machine-readable report
instead, and `--json-out` writes it to a file without contacting an external system.
Threshold breaches are reported in the table and JSON; they do not change the command
exit status yet because the first Sprint 2 run establishes the baseline.

For a live detector measurement, export the normal AgentGate audit-store and Ollama
configuration, then opt in explicitly:

```bash
python3 benchmarks/raw_vs_guarded.py --live --runs 30 --warmups 1
```

Live mode still uses the in-process executor, so it measures the real detector and audit
path without sending API requests or opening a browser. It does write benchmark audit
rows to the configured Postgres database; use an isolated benchmark database rather
than a production audit store.

## Boundaries

- The planner proposes; AgentGate evaluates; the Decision Router enforces.
- No API or browser action is executed before evaluation.
- The benchmark compares identical inputs between the raw and guarded paths.
- Detector failures and malformed outputs remain fail-closed; benchmarks must not turn
  an unavailable detector into an automatic allow.
- MCP, LangGraph, OpenClaw, and browser-extension adapters remain post-MVP work.
- Use synthetic data, mock or sandbox systems, and dummy credentials for evaluation.

## References

- [Architecture and evaluation metrics](02-architecture-and-evaluation-metrics.md)
- [CLI contract and benchmark plan](03-cli-contract-and-benchmark-plan.md)
- [AgentGate PRD](../../AgentGate_PRD.docx)
