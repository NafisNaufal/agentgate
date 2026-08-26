# Phase 2 — Loop Architecture, Contracts & Evaluation Metrics

**Sprint:** Phase 2 (Jun 29–Jul 5) · **Owner:** Data Science
**PRD row:** "Define custom loop architecture, tool registry, fixed action vocabulary, ActionRequest schema, and evaluation metrics."

## 1. Loop architecture

```
task
 └─> Planner.propose()                    untrusted
      └─> Proposal
           └─> validate_proposal()        action-space gate
                └─> to_action_request()   ActionRequest builder (F3)
                     └─> DecisionEngine.evaluate()
                          ├─ 6 LLM detectors
                          ├─ PolicyEngine (JSON packs)
                          ├─ risk scoring + policy floor
                          ├─ sanitizer
                          └─ audit write            <- audit_id stamped here
                               └─> DecisionRouter.route()
                                    ├─ BLOCK / NEED_APPROVAL / ASK_USER -> stop
                                    └─ ALLOW / SANITIZE -> Executor
                                         └─> ExecutionResult
                                              └─> observation screening
                                                   └─> back to Planner
```

Every arrow crossing into an executor passes through the router, and the router only
dispatches on `ALLOW` or `SANITIZE`. There is no second path.

## 2. Fixed action vocabulary

Defined in `schemas.ACTION_TYPES`, enforced by `action_space.validate_proposal()`,
which also checks required arguments per verb.

| Group | Verbs |
|---|---|
| API | `API_CALL(tool_name, arguments)` |
| Browser | `BROWSER_OPEN(url)`, `BROWSER_SNAPSHOT()`, `BROWSER_CLICK(element_id)`, `BROWSER_TYPE(element_id, value)`, `BROWSER_SELECT(element_id, option)`, `BROWSER_SUBMIT(element_id)`, `BROWSER_SCREENSHOT()` |
| File | `FILE_READ(path)`, `FILE_WRITE(path, content)`, `FILE_DELETE(path)` |
| Control | `ASK_USER(question)`, `NEED_APPROVAL(action_description)`, `SANITIZE(payload)` |
| Terminal | `DONE(result_summary)`, `FAIL(reason)` |

A closed vocabulary is what makes the policy layer expressible: rules can match on
`action_types` because the set is finite and known at review time.

`FILE_WRITE` and `FILE_DELETE` extend the PRD's Action Space, which defines only
`FILE_READ`. DA's eval case DATA-06 encoded a file *modification* as `FILE_READ`
because nothing else could express it, so the guardrail evaluated a read and correctly
allowed it - a write was simply not representable. Both verbs are evaluable and
policy-covered but have **no executor**, so a proposal fails closed at dispatch
instead of touching disk. Implementing them is DE's call, and the vocabulary change
should be confirmed with DA so their eval set can encode mutations properly.

## 3. ActionRequest — the shared DS/DE contract (F3)

| Field | Type | Purpose |
|---|---|---|
| `action_type` | str | Verb from the vocabulary above (only required field) |
| `domain` | str | `booking_style` / `code_security` / `productivity` / `generic` |
| `target_system` | str | Gmail, GitHub, browser, local file, … |
| `tool_name` | str | Registered tool the planner proposed |
| `target` | str | URL, path, element id, or API object affected |
| `payload_summary` | str | Compact, flattened view of the payload |
| `content_context` | str | User goal / page context / planner rationale |
| `risk_hint` | list[str] | `external_send`, `payment_related`, `source_code`, `bulk_action`, `destructive_action`, `form_submit` |
| `rollback_available` | bool | Whether the action can be undone |
| `confidence` | float | Planner confidence, `[0, 1]` |
| `raw_payload` | str | Full text for detection/redaction; never required to equal `payload_summary` |

`scan_text` concatenates the text a detector should inspect, de-duplicated on
whitespace-normalized content — `raw_payload` and `payload_summary` are usually the
same content in two forms, and feeding both to a classifier makes benign text look
deliberately duplicated.

**Provenance rule:** where a registered `ToolSpec` exists, its `target_system`,
`rollback_available`, `default_risk_hints`, and `content_fields` win over anything the
planner declared. The planner can add risk hints; it cannot remove them.

## 4. DecisionResponse

| Field | Purpose |
|---|---|
| `decision` | `ALLOW` / `BLOCK` / `NEED_APPROVAL` / `SANITIZE` / `ASK_USER` |
| `risk_level` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `risk_score` | Numeric score for dashboard ranking |
| `reasons` | Human-readable, shown on the decision card |
| `triggered_policies` | Rule IDs that fired |
| `sensitive_entities` | Detected PII / secrets / code, already masked |
| `sanitized_payload` | Redacted payload when safe continuation is possible |
| `next_step` | `execute` / `execute_sanitized` / `ask_user` / `approval` / `stop` |
| `audit_id` | Set by the audit store at record time |

## 5. Tool registry

`ToolSpec` (`tool_specs/base.py`) carries the trusted metadata the guardrail uses
instead of believing the planner: `target_system`, `rollback_available`,
`default_risk_hints`, and `content_fields` (which argument keys carry scannable and
sanitizable content). In execution mode, an `API_CALL` naming an unregistered tool is
refused before evaluation — real side effects require declared metadata.

## 6. Evaluation metrics

The metrics DS is measured on, with where each is computed.

| Metric | Definition | Target | Source |
|---|---|---|---|
| Action evaluation completion rate | Proposals receiving a `DecisionResponse` | ≥ 95% | audit rows, `stage = 'action'` |
| Unsafe auto-allow rate | Curated unsafe cases decided `ALLOW` | 0 critical | `benchmarks/da_eval_runner.py` |
| Sensitive-data detection recall | Sensitive cases with the entity detected | ≥ 85% | DA eval set |
| Approval routing accuracy | High-risk cases routed to `NEED_APPROVAL`/`ASK_USER` | ≥ 90% | DA eval set |
| False block rate | Benign cases decided `BLOCK` | minimize | DA eval set |
| Policy coverage | Rules firing at least once across the eval set | report | `triggered_policies` |
| Guardrail evaluation latency | P50/P95 of `evaluate()` | P95 ≤ 500 ms | per-step `eval_ms` |
| Raw vs guarded overhead | Guarded ÷ raw execution time | ≤ 20% | Sprint 2 harness |
| Audit completeness | Action rows carrying request, decision, status, timestamp | ≥ 95% | `PostgresAuditStore.completeness()` |

**Counting rule.** Only audit rows with `stage = 'action'` are proposed tool calls.
The loop also screens the task text, terminal messages, and executor output; those are
recorded under `task_screen`, `terminal_screen`, and `observation_screen` so they do
not inflate any of the rates above.

The DA runner compares both `expected_decision` and `expected_risk_level` for every case.
Each case also declares `expectation_source` as either `da_approved` or `inferred`; the
19 DA-approved cases form the headline decision metrics and the 7 inferred cases are
reported separately. Sensitive cases declare `expected_entity_kinds`, which supplies
the independent denominator for detector recall. Task success is not reported by this
runner because its cases are dry-run proposals and do not execute a real task.
