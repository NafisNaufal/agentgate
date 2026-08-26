# Phase 1 — Detector Baseline, Scoring Design & Core Latency Budget

**Sprint:** Phase 1 (Jun 22–28) · **Owner:** Data Science
**PRD row:** "Research tool calling loop, action schema, LLM planner, detector baseline, policy/risk scoring design, and core latency budget."

## 1. Detector baseline

The detector layer went through three architectures. Only the last one survives in
the runtime; the earlier two are recorded here because the choice is the interesting
part.

| Architecture | How it worked | Why it was dropped |
|---|---|---|
| Regex-only | Pattern matching for emails, cards, key formats, payment/urgency wording | High recall on formatted secrets, near-zero on *semantic* risk. "Forward the quarterly figures to my personal address" matches nothing. |
| Hybrid | Regex first, LLM only on ambiguous cases | Two code paths, two failure modes, and the routing rule itself became the weakest link |
| **Full LLM (current)** | Six structured classifiers over one local model via Ollama | Catches semantic risk; single failure mode; prompts are reviewable by non-DS teammates |

**Six production classifiers** (`agentgate/detectors/`): PII, secrets/credentials,
source code + internal codenames, payment/phishing, prompt injection, and action
intent (bulk / destructive / external-send).

Two properties make an LLM detector safe to depend on:

- **Structured output, deterministically validated.** Every response is parsed
  against an explicit schema (`llm_validation.py`). A malformed field, an
  out-of-range confidence, or a self-contradictory answer (`has_pii: false` with a
  non-empty `items`) raises `LLMUnavailable` rather than being coerced into a
  permissive default.
- **Fail closed.** An unreachable model, a timeout, or an invalid response forces a
  `HIGH` risk floor and `NEED_APPROVAL`. The one thing a detector outage must never
  produce is `ALLOW`.

### Why detection is LLM-only but redaction is not

Redaction has to replace **exact character spans**. A classifier reliably answers
"is there a secret here?" but cannot be trusted to return character-exact offsets for
every occurrence, and a redaction that misses one span leaks the value it was meant
to hide. So detectors decide *whether* content is sensitive; `sanitizer.py` decides
*which characters* are replaced. That is the only place patterns remain.

## 2. Risk scoring design

Detectors return independent `risk_contribution` values in `[0, 1]`. They are
combined with a **noisy-OR** (`risk.py::combine`):

```
score = 1 - Π (1 - cᵢ)
```

Chosen over sum (which saturates past 1.0 and needs an arbitrary clamp) and over max
(which ignores corroborating signals entirely). Noisy-OR lets several weak signals
accumulate into a real score while never exceeding 1.0, which matches the intuition
that independent evidence compounds.

**Bands:** `< 0.3` LOW · `< 0.6` MEDIUM · `< 0.85` HIGH · `>= 0.85` CRITICAL.

**Accumulation cap.** Without a cap, enough MEDIUM findings eventually reach CRITICAL
and a legitimate-but-busy action gets blocked outright. `CRITICAL` is therefore
reserved for a categorically critical entity (a live credential) or a `CRITICAL`
policy floor; everything else caps at `0.84`, i.e. HIGH → `NEED_APPROVAL`. The design
preference is explicit: **route to a human rather than block**, except where the
signal is unambiguous.

**Policy floors** raise a score into a required band but never lower it, so a policy
can only make an action more restricted, never less.

## 3. Decision resolution

The final decision is the **strongest** of the policy decision and the risk-band
decision, ranked `ALLOW < SANITIZE < ASK_USER < NEED_APPROVAL < BLOCK`.

Two deliberate refinements:

- **Low confidence downgrades approval to a question.** If the planner itself was
  unsure (`confidence < 0.75`) on an impactful verb, `NEED_APPROVAL` becomes
  `ASK_USER` — a reviewer should not adjudicate a risk score computed from a guess.
  This only ever softens `NEED_APPROVAL`; a confirmed `BLOCK` is never softened.
- **Unredactable SANITIZE becomes approval.** If policy asks to sanitize but nothing
  actually changed, the action goes to a human rather than executing unmodified.

## 4. Core latency budget

The PRD targets **P95 ≤ 250 ms** for rule-based evaluation and **P95 ≤ 500 ms**
including detectors and audit write, with guarded API actions adding **≤ 20%**
overhead versus raw execution.

Per-stage budget for one `DecisionEngine.evaluate()`:

| Stage | Budget (P95) | Notes |
|---|---|---|
| ActionRequest build + action-space validation | < 1 ms | Pure dataclass work |
| Detector pipeline (6 classifiers) | 350 ms | Dominant cost; local model, no retries, per-request timeout |
| Policy matching | < 5 ms | Linear scan over ~20 rules |
| Risk scoring + decision resolution | < 1 ms | Arithmetic only |
| Sanitization | < 5 ms | Only when entities were found |
| Audit write | < 20 ms | Single INSERT, indexed table |
| **Total** | **≤ 500 ms** | |

**The detector pipeline is the entire budget.** Everything else is rounding error,
which is why optimization work belongs there and nowhere else. Known levers, in the
order they should be tried:

1. Run the six classifiers concurrently rather than sequentially — done in Sprint 2
   (`DecisionEngine.evaluate()` dispatches all detectors on a thread pool; see below).
2. Skip classifiers whose category cannot apply to the action type.
3. Cache by payload hash within a run (the same text is often screened twice: once as
   a proposal, once as an observation).
4. Smaller model, measured against the recall target before adopting. Rejected once
   already: `qwen2.5:3b` runs ~8x faster but produces two distinct false results
   (flags Python source as prompt injection; rates a plain email HIGH instead of
   MEDIUM severity, flipping an expected SANITIZE to NEED_APPROVAL). Do not revisit
   without re-validating against the full DA eval set.

The loop already records per-step `eval_ms`, so this budget is measurable today.

### Detector concurrency: implemented, and the finding behind it

Client-side concurrency alone was not the win it looked like on paper. Measured
directly against the Ollama HTTP API, bypassing AgentGate entirely: four concurrent
requests to a warm model completed in the same total wall time as four sequential
ones, with each request finishing in a staggered ~0.18s-spaced sequence — the
signature of the server queuing requests behind one worker, not serving them in
parallel. `OLLAMA_NUM_PARALLEL` defaults effectively to 1 on memory-constrained
hardware, and dispatching six concurrent HTTP calls into a single-slot queue buys
nothing but scheduling overhead.

`DecisionEngine.evaluate()` now dispatches all detectors on a thread pool regardless,
because it is necessary once the server side is configured to actually serve
concurrent requests — client-side sequencing would put a ceiling on throughput that no
server setting could remove. **`OLLAMA_NUM_PARALLEL` must be raised (e.g. to the
detector count, 6) for this to matter**; deployment docs should say so explicitly, not
leave it as an unstated assumption.

With `OLLAMA_NUM_PARALLEL=6` on an Apple M4, before/after via
`benchmarks/raw_vs_guarded.py --live` (same warm model, same machine, only the client
code changed):

| Case | Guarded P95 before | Guarded P95 after | Reduction |
|---|---|---|---|
| clean_api_read | 7190 ms | 5382 ms | 25.1% |
| sanitized_api_send | 9453 ms | 6083 ms | 35.7% |
| clean_browser_open | 8486 ms | 5244 ms | 38.2% |
| sanitized_browser_type | 9682 ms | 5803 ms | 40.1% |

Real, but sub-linear rather than the naive "1/6th of the sum" a reader might expect:
six requests still share one GPU's compute, so they overlap rather than truly run
independently. The reduction tracks the slowest single detector (`action_intent`,
consistently) rather than the sum of all six, which is the ceiling concurrent dispatch
can reach on shared hardware — the remaining gap to `action_intent`'s own latency is
where prompt/model-size work (lever 4, cautiously) would apply next, not further
concurrency work.
