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

The full lifecycle works end to end: a detector suite, policy engine, risk scoring,
and sanitizer are all implemented and wired into the CLI. Real execution connectors
and persistent audit storage are still ahead — see [Status](#status).

## Setup from scratch

Three steps, no experience with this repo required:

**1. Clone it.**
```bash
git clone https://github.com/NafisNaufal/agentgate.git
cd agentgate
```

**2. Run the setup script.** It checks your Python version, installs
[Ollama](https://ollama.com) if you don't have it, downloads the model the
guardrail uses, and runs a quick self-test so you know it worked.
```bash
./scripts/setup.sh          # macOS / Linux
```
```powershell
.\scripts\setup.ps1          # Windows (PowerShell)
```

**3. Try it.**
```bash
python3 -m agentgate list
python3 -m agentgate run booking_message
```

That's it — you should see a scenario play out with allow/block/approve decisions
printed for each step.

**Don't want to install Ollama?** Nothing breaks — pass `--no-ollama` /
`-NoOllama` to the setup script, or just skip step 2 and go straight to step 3.
AgentGate is designed so the guardrail always works even without a local LLM; you
just won't get the extra paraphrase-detection boost `hybrid` (the default) can add
when Ollama is available. See [Detector architectures](#detector-architectures) for
what that means.

<details>
<summary>Manual setup (no script)</summary>

Requires **Python 3.10+**. Pure stdlib, no third-party dependencies.

```bash
python3 -m unittest discover -s tests   # sanity check
python3 -m agentgate list
python3 -m agentgate run booking_message
python3 -m agentgate eval API_CALL --payload "key AKIAIOSFODNN7EXAMPLE"
```

To also enable the LLM-backed part of the default `hybrid` architecture, install
Ollama and pull a model:

| OS | Install Ollama |
|---|---|
| macOS | `brew install ollama`, or download from [ollama.com/download](https://ollama.com/download) |
| Linux | `curl -fsSL https://ollama.com/install.sh \| sh` |
| Windows | `winget install --id Ollama.Ollama -e`, or download from [ollama.com/download](https://ollama.com/download) |

```bash
ollama serve                # if it isn't already running as a background service
ollama pull qwen2.5:7b      # the model this project's bake-off recommends (see below)
```
</details>

## How it works

- **`schemas.py`** — the two contracts everything is built around: `ActionRequest`
  (a proposed action, normalized) and `DecisionResponse` (allow/block/approve/
  sanitize/ask, with reasons).
- **`action_space.py`** — a closed vocabulary of action verbs; anything outside it
  is rejected before evaluation.
- **`planner/`** — proposes the next action. A deterministic scenario-replay
  planner (no API key needed) and an optional live LLM planner.
- **`detectors/`** — six detectors (PII, secrets, source code, payment/phishing,
  prompt injection, action-intent) plus two LLM-backed architectures for
  prompt-injection specifically — see [Detector architectures](#detector-architectures).
- **`policy/`** — declarative JSON policy packs per domain, matched against
  detector findings.
- **`risk.py`** — combines detector findings into a risk score and band.
- **`sanitizer.py`** — redacts detected sensitive content for `SANITIZE` decisions.
- **`decision.py`** — ties detectors + policy + risk + sanitizer together into one
  `DecisionResponse`.
- **`router.py`** — enforces the decision so a risky action is never silently
  allowed to proceed.
- **`loop.py`** — the function-calling loop, built from scratch.
- **`tools.py`** — the shape of a tool registry, with illustrative entries; not yet
  consulted by the loop or planner.

## Detector architectures

Simple version: `regex` is fast pattern matching with fixed rules — great at
catching obvious cases, blind to reworded ones. `hybrid` (the default) tries regex
first and only calls a local LLM when regex genuinely can't tell, so most actions
never pay for a model call, but paraphrased attacks still get caught. `llm_first`
sends everything to the LLM directly, no regex fast-path.

| Architecture | How it works | Select with |
|---|---|---|
| `hybrid` (default) | Regex fast-path; LLM only when regex is unsure | `--architecture hybrid` |
| `llm_first` | Every action goes through the LLM directly | `--architecture llm_first` |
| `regex` | No LLM at all, ever | `--architecture regex` |

Select an architecture with the `--architecture` flag on `run`/`eval`, or set it
once for the whole shell via `AGENTGATE_DETECTOR_ARCHITECTURE`:

```bash
python -m agentgate eval API_CALL --context "some text" --architecture llm_first
# or:
export AGENTGATE_DETECTOR_ARCHITECTURE=regex
python -m agentgate run booking_message
```

To pick which model the LLM architectures call, either pull a different model and
set `AGENTGATE_LLM_DETECTOR_MODEL` (defaults to `qwen2.5:7b` if unset, matching
what `scripts/setup.sh` pulls), or point at a non-default Ollama host with
`OLLAMA_HOST`:

```bash
ollama pull qwen2.5:1.5b
export AGENTGATE_LLM_DETECTOR_MODEL=qwen2.5:1.5b
```

**Note:** `hybrid` being the default does not mean Ollama is required. It only
*skips* the LLM call when regex already resolves a case — if Ollama isn't running
at all, `hybrid` fails safe and behaves exactly like plain `regex` (no crash, no
error, just no paraphrase-detection boost). Worth checking `ollama serve` is
actually running if results look like plain regex when you expected the LLM to
kick in.

### Bake-off results

Measured with `benchmarks/detector_bakeoff.py` against 42 labeled prompt-injection
cases (paraphrased/evasive attacks plus benign text designed to look suspicious).

**Hardware caveat:** run locally on an Apple M4 laptop (arm64, 10 cores, 16GB RAM,
Metal GPU) with Ollama's `num_gpu` forced to `0` to approximate CPU-only inference.
The real deployment target is a 48-core x86 VM, 377GB RAM, **no GPU at all**
(confirmed via `nvidia-smi` / `lspci` on that host). Apple Silicon and generic x86
server cores are not the same hardware — treat the *relative* ranking between
models/architectures below as informative, and the *absolute* millisecond numbers
as approximate only. Re-run this exact script on the real host before finalizing a
production model choice.

**Architecture comparison** (regex vs. hybrid vs. llm_first, `qwen2.5:1.5b`):

| architecture | model | f1 | precision | recall | evasion_recall | hardbenign_fp | p50 latency |
|---|---|---|---|---|---|---|---|
| regex | – | 0.625 | 1.0 | 0.455 | 0.0 | 0.0 | 0.0ms |
| hybrid | qwen2.5:1.5b | 0.952 | 1.0 | 0.909 | 0.833 | 0.0 | 387.5ms |
| llm_first | qwen2.5:1.5b | 0.842 | 1.0 | 0.727 | 0.833 | 0.0 | 392.5ms |

`hybrid` beats `llm_first` on the same model because regex's fast path already
resolves the easy cases, leaving the LLM only the genuinely ambiguous remainder —
`llm_first` gets no such help and classifies everything cold. That's why the model
sweep below only tests `hybrid`.

**Model sweep within `hybrid`** (7 models against the 42-case eval set; latency not
a selection factor per the PM's ask — accuracy is):

| model | f1 | precision | recall | evasion_recall | hardbenign_fp | p50 latency |
|---|---|---|---|---|---|---|
| qwen2.5:1.5b | 0.846 | 0.733 | 1.0 | 1.0 | 0.625 | 368.2ms |
| qwen2.5:3b | 0.955 | 0.955 | 0.955 | 0.917 | 0.0 | 617.1ms |
| **qwen2.5:7b** | 0.952 | 1.0 | 0.909 | 0.833 | 0.0 | 1251.5ms |
| gemma3:4b | 0.93 | 0.952 | 0.909 | 0.833 | 0.125 | 2224.0ms |
| gemma3:12b | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 6713.6ms |
| llama3.1:8b | 0.9 | 1.0 | 0.818 | 0.667 | 0.0 | 1309.2ms |
| phi4 | 0.9 | 1.0 | 0.818 | 0.667 | 0.0 | 2355.7ms |

**Important methodology lesson, not just a results table:** the eval-set numbers
above do not by themselves determine the pick. Two models that scored well here
were checked against the three demo scenarios (`booking_message`, `sensitive_code`,
`productivity_archive` — real action text, not in the 42-case set) and failed:

- `qwen2.5:3b` looked like the standout on paper, but reliably false-positived on
  an ordinary bulk-archive action and a payment-message send in the demo
  scenarios, run repeatedly. Not visible in the eval-set numbers at all.
- `gemma3:12b` scored a perfect 1.0 here, but also false-positived on the
  `sensitive_code` scenario, and at 7-30 seconds per call in practice it's edging
  toward the request timeout for basically no accuracy benefit over smaller models.

`qwen2.5:7b` is the only model that came back clean across all three demo
scenarios, checked repeatedly (5/5 on the case that broke every other model). Its
eval-set F1 (0.952) is very good, not literally the top number, but it's the one
result that's actually been cross-checked against real out-of-distribution action
text rather than just the benchmark's own labeled set.

Two real bugs surfaced and were fixed during this cross-checking, both worth
knowing about since they affected every model's numbers above:
1. `ActionRequest.scan_text` was including the same payload twice (once raw, once
   whitespace-flattened) whenever a payload had newlines — duplicated content in
   the prompt reads as suspicious to an LLM classifier, and it was also silently
   double-counting entities for the regex detectors. Fixed to dedupe on
   whitespace-normalized content.
2. The injection-detection system prompt originally asked the model to also flag
   "data-exfiltration attempts," which overlaps with what `SourceCodeDetector` /
   `PaymentPhishingDetector` already own — it was overriding their intended
   `NEED_APPROVAL` outcome with `BLOCK` on every model tested. Narrowed the prompt
   to instruction-override attempts only; the numbers above reflect the fix.

**Working recommendation:** `hybrid` is the default architecture, `qwen2.5:7b` is
the recommended model — the only one validated clean against real scenario text,
not just the eval set. `qwen2.5:1.5b`/`qwen2.5:3b` are lighter options if
resources are tight, but re-check them against real traffic before trusting them;
don't take a perfect eval-set score as the final word. This should also be
re-validated once the script is run on the actual deployment VM.

## Project layout

```
agentgate/
  schemas.py         ActionRequest / DecisionResponse contracts
  action_space.py     registered action vocabulary + validator
  detectors/           six regex detectors + two LLM-backed architectures
  policy/               policy engine + JSON packs
  risk.py              risk scoring
  sanitizer.py         redaction for SANITIZE decisions
  decision.py          DecisionEngine: detectors + policy + risk + sanitizer
  router.py            decision enforcement
  loop.py              function-calling loop
  tools.py             tool registry shape (defined, not yet wired in)
  planner/              planner interface, replay planner, optional LLM planner
  cli.py               CLI demo (list / tools / run / eval)
scenarios/            demo scenarios for the replay planner
benchmarks/           detector architecture bake-off + labeled eval data
scripts/              setup.sh / setup.ps1 - one-command environment setup
tests/                unittest suite
```

## Design notes

**Known risks in a custom agent loop, and how each is handled here:**
- *An untrusted planner proposes something unsafe, or doesn't flag its own risk* —
  the planner only proposes; the DecisionEngine judges independently.
- *The planner itself was unsure what the user meant* — a risky action with planner
  confidence below 0.75 gets routed to `ASK_USER` instead of `NEED_APPROVAL`;
  clarifying intent comes before judging a risk score computed from a guess. This
  never softens a confirmed `BLOCK`/`SANITIZE` finding, only a `NEED_APPROVAL`.
- *Malformed or off-vocabulary tool calls* — rejected by `action_space.py` before
  they ever reach evaluation.
- *A run that never terminates* — bounded by `max_steps`, plus explicit `DONE`/
  `FAIL` terminal actions.
- *The planner itself fails* (a live LLM call times out or errors) — caught in
  `loop.py`, turned into a failed run with a clear reason, not an uncaught
  exception.
- *Schema drift as more pieces get added* — the `ActionRequest` /
  `DecisionResponse` contract in `schemas.py` is meant to stay stable.

**Latency budget:** target is P95 ≤ 250ms for rule-based evaluation. Regex-based
evaluation runs in low single-digit milliseconds. The default `hybrid` architecture
only pays LLM latency for the cases regex can't resolve on its own — see
[Bake-off results](#bake-off-results) above for measured numbers (~572ms p50 for
the recommended hybrid + qwen2.5:7b combination, CPU-only on the benchmark
laptop; accuracy was prioritized over latency for this model choice).

**Evaluation metrics (defined, measured once a labeled harness lands):** completion
rate, decision accuracy, unsafe auto-allow rate (target 0%), false-block rate,
approval-routing accuracy, sensitive-data detection recall.

## Status

**Working now:** the full lifecycle (propose → validate → evaluate → enforce) runs
end to end via the CLI. Detectors, policy engine, risk scoring, sanitizer, and
decision engine are implemented and tested. Two LLM-backed detector architectures
were built and benchmarked; `hybrid` is the default and fails safe to regex-only
behavior if Ollama isn't available.

**In progress / planned next:**
- Wiring the tool registry into the planner, with a full tool catalog and
  per-tool safety defaults.
- Real execution connectors (Gmail, GitHub, Stripe, browser automation) behind a
  stable executor interface, and an approval queue for `NEED_APPROVAL` decisions —
  both Data Engineering scope, built against the existing decision contract.
- Persistent audit storage.
- A labeled evaluation harness with test data reviewed independently of whoever
  implements the detectors, to keep the accuracy numbers honest.

## Optional: live LLM planner

```bash
export AGENTGATE_LLM_PROVIDER=gemini   # or openai | anthropic | openrouter
export AGENTGATE_LLM_API_KEY=...
```

The LLM only proposes actions — it never decides whether one is safe.
