# AgentGate

## Requirements

- Python 3.10+
- No third-party packages required for the core engine and CLI.
- Optional: [Ollama](https://ollama.com) with `gemma3:4b` pulled, only if you want
  the Gemma-backed injection detector (`--llm-detector` flag) instead of the default
  regex-only detection.

## Setup

```bash
git clone https://github.com/NafisNaufal/agentgate.git
cd agentgate
python3 -m unittest discover -s tests   # verify the install (35 tests, 4 expected failures)
```

No `pip install` is required to run the CLI — it works directly from the repo root.

## Running the CLI

```bash
# List available demo scenarios
python -m agentgate list

# List the registered tool catalog
python -m agentgate tools

# Evaluate a single action
python -m agentgate eval API_CALL --domain code_security --target-system GitHub \
  --payload "deploy key AKIAIOSFODNN7EXAMPLE" --risk-hint external_send

# Run the labeled evaluation suite
python -m agentgate eval-suite

# Replay a full scenario (works standalone; some scenarios are blocked pending
# a real Executor and will print a clear message rather than fail silently)
python -m agentgate run booking_message
python -m agentgate run sensitive_code

# Raw-vs-guarded latency benchmark
python -m agentgate benchmark --repeats 40
```

## Optional: live LLM planner

By default the demo runs key-free via scenario replay. To use a real LLM as the
planner instead:

```bash
export AGENTGATE_LLM_PROVIDER=openrouter   # or openai | gemini | anthropic
export AGENTGATE_LLM_API_KEY=sk-...
export AGENTGATE_LLM_MODEL=openai/gpt-4o-mini   # optional

python -m agentgate plan "archive old promotional emails"
```

## Optional: Gemma-backed injection detector

```bash
ollama pull gemma3:4b
ollama serve   # if not already running

python -m agentgate eval API_CALL --context "some text to check" --llm-detector
python -m agentgate eval-suite --llm-detector
```

Falls back to regex-only detection automatically if Ollama is not reachable.

## Benchmarks

```bash
cd benchmarks
python3 bakeoff.py --backends regex
python3 coverage_eval.py
```

`bakeoff.py --backends gemini_llm,gemini_knn` additionally requires
`AGENTGATE_LLM_API_KEY` (or `GEMINI_API_KEY`) set to a Gemini API key.
`bakeoff.py --backends slm,gemma_llm` requires a local Ollama server.
