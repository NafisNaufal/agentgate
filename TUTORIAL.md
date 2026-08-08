# AgentGate Tutorial

This tutorial explains how to run AgentGate as a CLI guardrail and how to enable its
GitHub, local filesystem, and Playwright executors.

AgentGate is not currently a long-running HTTP service. It is a CLI and Python
library that evaluates every proposed action before optionally executing it:

```text
Task -> Planner -> Proposal -> ActionRequest -> DecisionEngine
     -> DecisionRouter -> Executor -> ExecutionResult
```

The enforcement rules are:

| Decision | Result |
|---|---|
| `ALLOW` | Execute only when `--execute` is present |
| `SANITIZE` | Execute only sanitized content when `--execute` is present |
| `BLOCK` | Never execute |
| `NEED_APPROVAL` | Never execute; return `awaiting_approval` |
| `ASK_USER` | Never execute; return `ask_user` |

Real execution is always opt-in. Running a scenario without `--execute` is a safe
guardrail-only dry run.

## 1. Prerequisites

You need:

- Python 3.10 or newer
- Git
- Ollama with the configured detector model
- A GitHub token only if you intend to execute GitHub actions
- Playwright and Chromium only if you intend to execute browser actions

Check Python:

```bash
python3 --version
```

On Windows, use `py` if `python3` is unavailable:

```powershell
py --version
```

## 2. Install AgentGate

Clone the repository and enter it:

```bash
git clone https://github.com/NafisNaufal/agentgate.git
cd agentgate
```

Install the core and test dependencies:

```bash
python3 -m pip install -e ".[dev]"
```

The core guardrail and GitHub/filesystem executors use only the Python standard
library, but full-LLM detection requires the external Ollama runtime. Install the
optional browser dependencies only when needed:

```bash
python3 -m pip install -e ".[dev,browser]"
python3 -m playwright install chromium
```

Windows equivalents:

```powershell
py -m pip install -e ".[dev,browser]"
py -m playwright install chromium
```

## 3. Configure Environment Variables

AgentGate reads variables from the process environment. It does not automatically
load `.env` files. `.env.example` contains placeholders for all executor settings.

### macOS and Linux

```bash
export OLLAMA_HOST=http://localhost:11434
export AGENTGATE_LLM_DETECTOR_MODEL=qwen2.5:7b
export AGENTGATE_LLM_DETECTOR_TIMEOUT=30
export GITHUB_TOKEN=
export GITHUB_API_URL=https://api.github.com
export AGENTGATE_SANDBOX_ROOT=./sandbox
export AGENTGATE_FILE_MAX_BYTES=1048576
export AGENTGATE_BROWSER_HEADLESS=true
export AGENTGATE_BROWSER_ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
export AGENTGATE_SCREENSHOT_DIR=./artifacts/screenshots
```

### Windows PowerShell

```powershell
$env:OLLAMA_HOST = "http://localhost:11434"
$env:AGENTGATE_LLM_DETECTOR_MODEL = "qwen2.5:7b"
$env:AGENTGATE_LLM_DETECTOR_TIMEOUT = "30"
$env:GITHUB_TOKEN = ""
$env:GITHUB_API_URL = "https://api.github.com"
$env:AGENTGATE_SANDBOX_ROOT = ".\sandbox"
$env:AGENTGATE_FILE_MAX_BYTES = "1048576"
$env:AGENTGATE_BROWSER_HEADLESS = "true"
$env:AGENTGATE_BROWSER_ALLOWED_ORIGINS = "http://localhost:8000,http://127.0.0.1:8000"
$env:AGENTGATE_SCREENSHOT_DIR = ".\artifacts\screenshots"
```

Leave `GITHUB_TOKEN` empty until the GitHub tutorial. Never place a real token in a
scenario, source file, CLI argument, or planner prompt.

Start Ollama in one terminal:

```bash
ollama serve
```

Install the detector model from another terminal:

```bash
ollama pull qwen2.5:7b
```

## 4. Verify the Installation

List registered scenarios:

```bash
python3 -m agentgate list
```

List registered API tools and trusted risk metadata:

```bash
python3 -m agentgate tools
```

Run the test suite:

```bash
python3 -m unittest discover -s tests -v
```

Run the built-in scenarios through the full-LLM detector:

```bash
python3 -m agentgate run sensitive_code
python3 -m agentgate run booking_message
```

These commands are dry runs. They do not read local files, contact GitHub, or launch
a browser because `--execute` is absent.

## 5. Understand Scenario Files

The default `ReplayPlanner` reads JSON files from `scenarios/`. Each scenario
contains a task and a sequence of proposed actions.

A minimal scenario looks like this:

```json
{
  "name": "example",
  "title": "Example scenario",
  "task": "Perform one guarded action",
  "steps": [
    {
      "action_type": "FILE_READ",
      "arguments": {"path": "public/readme.txt"},
      "rationale": "Read a sandbox file",
      "confidence": 0.99
    },
    {
      "action_type": "DONE",
      "arguments": {"result_summary": "Finished"}
    }
  ]
}
```

AgentGate validates and evaluates every non-terminal step. Original structured
arguments are retained for execution, but credentials remain in environment
variables and are never added to the `ActionRequest`.

## 6. Local Filesystem Tutorial

The filesystem executor supports `FILE_READ` only. It does not implement arbitrary
write or delete actions.

### Step 1: Create the sandbox content

On macOS or Linux:

```bash
mkdir -p sandbox/public
printf 'Hello from the AgentGate sandbox.\n' > sandbox/public/readme.txt
```

On Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force sandbox\public
Set-Content -Encoding utf8 sandbox\public\readme.txt "Hello from the AgentGate sandbox."
```

### Step 2: Set the sandbox configuration

```bash
export AGENTGATE_SANDBOX_ROOT=./sandbox
export AGENTGATE_FILE_MAX_BYTES=1048576
```

### Step 3: Add a tutorial scenario

Create `scenarios/tutorial_file_read.json`:

```json
{
  "name": "tutorial_file_read",
  "title": "Read a local sandbox file",
  "task": "Read the public tutorial file",
  "steps": [
    {
      "action_type": "FILE_READ",
      "arguments": {"path": "public/readme.txt"},
      "rationale": "Read a user-approved file inside the sandbox",
      "confidence": 0.99
    },
    {
      "action_type": "DONE",
      "arguments": {"result_summary": "Sandbox read complete"}
    }
  ]
}
```

### Step 4: Dry-run the scenario

```bash
python3 -m agentgate run tutorial_file_read
```

The expected outcome is `would_execute`. The file is not read yet.

### Step 5: Execute the allowed read

```bash
python3 -m agentgate run tutorial_file_read --execute
```

The expected outcome is `executed`, with a bounded and sanitized result.

### Filesystem protections

AgentGate rejects:

- `../outside.txt`
- Absolute paths outside the sandbox
- Windows drive escapes such as `C:\secrets\token.txt`
- Symlinks or reparse points that resolve outside the sandbox
- Directories, binary files, invalid UTF-8, and oversized files

Only relative paths beneath `AGENTGATE_SANDBOX_ROOT` should be proposed.

## 7. GitHub Tutorial

Use a dummy repository. Do not test write actions against production repositories.

Implemented tools:

| Tool | Required arguments |
|---|---|
| `github_read_repo` | `owner`, `repo` |
| `github_read_file` | `owner`, `repo`, `path`; optional `ref` |
| `github_create_issue` | `owner`, `repo`, `title`; optional `body` |
| `github_create_issue_comment` | `owner`, `repo`, `issue_number`, `body` |
| `github_create_gist` | `files`; optional `description` and `public` |

### Step 1: Create a restricted token

Prefer a fine-grained GitHub token restricted to one dummy repository. Grant only
the permissions needed by the tutorial:

- Metadata read access for repository metadata
- Contents read access for repository files
- Issues write access for issue and comment creation
- Gist permission only if gist creation is required

GitHub gist permissions are account-level and may require a separate classic token
with only the `gist` scope if they are not available on your fine-grained token. Do
not broaden a repository token merely to make the gist tutorial work.

### Step 2: Export the token

```bash
export GITHUB_TOKEN=your_test_token
export GITHUB_API_URL=https://api.github.com
```

PowerShell:

```powershell
$env:GITHUB_TOKEN = "your_test_token"
$env:GITHUB_API_URL = "https://api.github.com"
```

### Step 3: Read repository metadata

Create `scenarios/tutorial_github_read.json`, replacing `YOUR_TEST_OWNER` and
`YOUR_TEST_REPO` with a dummy repository:

```json
{
  "name": "tutorial_github_read",
  "title": "Read dummy repository metadata",
  "task": "Inspect a dummy GitHub repository",
  "steps": [
    {
      "action_type": "API_CALL",
      "arguments": {
        "tool_name": "github_read_repo",
        "owner": "YOUR_TEST_OWNER",
        "repo": "YOUR_TEST_REPO"
      },
      "rationale": "Read safe repository metadata",
      "confidence": 0.99
    },
    {
      "action_type": "DONE",
      "arguments": {"result_summary": "Repository metadata checked"}
    }
  ]
}
```

Dry-run first:

```bash
python3 -m agentgate run tutorial_github_read
```

Execute only after checking the decision:

```bash
python3 -m agentgate run tutorial_github_read --execute
```

### Step 4: Create a test issue

Create `scenarios/tutorial_github_issue.json`:

```json
{
  "name": "tutorial_github_issue",
  "title": "Create an issue in a dummy repository",
  "task": "Create a harmless tutorial issue",
  "steps": [
    {
      "action_type": "API_CALL",
      "arguments": {
        "tool_name": "github_create_issue",
        "owner": "YOUR_TEST_OWNER",
        "repo": "YOUR_TEST_REPO",
        "title": "AgentGate tutorial test",
        "body": "This issue was created during an AgentGate executor tutorial."
      },
      "rationale": "Create one harmless issue in a dummy repository",
      "confidence": 0.99
    },
    {
      "action_type": "DONE",
      "arguments": {"result_summary": "Issue proposal processed"}
    }
  ]
}
```

Always inspect a dry run before enabling the write:

```bash
python3 -m agentgate run tutorial_github_issue
python3 -m agentgate run tutorial_github_issue --execute
```

The write runs only if the final decision is `ALLOW`. If policy returns
`NEED_APPROVAL`, AgentGate stops with `awaiting_approval` and does not create the
issue. There is intentionally no automatic approval shortcut.

### GitHub safety behavior

- The token is loaded only from `GITHUB_TOKEN`.
- The token is not placed in planner input, `ActionRequest`, results, or CLI output.
- API response sizes and decoded file sizes are bounded.
- Cross-origin redirects cannot receive the authorization header.
- Registered write tools receive trusted risk hints even if the planner omits them.
- Structured arguments are fingerprinted between evaluation and execution.

## 8. Playwright Browser Tutorial

Browser execution defaults to `localhost` and `127.0.0.1`. Arbitrary production
sites are not silently allowed.

### Step 1: Install Playwright

```bash
python3 -m pip install -e ".[dev,browser]"
python3 -m playwright install chromium
```

### Step 2: Create a local mock page

Create `sandbox/browser-demo/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>AgentGate Browser Demo</title>
  </head>
  <body>
    <h1>Message Sandbox</h1>
    <textarea aria-label="Customer message"></textarea>
    <button type="button" onclick="document.querySelector('#status').textContent = 'Sent locally'">
      Send Message
    </button>
    <p id="status">Not sent</p>
  </body>
</html>
```

### Step 3: Start a local web server

Run this in a separate terminal:

```bash
python3 -m http.server 8000 --directory sandbox/browser-demo
```

### Step 4: Configure browser safety

```bash
export AGENTGATE_BROWSER_HEADLESS=true
export AGENTGATE_BROWSER_ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
export AGENTGATE_SCREENSHOT_DIR=./artifacts/screenshots
```

Set headless mode to `false` if you want to watch the browser:

```bash
export AGENTGATE_BROWSER_HEADLESS=false
```

### Step 5: Add a browser scenario

Create `scenarios/tutorial_browser.json`:

```json
{
  "name": "tutorial_browser",
  "title": "Use the local browser sandbox",
  "task": "Type a sanitized message into a local mock page",
  "steps": [
    {
      "action_type": "BROWSER_OPEN",
      "arguments": {"url": "http://localhost:8000"},
      "domain": "booking_style",
      "rationale": "Open the local browser sandbox",
      "confidence": 0.99
    },
    {
      "action_type": "BROWSER_SNAPSHOT",
      "arguments": {},
      "domain": "booking_style",
      "rationale": "Map visible interactive controls to short element IDs",
      "confidence": 0.99
    },
    {
      "action_type": "BROWSER_TYPE",
      "arguments": {
        "element_id": "1",
        "value": "Contact john@example.com about booking BK-123"
      },
      "domain": "booking_style",
      "risk_hint": ["external_send"],
      "rationale": "Type a message into the local textarea",
      "confidence": 0.99
    },
    {
      "action_type": "BROWSER_CLICK",
      "arguments": {"element_id": "2"},
      "domain": "booking_style",
      "rationale": "Click the local Send Message button",
      "confidence": 0.99
    },
    {
      "action_type": "BROWSER_SCREENSHOT",
      "arguments": {},
      "domain": "booking_style",
      "rationale": "Capture a controlled screenshot artifact",
      "confidence": 0.99
    },
    {
      "action_type": "DONE",
      "arguments": {"result_summary": "Browser tutorial complete"}
    }
  ]
}
```

For this exact mock page, the snapshot maps the textarea to element `1` and the
button to element `2`. Element IDs are snapshot-specific and become stale after
navigation or actions that may change the page. A live planner should always use the
IDs returned by the latest snapshot rather than guessing them.

### Step 6: Dry-run and execute

```bash
python3 -m agentgate run tutorial_browser
python3 -m agentgate run tutorial_browser --execute
```

The `BROWSER_TYPE` step should receive `SANITIZE`. The executor types redacted text,
such as `[REDACTED_EMAIL]`, instead of the original email address. Screenshots are
saved under `AGENTGATE_SCREENSHOT_DIR`; scenario-supplied output paths are ignored.

### Browser action vocabulary

```text
BROWSER_OPEN(url)
BROWSER_SNAPSHOT()
BROWSER_CLICK(element_id)
BROWSER_TYPE(element_id, value)
BROWSER_SELECT(element_id, option)
BROWSER_SUBMIT(element_id)
BROWSER_SCREENSHOT()
```

Snapshots contain only bounded visible text and simplified interactive-element
metadata. Raw full HTML and internal selectors are not returned to the planner.

## 9. Inspect JSON Results

Add `--json` to receive structured, audit-ready output:

```bash
python3 -m agentgate run tutorial_file_read --json
```

Execution mode also supports JSON output:

```bash
python3 -m agentgate run tutorial_file_read --execute --json
```

Executor output is bounded and sanitized before serialization. The output contains
step proposals, normalized requests, decisions, enforcement outcomes, and safe
execution results when an executor ran.

## 10. Use AgentGate as a Python Library

The same guarded lifecycle can be embedded in another application. Do not call a
provider executor directly; route actions through `AgentLoop` and `DecisionRouter` so
the `DecisionEngine` always evaluates them first.

```python
from agentgate.decision import DecisionEngine
from agentgate.executors import build_default_executor_registry
from agentgate.loop import AgentLoop
from agentgate.planner import ReplayPlanner
from agentgate.router import DecisionRouter

steps = [
    {
        "action_type": "FILE_READ",
        "arguments": {"path": "public/readme.txt"},
        "rationale": "Read an approved sandbox file",
        "confidence": 0.99,
    }
]

executors = build_default_executor_registry()
router = DecisionRouter(executors, execute=True)
decider = DecisionEngine()
loop = AgentLoop(ReplayPlanner(steps), router, decider=decider)

try:
    result = loop.run("Read the tutorial file")
    print(result.to_dict())
finally:
    executors.close()
```

Use `DecisionRouter()` without `execute=True` for dry-run behavior.

## 11. Exit Statuses

In real execution mode, the CLI uses these exit statuses:

| Exit code | Meaning |
|---|---|
| `0` | Run completed |
| `1` | Blocked, failed, executor failure, or max steps reached |
| `2` | Awaiting approval or user clarification |

Dry-run scenarios retain their current replay behavior and normally return `0` after
showing every guardrail decision.

## 12. Troubleshooting

### `python3: command not found`

Use `python` on systems where it points to Python 3, or use `py` on Windows.

### `Playwright is not installed`

```bash
python3 -m pip install -e ".[browser]"
python3 -m playwright install chromium
```

### LLM detector is unavailable

Start Ollama in one terminal:

```bash
ollama serve
```

Then install the configured model from another terminal:

```bash
ollama pull "${AGENTGATE_LLM_DETECTOR_MODEL:-qwen2.5:7b}"
```

AgentGate fails closed to `NEED_APPROVAL`; it does not fall back to a legacy detector.

### `Executable doesn't exist` or browser not installed

Install Chromium again:

```bash
python3 -m playwright install chromium
```

### Browser origin is not allowed

Check the exact scheme, hostname, and port in the URL and update the allowlist only for environments
you control:

```bash
export AGENTGATE_BROWSER_ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
```

Do not add broad production domains merely to bypass a policy decision.

### `GITHUB_TOKEN is not configured`

Export the token in the same terminal that runs AgentGate. Do not place it in the
scenario JSON.

### GitHub returns `403`

Check that the token is restricted to the intended dummy repository and has the
specific Contents, Issues, or Gist permission required by the selected tool.

### Filesystem sandbox violation

Use a relative path beneath `AGENTGATE_SANDBOX_ROOT`. Do not use `..`, absolute
paths, drive-qualified paths, or links to files outside the sandbox.

### `awaiting_approval`

AgentGate deliberately did not execute the action. Approval persistence and resume
execution are not implemented in this MVP, so there is no auto-approval flag.

## 13. Safety Checklist

Before using `--execute`:

- Run the same scenario without `--execute` first.
- Use a dummy GitHub repository and least-privilege token.
- Keep local files inside the configured sandbox.
- Keep browser automation on localhost or explicit test hosts.
- Review `SANITIZE` output before external communication.
- Confirm `NEED_APPROVAL`, `ASK_USER`, and `BLOCK` actions remain unexecuted.
- Never place real credentials in scenarios, prompts, source code, or CLI arguments.

This implementation does not provide Gmail, Google Calendar, or Telegram executors.
