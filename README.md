# Pengetic

<p align="center">
  <img src="frontend/public/pengetic-logo.png" alt="Pengetic logo" width="760" />
</p>

Pengetic is a local-first defensive web assessment platform for authorized security work. It combines a scope-gated assessment engine, a FastAPI backend, a React + Tailwind GUI, SQLite persistence, and a local Ollama-backed planner service.

It is built to stay closed by default:

- no scope, no run
- no active action without approval
- no destructive testing
- no brute force, credential attacks, persistence, or evasion
- no unrestricted shell access for the LLM
- no active diagnostic action without operator approval

## What Pengetic Does

- Validates a versioned YAML scope package before work begins.
- Builds a risk-labelled assessment plan from the validated scope.
- Executes passive-safe checks automatically.
- Queues active checks for explicit approval.
- Persists runs, approvals, findings, logs, artifacts, and reports in SQLite.
- Persists the selected Ollama model locally so the preferred planner survives reloads.
- Shows an Engine Pulse status from the Ollama Tags API in the GUI footer.
- Renders a dark security-operations GUI for reviewing scope, plans, live runs, approvals, and reports.
- Includes a scope template wizard for one-click YAML generation from validated inputs.
- Includes structured tool intelligence with normalized results, persisted artifacts, and cross-tool evidence correlation.
- Includes scoped HTTP, header, TLS, DNS, route, technology-fingerprint, and Nmap diagnostic modules.
- Provides a confirmation-gated workspace purge for local administrative resets.
- Uses a local Ollama service to summarize assessment state and propose the next allowed step.

## Architecture

Pengetic is split into these layers:

1. Scope validation and policy gating.
2. Assessment planning and approval handling.
3. Normalized diagnostic tools and evidence capture.
4. SQLite persistence, correlation, and run state tracking.
5. FastAPI API and React GUI.
6. Optional local LLM planning through Ollama.

The existing assessment engine is reused internally. The V2 platform adds a backend, a frontend, and a persistent workflow around it.

## Repository Layout

```text
src/pengetic/        FastAPI backend, CLI, state machine, storage, LLM planner
src/scopeguard/      Legacy assessment engine reused internally by Pengetic
frontend/            React + Tailwind GUI
frontend/public/     Logo and browser icon assets
docs/                Architecture and policy notes
examples/            Demo scope package
tests/               Backend and engine regression tests
data/                SQLite database and app state
artifacts/           Run artifacts, logs, evidence, reports
```

## Safety Model

Pengetic is designed for authorized assessments only.

| Risk class | Behavior |
| --- | --- |
| `PASSIVE_SAFE` | Runs automatically if the tool is allowed by scope. |
| `LOW_RISK_ACTIVE` | Requires explicit approval. |
| `HIGH_RISK_ACTIVE` | Requires explicit approval and should be used sparingly. |
| `FORBIDDEN` | Never executed. |

The LLM can summarize state and recommend the next allowed step, but it cannot execute arbitrary shell commands or bypass approval gates.

## Scope Package

The scope package is a YAML file with explicit host, route, and tooling boundaries.

Required top-level fields:

- `version`
- `name`
- `primary_domain`
- `base_url`
- `allowed_subdomains`
- `allowed_urls`
- `out_of_scope_assets`
- `login_areas_allowed`
- `apis_allowed`
- `tool_allowlist`
- `rate_limits`
- `testing_window`
- `authorization_note`
- `contacts`

Example:

```yaml
version: 1
name: Demo Assessment
primary_domain: demo.example
base_url: https://demo.example
allowed_subdomains:
  - app.demo.example
allowed_urls:
  - https://demo.example/
  - https://demo.example/login
out_of_scope_assets:
  - admin.demo.example
login_areas_allowed:
  - /login
apis_allowed:
  - /api
tool_allowlist:
  - http-probe
  - header-review
  - tls-review
  - dns-visibility
  - robots-fetch
  - sitemap-fetch
  - route-inventory
  - tech-fingerprint
  - manual-review
  - nmap-service-discovery
rate_limits:
  max_requests_per_minute: 60
  max_concurrent_requests: 2
  delay_seconds_between_requests: 0.5
testing_window:
  start: 2026-03-22T00:00:00Z
  end: 2026-03-29T23:59:59Z
authorization_note: Authorized by the site owner for defensive assessment only.
contacts:
  - security@example.com
notes: Demo scope for local testing.
```

## Structured Tool Intelligence

Every diagnostic module returns a normalized result with:

- `tool_id`
- `target`
- `run_id`
- `scope_id`
- `timestamp`
- `status`
- `raw_output`
- `parsed_output`
- `artifacts`
- `findings_candidates`
- `next_safe_checks`
- `metadata`

Pengetic stores the raw artifacts and parsed summaries in SQLite so the planner can reason over structured evidence instead of guessing from text blobs. The correlation layer combines observations across tools into a single evidence picture for the active run.

The planner can ingest:

- service inventory
- route inventory
- TLS posture
- security header posture
- DNS visibility
- evidence correlation summaries

Supported tools currently include:

- `http-probe`
- `header-review`
- `tls-review`
- `dns-visibility`
- `robots-fetch`
- `sitemap-fetch`
- `route-inventory`
- `tech-fingerprint`
- `manual-review`
- `nmap-service-discovery`
- `approved-login-surface-probe`
- `approved-api-surface-probe`
- `approved-rate-limit-probe`

## Getting Started

### Fresh install from the GitHub source ZIP

1. Extract the release source ZIP.
2. Open a terminal in the Pengetic root directory.
3. Run the installer for your platform:

```bash
# Windows
powershell -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1

# Linux
bash ./scripts/install_linux.sh
```

The installers will:

- verify Python, pip, Node, and npm
- create `.venv`
- install the backend in editable mode
- install frontend dependencies
- build the production UI
- initialize the local workspace and SQLite database
- run `python -m pengetic doctor`
- optionally check Ollama if you pass the flag

Optional flags:

- `powershell -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1 -CheckOllama`
- `powershell -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1 -Launch -OpenBrowser`
- `bash ./scripts/install_linux.sh`
- `bash ./scripts/run_pengetic.sh`

### 1. Install the backend

```bash
pip install -e .
```

### 2. Install the frontend

```bash
cd frontend
npm install
```

### 3. Build the frontend

```bash
cd frontend
npm run build
```

This creates `frontend/dist`, which `pengetic serve` uses to serve the production UI.

### 4. Start the API server and built UI

```bash
pengetic serve
# or
python -m pengetic serve
```

Use `python -m pengetic doctor` to verify the local install, workspace, frontend build, database, and optional Ollama health.

### 5. Start the GUI in development mode

```bash
cd frontend
npm run dev
```

Use the Vite dev server only for frontend development. It proxies API calls to `http://127.0.0.1:8000`.

If `frontend/dist` is missing, `pengetic serve` will show a clear setup page instead of a blank UI. Asset routes such as `/assets/*.js` are served as static files only and never fall back to `index.html`.

### Launch wrappers

For a quick launch after install:

```bash
# Windows
pwsh -File .\scripts\run_pengetic.ps1 -OpenBrowser

# Linux
bash ./scripts/run_pengetic.sh
```

These wrappers prefer the local virtual environment if it exists and fall back to the system Python otherwise.

### Fresh-user setup

For a clean install from the GitHub source ZIP:

1. Create and activate a Python virtual environment.
2. Install the backend with `pip install -e .`.
3. Install frontend dependencies with `cd frontend && npm install`.
4. Build the production UI with `cd frontend && npm run build`.
5. Start the combined backend and UI with `python -m pengetic serve`.

If you skip the frontend build, Pengetic still starts, but it shows a setup page instead of the production dashboard.

## Installer and Doctor

Pengetic now ships with guided bootstrap scripts and a doctor command so first-time setup is repeatable:

- `scripts/install_windows.ps1`
- `scripts/install_linux.sh`
- `scripts/run_pengetic.ps1`
- `scripts/run_pengetic.sh`
- `python -m pengetic doctor`

`doctor` reports:

- Python and pip
- Node and npm
- Git and Ollama availability
- frontend build status
- workspace and SQLite readiness
- selected Ollama model and health state

The command exits non-zero when required dependencies or build outputs are missing, which makes it useful in automation.

## CLI

```bash
pengetic validate-scope examples/scope.demo.yaml
pengetic plan examples/scope.demo.yaml
pengetic approve examples/scope.demo.yaml active-login-surface-probe
pengetic run examples/scope.demo.yaml
pengetic report examples/scope.demo.yaml
pengetic serve
pengetic paths
```

## GUI Surfaces

The default navigation is intentionally simple:

1. Dashboard
2. Results
3. Approvals
4. Report
5. Settings

The dashboard follows the operator flow:

1. Target
2. Mode
3. Start
4. Results
5. Report

Advanced scope, plan, and planner details stay behind collapsible panels.

Additional operator controls include:

- one-click scope template generation
- saved model selection in Settings
- Engine Pulse health status
- reset current scope with typed confirmation
- delete current-scope runs with typed confirmation
- factory reset workspace with typed confirmation

## Persistence

Pengetic stores local state in SQLite at:

```text
data/pengetic.sqlite3
```

It also stores run artifacts and reports under:

```text
artifacts/runs/
```

The selected Ollama model is also stored in SQLite so the preferred local planner persists across restarts.

## Nmap Adapter

Pengetic includes a scope-bound Nmap diagnostic module for authorized targets only.

It:

- runs only when `nmap-service-discovery` is present in the scope tool allowlist
- captures raw XML, normal, and grepable output
- stores scan evidence as artifacts
- extracts open ports and service/version data for review
- persists parsed service inventory for planner analysis
- suggests safe next steps such as SSL configuration checks or service header review

Active diagnostic actions always remain approval-gated.

## Engine Pulse

The footer shows an Engine Pulse indicator that checks the selected Ollama model through the Ollama Tags API.

If the model is unavailable, the UI shows the last known status and the model health indicator turns to a warning state.

## Workspace Reset

Pengetic provides an administrative reset flow for local operators.

The reset:

- requires the exact confirmation string `CONFIRM_PURGE`
- clears SQLite content
- removes generated artifacts and logs
- resets scope, plan, run, and planner state
- restores the backend to a clean workspace state

There are also narrower reset actions in Settings:

- `RESET_SCOPE` clears the current scope, plan, and run link
- `DELETE_RUNS` deletes runs for the current scope only

## LLM Planner

Pengetic talks to a local Ollama instance through the OpenAI-compatible `/v1/chat/completions` API.

Environment variables:

- `OLLAMA_BASE_URL`
- `OLLAMA_MODEL`

The selected model can also be changed from the Pengetic GUI and is persisted locally.

The planner is constrained to:

- summarize findings
- explain the current run state
- recommend the next allowed step from the approved plan

## Limitations

- Pengetic is not an exploitation toolkit.
- It does not run autonomous exploit chains.
- It does not brute force, flood, or persist.
- It only operates on assets explicitly listed in scope.
- It stops when scope validation fails or the required approval is missing.

## Troubleshooting

- Blank UI: run `cd frontend && npm install && npm run build`, then restart `python -m pengetic serve`.
- Missing Node/npm: install Node.js 18+ and make sure `node` and `npm` are on `PATH`.
- Missing Python deps: create a virtual environment and run `pip install -e .`.
- Frontend not built: check that `frontend/dist/index.html` and `frontend/dist/assets/*.js` exist after the build.
- Ollama not reachable: confirm `OLLAMA_BASE_URL` is correct and that Ollama is running locally.
- Model not found: verify the selected model name with `ollama list` or check the model in the Pengetic GUI.

## Release Checklist

- Fresh install from a source ZIP works.
- `python -m pengetic doctor` passes.
- `python -m pytest -q` passes.
- `cd frontend && npm run build` passes.
- `python -m pengetic serve` loads the real UI.
- Static assets return the correct MIME type.
- The selected Ollama model and workspace paths are correct.
- Install and launch wrappers are included in the release archive.

## Documentation

- [Architecture](docs/architecture.md)
- [Risk policy](docs/risk-policy.md)
- [Audit and reporting](docs/audit-reporting.md)
- [Implementation plan](docs/implementation-plan.md)
