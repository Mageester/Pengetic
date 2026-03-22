# Pengetic

Pengetic is a local-first defensive web assessment platform for authorized security work. It combines a scope-gated assessment engine, a FastAPI backend, a React + Tailwind GUI, SQLite persistence, and a local Ollama-backed planner service.

It is built to stay closed by default:

- no scope, no run
- no active action without approval
- no destructive testing
- no brute force, credential attacks, persistence, or evasion
- no unrestricted shell access for the LLM

## What Pengetic Does

- Validates a versioned YAML scope package before work begins.
- Builds a risk-labelled assessment plan from the validated scope.
- Executes passive-safe checks automatically.
- Queues active checks for explicit approval.
- Persists runs, approvals, findings, logs, artifacts, and reports in SQLite.
- Renders a dark security-operations GUI for reviewing scope, plans, live runs, approvals, and reports.
- Uses a local Ollama service to summarize assessment state and propose the next allowed step.

## Architecture

Pengetic is split into these layers:

1. Scope validation and policy gating.
2. Assessment planning and approval handling.
3. Passive tool execution and evidence capture.
4. SQLite persistence and run state tracking.
5. FastAPI API and React GUI.
6. Optional local LLM planning through Ollama.

The existing assessment engine is reused internally. The V2 platform adds a backend, a frontend, and a persistent workflow around it.

## Repository Layout

```text
src/pengetic/        FastAPI backend, CLI, state machine, storage, LLM planner
src/scopeguard/      Legacy assessment engine reused internally by Pengetic
frontend/            React + Tailwind GUI
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
  - header-review
  - tls-review
  - robots-fetch
  - sitemap-fetch
  - route-inventory
  - tech-fingerprint
  - manual-review
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

## Getting Started

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
```

### 5. Start the GUI in development mode

```bash
cd frontend
npm run dev
```

Use the Vite dev server only for frontend development. It proxies API calls to `http://127.0.0.1:8000`.

If `frontend/dist` is missing, `pengetic serve` will show a clear setup page instead of a blank UI. Asset routes such as `/assets/*.js` are served as static files only and never fall back to `index.html`.

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

The web UI is organized into seven views:

1. Assessment dashboard
2. Scope upload and validation
3. Plan viewer with risk labels
4. Live run view with logs, evidence, and findings
5. Approval queue for gated actions
6. Report viewer and export
7. Planner panel for the Ollama-backed suggestion service

## Persistence

Pengetic stores local state in SQLite at:

```text
data/pengetic.sqlite3
```

It also stores run artifacts and reports under:

```text
artifacts/runs/
```

## LLM Planner

Pengetic talks to a local Ollama instance through the OpenAI-compatible `/v1/chat/completions` API.

Environment variables:

- `OLLAMA_BASE_URL`
- `OLLAMA_MODEL`

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

## Documentation

- [Architecture](docs/architecture.md)
- [Risk policy](docs/risk-policy.md)
- [Audit and reporting](docs/audit-reporting.md)
- [Implementation plan](docs/implementation-plan.md)
