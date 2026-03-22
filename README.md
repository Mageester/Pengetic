# ScopeGuard

ScopeGuard is an authorized-only defensive web assessment framework. It is designed for user-owned targets or sites with explicit written permission, and it fails closed if no valid scope package is supplied.

## What It Does

- Validates a versioned YAML scope package before any assessment work starts.
- Classifies every action by risk.
- Executes only `PASSIVE_SAFE` actions automatically.
- Records approvals for active validation steps.
- Writes redacted audit logs and evidence artifacts.
- Generates a Markdown report with findings and remediation guidance.

## Who It Is For

- Security engineers running authorized web assessments.
- Internal red-team or AppSec teams working under a signed rules-of-engagement.
- Portfolio or lab projects that need a safe-by-default assessment scaffold.

## Safety Model

The framework is closed by default.

| Risk class | Behavior |
| --- | --- |
| `PASSIVE_SAFE` | Runs automatically if the tool is allowed by scope. |
| `LOW_RISK_ACTIVE` | Requires explicit per-action approval. |
| `HIGH_RISK_ACTIVE` | Requires explicit per-action approval and should be used sparingly. |
| `FORBIDDEN` | Never executed. |

The framework does not include brute force, destructive testing, exploit delivery, persistence, or evasion features.

## Repository Layout

```text
src/scopeguard/
  cli.py
  engine.py
  config.py
  runtime.py
  scope/
  policy/
  tools/
  evidence/
  findings/
  reporting/
tests/
docs/
examples/scope.demo.yaml
artifacts/
```

## How It Works

1. Load and validate the scope package.
2. Build a plan from the scope and the built-in tool registry.
3. Run only passive-safe actions unless an active step has an approval record.
4. Write evidence, audit logs, and a report into the assessment workspace.
5. Use the report to review findings and decide whether follow-up approval is needed.

## Scope Package

The scope package is a YAML file with explicit host and route boundaries.

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

### Example Scope YAML

```yaml
version: 1
name: Demo Assessment
primary_domain: demo.example
base_url: https://demo.example
allowed_subdomains:
  - www.demo.example
  - app.demo.example
allowed_urls:
  - https://demo.example/
  - https://demo.example/login
  - https://app.demo.example/dashboard
out_of_scope_assets:
  - admin.demo.example
  - billing.vendor.example
login_areas_allowed:
  - /login
  - /signin
apis_allowed:
  - /api
  - /graphql
tool_allowlist:
  - header-review
  - tls-review
  - robots-fetch
  - sitemap-fetch
  - route-inventory
  - tech-fingerprint
  - manual-review
  - approved-login-surface-probe
  - approved-api-surface-probe
  - approved-rate-limit-probe
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

## Risk Classification

ScopeGuard uses the same four risk classes everywhere: plan generation, approvals, execution, and reporting.

- `PASSIVE_SAFE`: read-only checks like header review, robots.txt, sitemap.xml, route inventory, TLS posture, and passive fingerprinting.
- `LOW_RISK_ACTIVE`: gated steps that are expected to be low impact but still require approval.
- `HIGH_RISK_ACTIVE`: gated steps that could trigger controls or create side effects.
- `FORBIDDEN`: never run.

## Approval Gate

Active actions are stored in the plan as deferred steps. They do not run until an approval record exists for the exact action id and scope fingerprint.

Approval records include:

- action id
- scope fingerprint
- approver
- approval time
- note
- risk class

## Audit Logging

Every run produces append-only JSONL audit events. Evidence files and logs are redacted before being written.

Captured metadata includes:

- timestamp
- run id
- action id
- tool id
- risk class
- decision reason
- execution outcome
- artifact references

## Report Template

The Markdown report includes:

- Executive summary
- Scope confirmation
- Methodology
- Findings
- Execution summary
- Evidence
- Limitations
- Run metadata

## CLI

```bash
scopeguard validate-scope examples/scope.demo.yaml
scopeguard plan examples/scope.demo.yaml
scopeguard run examples/scope.demo.yaml
scopeguard approve examples/scope.demo.yaml active-login-surface-probe
scopeguard report examples/scope.demo.yaml
```

### Profiles

- `passive-only`: run passive actions only.
- `report-only`: suppress execution and use the reporting path.
- `lab-safe`: allow approved active stubs in addition to passive work.

## Implementation Plan

1. Scaffold the package, scope validator, policy gate, and workspace layout.
2. Add passive collectors and the tool registry.
3. Add approval storage, audit logging, findings normalization, and report rendering.
4. Add tests, demo scope data, and documentation.

## Limitations

- The framework is not an exploitation toolkit.
- Active steps are stubs unless approved tooling is added later.
- The framework only operates on assets that are explicitly listed in scope.
- It stops immediately if scope validation fails.

