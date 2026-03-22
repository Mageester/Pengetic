# Architecture

ScopeGuard is split into five layers:

1. Scope loading and validation.
2. Policy, risk classification, and approval gating.
3. Tool registry and passive collectors.
4. Evidence, audit logging, and findings normalization.
5. Markdown reporting and CLI orchestration.

The framework is closed by default and refuses to run without a valid scope package.

