# Architecture

Pengetic is split into six layers:

1. Scope loading and validation.
2. Policy, risk classification, and approval gating.
3. Tool registry and passive collectors.
4. Evidence, audit logging, and findings normalization.
5. SQLite persistence and assessment state tracking.
6. FastAPI API, React GUI, and Ollama-backed planner service.

The platform is closed by default and refuses to run without a valid scope package.
