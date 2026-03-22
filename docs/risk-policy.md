# Risk Policy

ScopeGuard uses four risk classes:

- `PASSIVE_SAFE`
- `LOW_RISK_ACTIVE`
- `HIGH_RISK_ACTIVE`
- `FORBIDDEN`

Passive-safe actions can run automatically. Active actions require explicit approval for the exact action id and scope fingerprint. Forbidden actions never execute.

