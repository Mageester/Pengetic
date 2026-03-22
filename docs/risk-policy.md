# Risk Policy

Pengetic uses four risk classes:

- `PASSIVE_SAFE`
- `LOW_RISK_ACTIVE`
- `HIGH_RISK_ACTIVE`
- `FORBIDDEN`

Passive-safe actions can run automatically. Active actions require explicit approval for the exact action id and scope fingerprint. Forbidden actions never execute.

The approval queue in the GUI only exposes non-passive actions, and the state machine moves the assessment between `idle`, `scope_uploaded`, `plan_ready`, `running`, `awaiting_approval`, `completed`, and `failed`.
