class ScopeGuardError(Exception):
    """Base class for ScopeGuard exceptions."""


class ScopeValidationError(ScopeGuardError):
    """Raised when a scope package fails validation."""


class PolicyError(ScopeGuardError):
    """Raised when a policy or approval gate blocks an action."""


class ExecutionError(ScopeGuardError):
    """Raised when a tool or run cannot be executed safely."""

