class PengeticError(Exception):
    """Base class for Pengetic exceptions."""


class ScopeValidationError(PengeticError):
    """Raised when a scope package fails validation."""


class PolicyError(PengeticError):
    """Raised when a policy or approval gate blocks an action."""


class ExecutionError(PengeticError):
    """Raised when a tool or run cannot be executed safely."""
