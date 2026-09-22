"""
AgentShield Custom Exceptions.
"""


class AgentShieldError(Exception):
    """Base exception for all AgentShield errors."""
    pass


class AuthorizationDeniedError(AgentShieldError):
    """Raised when an action is blocked by policy."""
    def __init__(self, reason_code: str, message: str):
        self.reason_code = reason_code
        self.message = message
        super().__init__(message)


class ApprovalRequiredError(AgentShieldError):
    """Raised when an action requires human approval."""
    def __init__(self, approval_id: str, message: str):
        self.approval_id = approval_id
        self.message = message
        super().__init__(message)


class IdentityVerificationError(AuthorizationDeniedError):
    """Raised when identity verification fails."""
    pass


class ToolValidationError(AuthorizationDeniedError):
    """Raised when tool parameters fail schema validation."""
    pass


class PolicyEvaluationError(AgentShieldError):
    """Raised when policy evaluation fails (e.g., parsing error)."""
    pass


class AuditLoggingError(AgentShieldError):
    """Raised when audit logging fails."""
    pass


class ApprovalExpiredError(AuthorizationDeniedError):
    """Raised when an approval request has expired."""
    pass


class ApprovalTamperError(AuthorizationDeniedError):
    """Raised when request parameters do not match approved hash."""
    pass
