"""
AgentShield Core Module.
"""

from .models import (
    Principal,
    AgentIdentity,
    ActionRequest,
    PolicyDecision,
    ToolDefinition,
    ApprovalRequest,
    AuditEvent,
    DecisionType,
    ApprovalStatus,
    SensitivityLevel,
)
from .exceptions import (
    AgentShieldError,
    AuthorizationDeniedError,
    ApprovalRequiredError,
    IdentityVerificationError,
    ToolValidationError,
    PolicyEvaluationError,
    AuditLoggingError,
    ApprovalExpiredError,
    ApprovalTamperError,
)

__all__ = [
    # Models
    "Principal",
    "AgentIdentity",
    "ActionRequest",
    "PolicyDecision",
    "ToolDefinition",
    "ApprovalRequest",
    "AuditEvent",
    "DecisionType",
    "ApprovalStatus",
    "SensitivityLevel",
    # Exceptions
    "AgentShieldError",
    "AuthorizationDeniedError",
    "ApprovalRequiredError",
    "IdentityVerificationError",
    "ToolValidationError",
    "PolicyEvaluationError",
    "AuditLoggingError",
    "ApprovalExpiredError",
    "ApprovalTamperError",
]
