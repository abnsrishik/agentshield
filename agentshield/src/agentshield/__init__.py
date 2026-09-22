"""
AgentShield - An independent authorization and governance enforcement layer for autonomous AI agents.
"""

from .shield import AgentShield
from .core import (
    Principal,
    ActionRequest,
    PolicyDecision,
    ToolDefinition,
    ApprovalRequest,
    AuditEvent,
    DecisionType,
    ApprovalStatus,
    SensitivityLevel,
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
from .identity import IdentityVerifier
from .tools import ToolRegistry, ToolValidator
from .policy import PolicyEngine

__version__ = "0.1.0"
__author__ = "AgentShield Team"

__all__ = [
    # Main SDK
    "AgentShield",
    # Core Models
    "Principal",
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
    # Components
    "IdentityVerifier",
    "ToolRegistry",
    "ToolValidator",
    "PolicyEngine",
]
