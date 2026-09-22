"""
AgentShield Core Data Models.

These Pydantic models define the strict data structures used throughout the SDK.
They ensure type safety, validation, and consistent serialization for auditing.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class DecisionType(str, Enum):
    """Possible outcomes of a policy evaluation."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ApprovalStatus(str, Enum):
    """Status of a human approval request."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class SensitivityLevel(str, Enum):
    """Sensitivity classification for tools and data."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Principal(BaseModel):
    """
    Represents a verified actor after authentication.
    Trust Level: High (Created internally after JWT verification).
    Never contains raw tokens.
    """
    user_id: str = Field(..., description="Unique user identifier")
    roles: List[str] = Field(default_factory=list, description="User roles e.g. ['employee', 'manager']")
    agent_id: str = Field(..., description="Verified ID of the agent software")
    auth_context: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Metadata like auth_method, issued_at"
    )

    class Config:
        frozen = True  # Immutable once created


class AgentIdentity(BaseModel):
    """Specific metadata about the AI agent instance."""
    agent_id: str = Field(..., description="Registered ID")
    version: Optional[str] = Field(None, description="Agent version")
    capabilities: List[str] = Field(default_factory=list, description="Allowed tool categories")


class ActionRequest(BaseModel):
    """
    The standardized request to perform an action.
    All fields are required and validated.
    """
    request_id: UUID = Field(default_factory=uuid4, description="Unique per attempt")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Request time")
    principal: Principal = Field(..., description="Verified identity")
    action_name: str = Field(..., description="Target tool name")
    parameters: Dict[str, Any] = Field(..., description="Validated arguments")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Environmental data")

    def canonical_json(self) -> str:
        """Generate a deterministic JSON string for hashing."""
        import json
        # Sort keys to ensure deterministic hash
        data = {
            "action_name": self.action_name,
            "parameters": self.parameters,
            "user_id": self.principal.user_id,
            "agent_id": self.principal.agent_id,
            # Exclude volatile fields like timestamp and request_id from the hash
            # that binds the human approval to the *content* of the request
        }
        return json.dumps(data, sort_keys=True, separators=(',', ':'))


class PolicyDecision(BaseModel):
    """The outcome of the policy evaluation."""
    decision: DecisionType
    reason_code: str = Field(..., description="Machine-readable reason")
    message: str = Field(..., description="Human-readable explanation")
    matched_policies: List[str] = Field(default_factory=list, description="IDs of triggered policies")
    policy_version: str = Field(..., description="Hash of the policy set used")
    required_approver_role: Optional[str] = Field(None, description="Role needed for approval")


class ToolDefinition(BaseModel):
    """Definition of a protected tool."""
    name: str
    description: str = ""
    parameter_schema: Any = Field(..., description="Pydantic model class for validation")
    sensitivity_level: SensitivityLevel = SensitivityLevel.MEDIUM
    endpoint: Optional[str] = Field(None, description="URL/Path to Protected Tool Gateway")


class ApprovalRequest(BaseModel):
    """
    Immutable record of a pending approval.
    
    Security Properties:
    - approval_id: Unique identity for the approval flow (primary key).
    - request_hash: Integrity binding to the exact action parameters.
    - used: One-time execution flag to prevent replay attacks.
    """
    approval_id: UUID = Field(default_factory=uuid4)
    request_id: UUID = Field(..., description="Links to the original ActionRequest")
    request_hash: str = Field(..., description="SHA-256 of canonical action request for integrity")
    action_name: str
    parameters: Dict[str, Any]
    principal_snapshot: Dict[str, Any]  # Serialized principal for audit
    status: ApprovalStatus = ApprovalStatus.PENDING
    approver_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    decided_at: Optional[datetime] = None
    used: bool = False  # Critical: Prevents replay attacks

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def can_transition_to(self, new_status: ApprovalStatus) -> bool:
        if self.status != ApprovalStatus.PENDING:
            return False
        if self.is_expired():
            return False
        return new_status in [ApprovalStatus.APPROVED, ApprovalStatus.REJECTED]


class AuditEvent(BaseModel):
    """Compliance log event."""
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: str
    agent_id: str
    action_name: str
    decision: DecisionType
    policy_version: str
    parameter_hash: str  # Hash of params (no raw sensitive data)
    redacted_fields: List[str] = Field(default_factory=list)
    request_id: Optional[UUID] = None
    approval_id: Optional[UUID] = None
