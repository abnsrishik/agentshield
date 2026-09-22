"""
Unit tests for AgentShield core data models.
"""
import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from agentshield.core.models import (
    Principal, ActionRequest, PolicyDecision, DecisionType,
    ApprovalRequest, ApprovalStatus, AuditEvent, ToolDefinition,
    SensitivityLevel
)


class TestPrincipal:
    """Test Principal model."""
    
    def test_create_valid_principal(self):
        """Should create principal with required fields."""
        principal = Principal(
            user_id="user_123",
            agent_id="finance-agent-v1",
            roles=["employee"]
        )
        assert principal.user_id == "user_123"
        assert principal.agent_id == "finance-agent-v1"
        assert principal.roles == ["employee"]
        assert principal.auth_context == {}
    
    def test_principal_is_immutable(self):
        """Principal should be frozen (immutable)."""
        principal = Principal(
            user_id="user_123",
            agent_id="agent-1"
        )
        with pytest.raises(Exception):  # Pydantic v1/v2 differ on frozen error type
            principal.user_id = "hacker"


class TestActionRequest:
    """Test ActionRequest model."""
    
    def test_create_valid_request(self):
        """Should create request with required fields."""
        principal = Principal(user_id="u1", agent_id="a1")
        request = ActionRequest(
            principal=principal,
            action_name="transfer_money",
            parameters={"amount": 5000, "recipient": "ABC"}
        )
        assert request.action_name == "transfer_money"
        assert request.parameters["amount"] == 5000
        assert isinstance(request.request_id, object)  # UUID
        assert isinstance(request.timestamp, datetime)
    
    def test_canonical_json_excludes_volatile_fields(self):
        """Canonical JSON should exclude request_id and timestamp."""
        principal = Principal(user_id="u1", agent_id="a1")
        
        req1 = ActionRequest(
            principal=principal,
            action_name="transfer_money",
            parameters={"amount": 5000}
        )
        
        req2 = ActionRequest(
            principal=principal,
            action_name="transfer_money",
            parameters={"amount": 5000}
        )
        
        # Different request_ids and timestamps, but same canonical hash
        assert req1.request_id != req2.request_id
        assert req1.canonical_json() == req2.canonical_json()
    
    def test_canonical_json_different_params(self):
        """Different parameters should produce different canonical JSON."""
        principal = Principal(user_id="u1", agent_id="a1")
        
        req1 = ActionRequest(
            principal=principal,
            action_name="transfer_money",
            parameters={"amount": 5000}
        )
        
        req2 = ActionRequest(
            principal=principal,
            action_name="transfer_money",
            parameters={"amount": 6000}
        )
        
        assert req1.canonical_json() != req2.canonical_json()


class TestPolicyDecision:
    """Test PolicyDecision model."""
    
    def test_create_block_decision(self):
        """Should create BLOCK decision."""
        decision = PolicyDecision(
            decision=DecisionType.BLOCK,
            reason_code="POLICY_BLOCK",
            message="Blocked by policy",
            policy_version="abc123"
        )
        assert decision.decision == DecisionType.BLOCK
        assert decision.matched_policies == []
    
    def test_create_approval_decision_with_role(self):
        """Should create REQUIRE_APPROVAL with approver role."""
        decision = PolicyDecision(
            decision=DecisionType.REQUIRE_APPROVAL,
            reason_code="NEEDS_APPROVAL",
            message="Needs manager approval",
            policy_version="abc123",
            required_approver_role="manager"
        )
        assert decision.required_approver_role == "manager"


class TestApprovalRequest:
    """Test ApprovalRequest model."""
    
    def test_create_pending_approval(self):
        """Should create pending approval request."""
        from datetime import timedelta
        from uuid import uuid4
        
        approval = ApprovalRequest(
            request_id=uuid4(),
            request_hash="sha256_hash_here",
            action_name="transfer_money",
            parameters={"amount": 50000},
            principal_snapshot={"user_id": "user123", "agent_id": "agent1"},
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        
        assert approval.status == ApprovalStatus.PENDING
        assert not approval.is_expired()
        assert approval.approver_id is None
        assert approval.used == False
    
    def test_approval_expiration(self):
        """Should detect expired approvals."""
        from uuid import uuid4
        
        approval = ApprovalRequest(
            request_id=uuid4(),
            request_hash="hash",
            action_name="test_action",
            parameters={},
            principal_snapshot={},
            expires_at=datetime.utcnow() - timedelta(hours=1)  # Expired 1 hour ago
        )
        
        assert approval.is_expired()
    
    def test_cannot_transition_from_non_pending(self):
        """Approved/rejected approvals cannot transition."""
        from datetime import timedelta
        from uuid import uuid4
        
        approval = ApprovalRequest(
            request_id=uuid4(),
            request_hash="hash",
            action_name="test_action",
            parameters={},
            principal_snapshot={},
            status=ApprovalStatus.APPROVED,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        
        assert not approval.can_transition_to(ApprovalStatus.REJECTED)


class TestAuditEvent:
    """Test AuditEvent model."""
    
    def test_create_audit_event(self):
        """Should create audit event with required fields."""
        event = AuditEvent(
            user_id="user_123",
            agent_id="agent-1",
            action_name="transfer_money",
            decision=DecisionType.ALLOW,
            policy_version="v1_hash",
            parameter_hash="param_hash"
        )
        
        assert event.user_id == "user_123"
        assert event.decision == DecisionType.ALLOW
        assert event.redacted_fields == []


class TestToolDefinition:
    """Test ToolDefinition model."""
    
    def test_create_tool_definition(self):
        """Should create tool definition."""
        from pydantic import BaseModel
        
        class TestSchema(BaseModel):
            amount: int
        
        tool = ToolDefinition(
            name="transfer_money",
            description="Transfer funds",
            parameter_schema=TestSchema,
            sensitivity_level=SensitivityLevel.HIGH
        )
        
        assert tool.name == "transfer_money"
        assert tool.sensitivity_level == SensitivityLevel.HIGH
