"""
AgentShield Main SDK.

The core entry point for intercepting and governing AI agent actions.
"""

import hashlib
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Optional, Type
from pydantic import BaseModel

from .core.models import (
    ActionRequest, Principal, PolicyDecision, DecisionType,
    ApprovalRequest, ApprovalStatus, AuditEvent, ToolDefinition, SensitivityLevel
)
from .core.exceptions import (
    AuthorizationDeniedError, ApprovalRequiredError, 
    IdentityVerificationError, ToolValidationError,
    AuditLoggingError, ApprovalExpiredError, ApprovalTamperError
)
from .identity.verifier import IdentityVerifier
from .tools.registry import ToolRegistry, ToolValidator
from .policy.engine import PolicyEngine


class AgentShield:
    """
    Main AgentShield SDK class.
    
    Intercepts AI agent action requests, evaluates them against policies,
    and enforces ALLOW, BLOCK, or REQUIRE_APPROVAL decisions.
    """

    def __init__(
        self,
        policy_path: str,
        jwt_secret: str,
        db_uri: str = "sqlite:///audit.db",
        approval_expiry_hours: int = 24
    ):
        """
        Initialize AgentShield.
        
        Args:
            policy_path: Path to directory containing YAML policy files.
            jwt_secret: Secret key for JWT verification.
            db_uri: Database URI for audit/approval storage.
            approval_expiry_hours: Hours before pending approvals expire.
        """
        self.jwt_secret = jwt_secret
        self.approval_expiry_hours = approval_expiry_hours
        
        # Initialize components
        self.identity_verifier = IdentityVerifier(secret_key=jwt_secret)
        self.tool_registry = ToolRegistry()
        self.tool_validator = ToolValidator(self.tool_registry)
        self.policy_engine = PolicyEngine(policy_path=policy_path)
        
        # Initialize simple in-memory stores for MVP
        # In production, these would be database-backed
        self._approvals: Dict[str, ApprovalRequest] = {}
        self._audit_log: list = []
        self._db_uri = db_uri

    def register_tool(
        self,
        name: str,
        schema: Type[BaseModel],
        executor: Callable[[Any], Any],
        description: str = "",
        sensitivity_level: SensitivityLevel = SensitivityLevel.MEDIUM
    ):
        """
        Register a protected tool.
        
        Args:
            name: Unique tool identifier.
            schema: Pydantic model for parameter validation.
            executor: Function to execute the tool.
            description: Human-readable description.
            sensitivity_level: Risk classification.
        """
        self.tool_registry.register(
            name=name,
            schema=schema,
            executor=executor,
            description=description,
            sensitivity_level=sensitivity_level
        )

    def execute(
        self,
        action: str,
        params: Dict[str, Any],
        auth_token: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Main entry point: Execute an action with full governance.
        
        Flow:
        1. Verify Identity (AuthN)
        2. Validate Tool & Parameters
        3. Evaluate Policies (AuthZ)
        4. Handle Approval if needed
        5. Write Audit Log (Sync, Fail-Closed)
        6. Execute Tool
        
        Args:
            action: Name of the tool/action.
            params: Action parameters.
            auth_token: JWT authentication token.
            context: Optional environmental context.
            
        Returns:
            Result of the tool execution.
            
        Raises:
            AuthorizationDeniedError: If action is blocked.
            ApprovalRequiredError: If human approval is needed.
            ToolValidationError: If parameters are invalid.
        """
        # Step 1: Verify Identity
        try:
            principal = self.identity_verifier.verify_token(auth_token)
        except IdentityVerificationError as e:
            # Log attempt? (Careful not to log unverified data)
            raise AuthorizationDeniedError(
                reason_code="IDENTITY_VERIFICATION_FAILED",
                message="Invalid or missing authentication"
            ) from e

        # Step 2: Validate Tool Exists and Parameters Match Schema
        try:
            validated_params = self.tool_validator.validate(action, params)
        except ToolValidationError as e:
            # Synchronous audit for validation failures on sensitive tools
            self._write_audit_sync(
                user_id=principal.user_id,
                agent_id=principal.agent_id,
                action_name=action,
                decision=DecisionType.BLOCK,
                reason_code=e.reason_code,
                params=params,
                policy_version=self.policy_engine.policy_version
            )
            raise e

        # Step 3: Create Action Request
        request = ActionRequest(
            principal=principal,
            action_name=action,
            parameters=params,
            context=context
        )

        # Step 4: Evaluate Policies
        try:
            decision = self.policy_engine.evaluate(request)
        except Exception as e:
            # Policy evaluation failure -> Fail Closed (BLOCK)
            self._write_audit_sync(
                user_id=principal.user_id,
                agent_id=principal.agent_id,
                action_name=action,
                decision=DecisionType.BLOCK,
                reason_code="POLICY_ENGINE_ERROR",
                params=params,
                policy_version=self.policy_engine.policy_version
            )
            raise AuthorizationDeniedError(
                reason_code="POLICY_EVALUATION_ERROR",
                message="Policy evaluation failed. Action blocked by default."
            ) from e

        # Step 5: Handle Decision
        if decision.decision == DecisionType.BLOCK:
            self._write_audit_sync(
                user_id=principal.user_id,
                agent_id=principal.agent_id,
                action_name=action,
                decision=DecisionType.BLOCK,
                reason_code=decision.reason_code,
                params=params,
                policy_version=decision.policy_version
            )
            raise AuthorizationDeniedError(
                reason_code=decision.reason_code,
                message=decision.message
            )

        elif decision.decision == DecisionType.REQUIRE_APPROVAL:
            # Create Approval Request
            approval_req = self._create_approval_request(
                request=request,
                approver_role=decision.required_approver_role
            )
            
            # Check if already approved (polling scenario) - lookup by hash
            existing_approval = self._approvals.get(approval_req.request_hash)
            if existing_approval and existing_approval.status == ApprovalStatus.APPROVED:
                # Already approved, proceed to execution immediately
                return self._execute_tool(action, validated_params, principal, request, decision)
            
            # Return error to caller indicating approval needed
            raise ApprovalRequiredError(
                approval_id=str(approval_req.approval_id),
                message=f"{decision.message}. Approval ID: {approval_req.approval_id}"
            )

        elif decision.decision == DecisionType.ALLOW:
            return self._execute_tool(action, validated_params, principal, request, decision)
        
        else:
            # Should not happen, but fail closed
            raise AuthorizationDeniedError(
                reason_code="UNKNOWN_DECISION",
                message="Unknown policy decision result"
            )

    def _create_approval_request(
        self, 
        request: ActionRequest, 
        approver_role: Optional[str] = None
    ) -> ApprovalRequest:
        """Create and store an approval request."""
        import json
        
        # Compute deterministic hash of the request content
        canonical = request.canonical_json()
        request_hash = hashlib.sha256(canonical.encode()).hexdigest()
        
        # Check if identical request already exists (pending or approved)
        if request_hash in self._approvals:
            existing = self._approvals[request_hash]
            if existing.status == ApprovalStatus.PENDING:
                return existing  # Return existing pending request
            elif existing.status == ApprovalStatus.APPROVED:
                # Already approved - caller will execute directly
                # Don't create a new record, just return the existing one
                return existing
        
        # Create new approval request only if no existing record
        expires_at = datetime.utcnow() + timedelta(hours=self.approval_expiry_hours)
        
        approval = ApprovalRequest(
            request_hash=request_hash,
            action_request_snapshot={
                "action": request.action_name,
                "params": request.parameters,
                "user_id": request.principal.user_id,
                "agent_id": request.principal.agent_id
            },
            status=ApprovalStatus.PENDING,
            expires_at=expires_at
        )
        
        # Store by both hash and approval_id for different lookup patterns
        self._approvals[request_hash] = approval
        self._approvals[str(approval.approval_id)] = approval
        return approval

    def _execute_tool(
        self,
        action: str,
        validated_params: BaseModel,
        principal: Principal,
        request: ActionRequest,
        decision: PolicyDecision
    ) -> Any:
        """Execute the tool after all checks pass."""
        # Get executor
        executor = self.tool_registry.get_executor(action)
        
        # Pre-execution audit (synchronous for HIGH sensitivity)
        tool_def = self.tool_registry.get_tool(action)
        if tool_def.sensitivity_level == SensitivityLevel.HIGH:
            self._write_audit_sync(
                user_id=principal.user_id,
                agent_id=principal.agent_id,
                action_name=action,
                decision=DecisionType.ALLOW,
                reason_code=decision.reason_code,
                params=request.parameters,
                policy_version=decision.policy_version
            )
        
        # Execute
        try:
            result = executor(validated_params)
        except Exception as e:
            # Execution failed
            self._write_audit_sync(
                user_id=principal.user_id,
                agent_id=principal.agent_id,
                action_name=action,
                decision=DecisionType.BLOCK,
                reason_code="EXECUTION_ERROR",
                params=request.parameters,
                policy_version=decision.policy_version
            )
            raise
        
        # Post-execution audit for non-HIGH sensitivity
        if tool_def.sensitivity_level != SensitivityLevel.HIGH:
            self._write_audit_sync(
                user_id=principal.user_id,
                agent_id=principal.agent_id,
                action_name=action,
                decision=DecisionType.ALLOW,
                reason_code=decision.reason_code,
                params=request.parameters,
                policy_version=decision.policy_version
            )
        
        return result

    def _write_audit_sync(
        self,
        user_id: str,
        agent_id: str,
        action_name: str,
        decision: DecisionType,
        reason_code: str,
        params: Dict[str, Any],
        policy_version: str,
        request_id: Optional[str] = None,
        approval_id: Optional[str] = None
    ):
        """
        Synchronously write audit event.
        Fail-closed: If this fails, sensitive actions should be blocked.
        """
        import json
        
        # Redact sensitive fields
        sensitive_fields = ['password', 'secret', 'token', 'credit_card', 'ssn']
        redacted_params = params.copy()
        redacted_list = []
        
        for key in redacted_params:
            for sensitive in sensitive_fields:
                if sensitive.lower() in key.lower():
                    redacted_params[key] = "***REDACTED***"
                    redacted_list.append(key)
                    break
        
        # Hash parameters for integrity
        param_hash = hashlib.sha256(
            json.dumps(params, sort_keys=True).encode()
        ).hexdigest()
        
        event = AuditEvent(
            user_id=user_id,
            agent_id=agent_id,
            action_name=action_name,
            decision=decision,
            policy_version=policy_version,
            parameter_hash=param_hash,
            redacted_fields=redacted_list,
            request_id=request_id,
            approval_id=approval_id
        )
        
        # In-memory storage for MVP (replace with SQLite in Phase 7)
        self._audit_log.append(event)
        
        # Simulate potential DB failure for testing
        # In real implementation: try/except around DB write
        # If exception: raise AuditLoggingError which triggers BLOCK

    def check_approval_status(self, approval_id: str) -> ApprovalStatus:
        """Check the status of an approval request."""
        for approval in self._approvals.values():
            if str(approval.approval_id) == approval_id:
                if approval.is_expired():
                    approval.status = ApprovalStatus.EXPIRED
                return approval.status
        raise ValueError(f"Approval ID not found: {approval_id}")

    def approve_request(self, approval_id: str, approver_id: str) -> bool:
        """Approve a pending request."""
        for approval in self._approvals.values():
            if str(approval.approval_id) == approval_id:
                if not approval.can_transition_to(ApprovalStatus.APPROVED):
                    return False
                approval.status = ApprovalStatus.APPROVED
                approval.approver_id = approver_id
                approval.decided_at = datetime.utcnow()
                return True
        return False

    def reject_request(self, approval_id: str, approver_id: str) -> bool:
        """Reject a pending request."""
        for approval in self._approvals.values():
            if str(approval.approval_id) == approval_id:
                if not approval.can_transition_to(ApprovalStatus.REJECTED):
                    return False
                approval.status = ApprovalStatus.REJECTED
                approval.approver_id = approver_id
                approval.decided_at = datetime.utcnow()
                return True
        return False

    def get_pending_approvals(self) -> list:
        """Get all pending approvals."""
        return [
            a for a in self._approvals.values() 
            if a.status == ApprovalStatus.PENDING and not a.is_expired()
        ]

    def get_audit_logs(self) -> list:
        """Get all audit logs."""
        return self._audit_log
