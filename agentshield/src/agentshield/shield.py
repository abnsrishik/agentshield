"""
AgentShield Main SDK.

The core entry point for intercepting and governing AI agent actions.
"""

import hashlib
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Optional, Type
from pydantic import BaseModel
from uuid import UUID

from .core.models import (
    ActionRequest, Principal, PolicyDecision, DecisionType,
    ApprovalRequest, ApprovalStatus, AuditEvent, ToolDefinition, SensitivityLevel
)
from .core.exceptions import (
    AuthorizationDeniedError, ApprovalRequiredError, 
    IdentityVerificationError, ToolValidationError,
    AuditLoggingError, ApprovalStorageError, ApprovalExpiredError, ApprovalTamperError
)
from .identity.verifier import IdentityVerifier
from .tools.registry import ToolRegistry, ToolValidator
from .policy.engine import PolicyEngine
from .storage.database import DatabaseManager, ApprovalStore, AuditStore


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
        db_uri: str = "sqlite:///agentshield.db",
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
        
        # Load policies - fail closed if this fails
        try:
            self.policy_engine = PolicyEngine(policy_path=policy_path)
        except Exception as e:
            raise RuntimeError(f"Failed to load policies: {e}") from e
        
        # Initialize persistent storage
        self.db_manager = DatabaseManager(db_uri.replace("sqlite:///", ""))
        self.approval_store = ApprovalStore(self.db_manager)
        self.audit_store = AuditStore(self.db_manager)

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
        context: Optional[Dict[str, Any]] = None,
        approval_id: Optional[str] = None  # For retrying after approval
    ) -> Any:
        """
        Main entry point: Execute an action with full governance.
        
        Flow:
        1. Verify Identity (AuthN)
        2. Validate Tool & Parameters
        3. Evaluate Policies (AuthZ)
        4. Handle Approval if needed (or verify existing approval)
        5. Write Audit Log (Sync, Fail-Closed)
        6. Mark Approval as Used (if applicable)
        7. Execute Tool
        
        Args:
            action: Name of the tool/action.
            params: Action parameters.
            auth_token: JWT authentication token.
            context: Optional environmental context.
            approval_id: Optional approval ID for retry after approval.
            
        Returns:
            Result of the tool execution.
            
        Raises:
            AuthorizationDeniedError: If action is blocked.
            ApprovalRequiredError: If human approval is needed.
            ToolValidationError: If parameters are invalid.
            ApprovalTamperError: If request doesn't match approved hash.
        """
        # Step 1: Verify Identity
        try:
            principal = self.identity_verifier.verify_token(auth_token)
        except IdentityVerificationError as e:
            raise AuthorizationDeniedError(
                reason_code="IDENTITY_VERIFICATION_FAILED",
                message="Invalid or missing authentication"
            ) from e

        # Step 2: Validate Tool Exists and Parameters Match Schema
        try:
            validated_params = self.tool_validator.validate(action, params)
        except ToolValidationError as e:
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
            return self._handle_approval_flow(
                request=request,
                validated_params=validated_params,
                principal=principal,
                decision=decision,
                provided_approval_id=approval_id
            )

        elif decision.decision == DecisionType.ALLOW:
            return self._execute_tool_after_checks(
                action=action,
                validated_params=validated_params,
                principal=principal,
                request=request,
                decision=decision
            )
        
        else:
            # Should not happen, but fail closed
            raise AuthorizationDeniedError(
                reason_code="UNKNOWN_DECISION",
                message="Unknown policy decision result"
            )

    def _handle_approval_flow(
        self,
        request: ActionRequest,
        validated_params: BaseModel,
        principal: Principal,
        decision: PolicyDecision,
        provided_approval_id: Optional[str] = None
    ) -> Any:
        """
        Handle the approval workflow with proper hash binding and replay prevention.
        
        If provided_approval_id is given, verify it exists and is approved.
        Otherwise, create a new pending approval request.
        """
        import json
        
        # Compute deterministic hash of the request content
        canonical = request.canonical_json()
        request_hash = hashlib.sha256(canonical.encode()).hexdigest()
        
        # Case 1: Retrying with an approval ID
        if provided_approval_id:
            try:
                approval_uuid = UUID(provided_approval_id)
            except ValueError:
                raise ApprovalTamperError(
                    reason_code="INVALID_APPROVAL_ID",
                    message="Invalid approval ID format"
                )
            
            # Retrieve approval from database
            approval = self.approval_store.get_approval(approval_uuid)
            
            if not approval:
                raise AuthorizationDeniedError(
                    reason_code="APPROVAL_NOT_FOUND",
                    message="Approval request not found"
                )
            
            # Verify approval is approved
            if approval.status != ApprovalStatus.APPROVED:
                if approval.is_expired():
                    raise ApprovalExpiredError(
                        reason_code="APPROVAL_EXPIRED",
                        message="Approval request has expired"
                    )
                raise ApprovalRequiredError(
                    approval_id=provided_approval_id,
                    message=f"Approval still pending. ID: {provided_approval_id}"
                )
            
            # SECURITY CRITICAL: Verify request hash matches approved hash
            if approval.request_hash != request_hash:
                raise ApprovalTamperError(
                    reason_code="REQUEST_HASH_MISMATCH",
                    message="Request parameters do not match approved request. Potential tampering detected."
                )
            
            # Verify approval hasn't been used (one-time use)
            if approval.used:
                raise AuthorizationDeniedError(
                    reason_code="APPROVAL_ALREADY_USED",
                    message="This approval has already been consumed. Replays are not allowed."
                )
            
            # Mark as used atomically BEFORE execution
            if not self.approval_store.mark_approval_used(approval_uuid):
                raise AuthorizationDeniedError(
                    reason_code="APPROVAL_CONSUMPTION_FAILED",
                    message="Failed to mark approval as used. Possible concurrent access."
                )
            
            # Write audit log synchronously
            self._write_audit_sync(
                user_id=principal.user_id,
                agent_id=principal.agent_id,
                action_name=request.action_name,
                decision=DecisionType.ALLOW,
                reason_code="APPROVAL_GRANTED",
                params=request.parameters,
                policy_version=decision.policy_version,
                request_id=str(request.request_id),
                approval_id=provided_approval_id
            )
            
            # Execute tool
            return self._execute_tool_after_checks(
                action=request.action_name,
                validated_params=validated_params,
                principal=principal,
                request=request,
                decision=decision
            )
        
        # Case 2: Create new approval request
        # Check if identical request already exists in DB (by hash)
        existing_by_request = self.approval_store.get_approval_by_request_id(request.request_id)
        if existing_by_request and existing_by_request.status == ApprovalStatus.PENDING:
            # Return existing pending approval
            raise ApprovalRequiredError(
                approval_id=str(existing_by_request.approval_id),
                message=f"{decision.message}. Approval ID: {existing_by_request.approval_id}"
            )
        
        # Create new approval record
        expires_at = datetime.utcnow() + timedelta(hours=self.approval_expiry_hours)
        
        approval = ApprovalRequest(
            request_id=request.request_id,
            request_hash=request_hash,
            action_name=request.action_name,
            parameters=request.parameters,
            principal_snapshot={
                "user_id": request.principal.user_id,
                "agent_id": request.principal.agent_id,
                "roles": request.principal.roles
            },
            status=ApprovalStatus.PENDING,
            expires_at=expires_at
        )
        
        # Save to database
        self.approval_store.save_approval(approval)
        
        # Return error indicating approval needed
        raise ApprovalRequiredError(
            approval_id=str(approval.approval_id),
            message=f"{decision.message}. Approval ID: {approval.approval_id}"
        )
    
    def _execute_tool_after_checks(
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
                policy_version=decision.policy_version,
                request_id=str(request.request_id)
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
                policy_version=decision.policy_version,
                request_id=str(request.request_id)
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
                policy_version=decision.policy_version,
                request_id=str(request.request_id)
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
        Raises AuditLoggingError on failure.
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
        
        # Parse UUIDs if strings provided
        req_uuid = UUID(request_id) if request_id else None
        appr_uuid = UUID(approval_id) if approval_id else None
        
        event = AuditEvent(
            user_id=user_id,
            agent_id=agent_id,
            action_name=action_name,
            decision=decision,
            policy_version=policy_version,
            parameter_hash=param_hash,
            redacted_fields=redacted_list,
            request_id=req_uuid,
            approval_id=appr_uuid
        )
        
        # Write to SQLite database - fail closed on error
        try:
            self.audit_store.save_audit_event(event)
        except AuditLoggingError as e:
            # Re-raise to trigger blocking behavior
            raise e
        except Exception as e:
            raise AuditLoggingError(f"Audit logging failed: {e}") from e

    def check_approval_status(self, approval_id: str) -> ApprovalStatus:
        """Check the status of an approval request."""
        try:
            approval_uuid = UUID(approval_id)
        except ValueError:
            raise ValueError(f"Invalid approval ID format: {approval_id}")
        
        approval = self.approval_store.get_approval(approval_uuid)
        if not approval:
            raise ValueError(f"Approval ID not found: {approval_id}")
        
        if approval.is_expired():
            return ApprovalStatus.EXPIRED
        return approval.status

    def approve_request(self, approval_id: str, approver_id: str) -> bool:
        """Approve a pending request via admin interface."""
        try:
            approval_uuid = UUID(approval_id)
        except ValueError:
            return False
        
        approval = self.approval_store.get_approval(approval_uuid)
        if not approval:
            return False
        
        if not approval.can_transition_to(ApprovalStatus.APPROVED):
            return False
        
        # Update status atomically (not marking as used yet - that happens on execution)
        return self.approval_store.update_approval_status(
            approval_id=approval_uuid,
            status=ApprovalStatus.APPROVED,
            approver_id=approver_id,
            used=False  # Marked as used only during execution
        )

    def reject_request(self, approval_id: str, approver_id: str) -> bool:
        """Reject a pending request via admin interface."""
        try:
            approval_uuid = UUID(approval_id)
        except ValueError:
            return False
        
        approval = self.approval_store.get_approval(approval_uuid)
        if not approval:
            return False
        
        if not approval.can_transition_to(ApprovalStatus.REJECTED):
            return False
        
        return self.approval_store.update_approval_status(
            approval_id=approval_uuid,
            status=ApprovalStatus.REJECTED,
            approver_id=approver_id,
            used=False
        )

    def get_pending_approvals(self) -> list:
        """Get all pending approvals."""
        return self.approval_store.get_pending_approvals()

    def get_audit_logs(self, limit: int = 100, offset: int = 0) -> list:
        """Get audit logs with pagination."""
        return self.audit_store.get_audit_events(limit=limit, offset=offset)
