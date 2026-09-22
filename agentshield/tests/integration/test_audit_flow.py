"""Integration tests for fail-closed, sanitized audit logging."""

import pytest
from unittest.mock import patch, MagicMock
from uuid import UUID

from agentshield.core.models import DecisionType
from agentshield.core.exceptions import (
    AuditLoggingError,
    AuthorizationDeniedError,
    ApprovalRequiredError
)
from tests.conftest import create_token


class TestAuditFlow:
    """Tests verifying audit logging completeness, redaction, and fail-closed guarantees."""

    def test_successful_action_creates_audit_event(self, shield):
        """Successful sensitive action must create an audit log with policy version and request ID."""
        token = create_token(user_id="alice", agent_id="agent_1")
        params = {
            "amount": 5000,
            "recipient": "Supplier Co",
            "account_number": "1234567890"
        }

        shield.execute(
            action="transfer_money",
            params=params,
            auth_token=token
        )

        logs = shield.get_audit_logs(limit=10)
        assert len(logs) >= 1
        latest = logs[0]

        assert latest.user_id == "alice"
        assert latest.agent_id == "agent_1"
        assert latest.action_name == "transfer_money"
        assert latest.decision == DecisionType.ALLOW
        assert latest.policy_version != ""
        assert latest.request_id is not None
        assert latest.parameter_hash != ""

    def test_blocked_action_creates_audit_event(self, shield):
        """Blocked actions must create an audit event recording the block decision."""
        token = create_token(user_id="eve", agent_id="rogue_agent")

        with pytest.raises(AuthorizationDeniedError):
            shield.execute(
                action="export_customer_data",
                params={},
                auth_token=token
            )

        logs = shield.get_audit_logs(limit=10)
        assert len(logs) >= 1
        blocked_log = logs[0]

        assert blocked_log.user_id == "eve"
        assert blocked_log.agent_id == "rogue_agent"
        assert blocked_log.action_name == "export_customer_data"
        assert blocked_log.decision == DecisionType.BLOCK
        assert blocked_log.policy_version != ""

    def test_approval_execution_records_approval_id(self, shield):
        """Approval execution audit event must record both request_id and approval_id."""
        token = create_token(user_id="carol", agent_id="agent_2")
        params = {
            "amount": 15000,
            "recipient": "Large Vendor",
            "account_number": "1234567890"
        }

        # Trigger approval
        with pytest.raises(ApprovalRequiredError) as exc_info:
            shield.execute(action="transfer_money", params=params, auth_token=token)

        approval_id = exc_info.value.approval_id
        shield.approve_request(approval_id, approver_id="manager_dan")

        # Execute approved request
        shield.execute(
            action="transfer_money",
            params=params,
            auth_token=token,
            approval_id=approval_id
        )

        logs = shield.get_audit_logs(limit=10)
        approved_log = next((l for l in logs if l.approval_id == UUID(approval_id)), None)

        assert approved_log is not None
        assert approved_log.decision == DecisionType.ALLOW
        assert approved_log.request_id is not None
        assert approved_log.approval_id == UUID(approval_id)

    def test_sensitive_parameters_not_stored_in_plaintext(self, shield):
        """Parameters must only be recorded as hashes; never stored in plaintext in the audit table."""
        token = create_token()
        params = {
            "amount": 3000,
            "recipient": "Secret Partner",
            "account_number": "1234567890"
        }

        shield.execute(action="transfer_money", params=params, auth_token=token)

        # Inspect SQLite row directly
        with shield.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 1")
            row = cursor.fetchone()

            # Ensure plaintext account number or recipient is NOT anywhere in raw SQL columns
            for col in row.keys():
                col_val = str(row[col])
                assert "1234567890" not in col_val
                assert "Secret Partner" not in col_val

            # Parameter hash is present
            assert row["parameter_hash"] is not None
            assert len(row["parameter_hash"]) == 64  # SHA-256 hex length

    def test_audit_database_failure_prevents_sensitive_execution(self, shield):
        """
        FAIL-CLOSED REQUIREMENT: If the audit store fails, execution of sensitive
        actions MUST be prevented before the gateway/executor is called.
        """
        token = create_token()
        params = {
            "amount": 1000,
            "recipient": "Dave",
            "account_number": "1234567890"
        }

        # Mock audit_store.save_audit_event to simulate a database failure
        with patch.object(
            shield.audit_store,
            "save_audit_event",
            side_effect=AuditLoggingError("Simulated disk/DB write failure")
        ):
            # Also mock gateway_executor.execute to ensure it is NEVER reached
            with patch.object(shield.gateway_executor, "execute") as mock_exec:
                with pytest.raises(AuditLoggingError, match="Simulated disk/DB write failure"):
                    shield.execute(
                        action="transfer_money",
                        params=params,
                        auth_token=token
                    )

                # Tool MUST NOT have executed
                mock_exec.assert_not_called()
