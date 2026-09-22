"""Integration tests for the human-in-the-loop approval lifecycle."""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from agentshield.core.models import ApprovalStatus
from agentshield.core.exceptions import (
    ApprovalRequiredError,
    AuthorizationDeniedError,
    ApprovalExpiredError,
    ApprovalTamperError
)
from tests.conftest import create_token


class TestApprovalFlow:
    """Full lifecycle tests for human approval workflow."""

    def test_approval_lifecycle_happy_path(self, shield):
        """
        1. Large transfer triggers REQUIRE_APPROVAL.
        2. Verify pending approval in SQLite.
        3. Manager approves request.
        4. Retrying with approved approval_id executes successfully via gateway.
        """
        token = create_token()
        params = {
            "amount": 25000,
            "recipient": "Major Supplier Ltd",
            "account_number": "1234567890"
        }

        # Step 1: Initial attempt requires approval
        with pytest.raises(ApprovalRequiredError) as exc_info:
            shield.execute(
                action="transfer_money",
                params=params,
                auth_token=token
            )

        approval_id = exc_info.value.approval_id
        assert approval_id is not None

        # Step 2: Verify status is PENDING in persistent storage
        status = shield.check_approval_status(approval_id)
        assert status == ApprovalStatus.PENDING

        # Step 3: Manager approves the request
        approved = shield.approve_request(approval_id, approver_id="manager_alice")
        assert approved is True
        assert shield.check_approval_status(approval_id) == ApprovalStatus.APPROVED

        # Step 4: Retry execution with exact parameters and approval_id
        result = shield.execute(
            action="transfer_money",
            params=params,
            auth_token=token,
            approval_id=approval_id
        )

        assert result["status"] == "success"
        assert result["amount"] == 25000
        assert result["recipient"] == "Major Supplier Ltd"

    def test_rejected_approval_blocks_execution(self, shield):
        """
        If human rejects an approval request, execution must be blocked upon retry.
        """
        token = create_token()
        params = {
            "amount": 50000,
            "recipient": "Untrusted Vendor",
            "account_number": "1234567890"
        }

        with pytest.raises(ApprovalRequiredError) as exc_info:
            shield.execute(action="transfer_money", params=params, auth_token=token)

        approval_id = exc_info.value.approval_id

        # Manager rejects
        rejected = shield.reject_request(approval_id, approver_id="manager_bob")
        assert rejected is True
        assert shield.check_approval_status(approval_id) == ApprovalStatus.REJECTED

        # Retry must be denied
        with pytest.raises(ApprovalRequiredError):
            shield.execute(
                action="transfer_money",
                params=params,
                auth_token=token,
                approval_id=approval_id
            )

    def test_retry_while_still_pending_re_raises_approval_required(self, shield):
        """
        Retrying before human approval has been granted should re-raise ApprovalRequiredError.
        """
        token = create_token()
        params = {
            "amount": 15000,
            "recipient": "Vendor A",
            "account_number": "1234567890"
        }

        with pytest.raises(ApprovalRequiredError) as exc_info:
            shield.execute(action="transfer_money", params=params, auth_token=token)

        approval_id = exc_info.value.approval_id

        # Retry immediately without approval
        with pytest.raises(ApprovalRequiredError, match="Approval still pending"):
            shield.execute(
                action="transfer_money",
                params=params,
                auth_token=token,
                approval_id=approval_id
            )

    def test_expired_approval_blocks_execution(self, shield):
        """
        An approval that has passed its expiration time must be blocked.
        """
        token = create_token()
        params = {
            "amount": 20000,
            "recipient": "Vendor B",
            "account_number": "1234567890"
        }

        with pytest.raises(ApprovalRequiredError) as exc_info:
            shield.execute(action="transfer_money", params=params, auth_token=token)

        approval_id = exc_info.value.approval_id
        shield.approve_request(approval_id, approver_id="manager_carol")

        # Manually expire the approval in the database
        with shield.db_manager.get_connection() as conn:
            past_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
            conn.execute(
                "UPDATE approvals SET expires_at = ? WHERE approval_id = ?",
                (past_time, approval_id)
            )
            conn.commit()

        # Attempt to execute with expired approval
        with pytest.raises(ApprovalExpiredError, match="Approval request has expired"):
            shield.execute(
                action="transfer_money",
                params=params,
                auth_token=token,
                approval_id=approval_id
            )

    def test_invalid_and_nonexistent_approval_ids(self, shield):
        """
        Invalid UUID format or non-existent approval IDs must be blocked.
        """
        token = create_token()
        params = {
            "amount": 20000,
            "recipient": "Vendor C",
            "account_number": "1234567890"
        }

        # Non-UUID string
        with pytest.raises(ApprovalTamperError, match="Invalid approval ID format"):
            shield.execute(
                action="transfer_money",
                params=params,
                auth_token=token,
                approval_id="not-a-valid-uuid"
            )

        # Random non-existent UUID
        random_id = str(uuid4())
        with pytest.raises(AuthorizationDeniedError, match="Approval request not found"):
            shield.execute(
                action="transfer_money",
                params=params,
                auth_token=token,
                approval_id=random_id
            )
