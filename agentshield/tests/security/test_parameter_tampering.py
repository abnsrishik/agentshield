"""Security tests: Parameter tampering detection post-approval."""

import pytest
from agentshield.core.exceptions import (
    ApprovalRequiredError,
    ApprovalTamperError,
    AuthorizationDeniedError
)
from tests.conftest import create_token


class TestParameterTamperingSecurity:
    """Tests verifying cryptographic request_hash integrity binding."""

    @pytest.fixture
    def approved_transfer(self, shield):
        """Helper to create and approve a standard transfer."""
        token = create_token(user_id="user_original", agent_id="agent_original")
        original_params = {
            "amount": 20000,
            "recipient": "Legitimate Vendor",
            "account_number": "1234567890"
        }

        with pytest.raises(ApprovalRequiredError) as exc_info:
            shield.execute(
                action="transfer_money",
                params=original_params,
                auth_token=token
            )

        approval_id = exc_info.value.approval_id
        shield.approve_request(approval_id, approver_id="manager_frank")

        return {
            "token": token,
            "params": original_params,
            "approval_id": approval_id
        }

    def test_tampered_amount_after_approval_blocked(self, shield, approved_transfer):
        """Modifying the transfer amount after human approval must be blocked as tampering."""
        tampered_params = approved_transfer["params"].copy()
        tampered_params["amount"] = 99000  # Tampered: increased amount

        with pytest.raises(ApprovalTamperError, match="Potential tampering detected"):
            shield.execute(
                action="transfer_money",
                params=tampered_params,
                auth_token=approved_transfer["token"],
                approval_id=approved_transfer["approval_id"]
            )

    def test_tampered_recipient_after_approval_blocked(self, shield, approved_transfer):
        """Modifying the recipient after human approval must be blocked as tampering."""
        tampered_params = approved_transfer["params"].copy()
        tampered_params["recipient"] = "Attacker Account"  # Tampered: changed recipient

        with pytest.raises(ApprovalTamperError, match="Potential tampering detected"):
            shield.execute(
                action="transfer_money",
                params=tampered_params,
                auth_token=approved_transfer["token"],
                approval_id=approved_transfer["approval_id"]
            )

    def test_tampered_account_number_after_approval_blocked(self, shield, approved_transfer):
        """Modifying the account number after human approval must be blocked as tampering."""
        tampered_params = approved_transfer["params"].copy()
        tampered_params["account_number"] = "0987654321"  # Tampered: changed account

        with pytest.raises(ApprovalTamperError, match="Potential tampering detected"):
            shield.execute(
                action="transfer_money",
                params=tampered_params,
                auth_token=approved_transfer["token"],
                approval_id=approved_transfer["approval_id"]
            )

    def test_tampered_user_identity_after_approval_blocked(self, shield, approved_transfer):
        """Executing with a different user identity than the one approved must be blocked."""
        # Create token for a different user
        different_user_token = create_token(user_id="user_impostor", agent_id="agent_original")

        with pytest.raises(ApprovalTamperError, match="Potential tampering detected"):
            shield.execute(
                action="transfer_money",
                params=approved_transfer["params"],
                auth_token=different_user_token,
                approval_id=approved_transfer["approval_id"]
            )

    def test_tampered_agent_identity_after_approval_blocked(self, shield, approved_transfer):
        """Executing with a different agent ID than the one approved must be blocked."""
        # Create token for a different agent
        different_agent_token = create_token(user_id="user_original", agent_id="rogue_agent")

        with pytest.raises(ApprovalTamperError, match="Potential tampering detected"):
            shield.execute(
                action="transfer_money",
                params=approved_transfer["params"],
                auth_token=different_agent_token,
                approval_id=approved_transfer["approval_id"]
            )
