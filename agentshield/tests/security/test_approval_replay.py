"""Security tests: Approval replay prevention and race condition mitigation."""

import pytest
from concurrent.futures import ThreadPoolExecutor, as_completed

from agentshield.core.exceptions import (
    ApprovalRequiredError,
    AuthorizationDeniedError,
    ToolExecutionError
)
from tests.conftest import create_token


class TestApprovalReplaySecurity:
    """Tests verifying one-time use semantics and concurrency safety of approvals."""

    def test_single_use_approval_replay_blocked(self, shield):
        """
        An approval ID can only be consumed once.
        Subsequent execution attempts with the same approval ID must be blocked.
        """
        token = create_token()
        params = {
            "amount": 15000,
            "recipient": "Contractor Ltd",
            "account_number": "1234567890"
        }

        # Step 1: Trigger approval requirement
        with pytest.raises(ApprovalRequiredError) as exc_info:
            shield.execute(action="transfer_money", params=params, auth_token=token)

        approval_id = exc_info.value.approval_id

        # Step 2: Manager approves
        shield.approve_request(approval_id, approver_id="manager_dan")

        # Step 3: First execution succeeds
        result1 = shield.execute(
            action="transfer_money",
            params=params,
            auth_token=token,
            approval_id=approval_id
        )
        assert result1["status"] == "success"

        # Step 4: Replay attempt with same approval ID must be blocked immediately
        with pytest.raises(AuthorizationDeniedError, match="already been consumed"):
            shield.execute(
                action="transfer_money",
                params=params,
                auth_token=token,
                approval_id=approval_id
            )

    def test_concurrent_consumption_race_condition(self, shield):
        """
        Concurrent execution attempts with the same approval ID:
        Only ONE thread may succeed; all other concurrent attempts must be blocked.
        """
        token = create_token()
        params = {
            "amount": 20000,
            "recipient": "Race Condition Vendor",
            "account_number": "1234567890"
        }

        # Request and approve
        with pytest.raises(ApprovalRequiredError) as exc_info:
            shield.execute(action="transfer_money", params=params, auth_token=token)

        approval_id = exc_info.value.approval_id
        shield.approve_request(approval_id, approver_id="manager_eve")

        successes = []
        failures = []

        def attempt_execution():
            try:
                res = shield.execute(
                    action="transfer_money",
                    params=params,
                    auth_token=token,
                    approval_id=approval_id
                )
                return ("SUCCESS", res)
            except AuthorizationDeniedError as e:
                return ("DENIED", e.reason_code)
            except Exception as e:
                return ("ERROR", str(e))

        # Launch 5 concurrent execution attempts
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(attempt_execution) for _ in range(5)]
            for future in as_completed(futures):
                status, outcome = future.result()
                if status == "SUCCESS":
                    successes.append(outcome)
                else:
                    failures.append(outcome)

        # EXACTLY one execution must succeed
        assert len(successes) == 1, f"Expected 1 success, got {len(successes)}"
        assert len(failures) == 4
        for fail_reason in failures:
            assert fail_reason in ("APPROVAL_ALREADY_USED", "APPROVAL_CONSUMPTION_FAILED")

    def test_reusing_request_id_with_different_params_at_gateway_rejected(self, gateway_executor):
        """Gateway must reject request_id reuse when parameters differ."""
        req_id = "replay-attempt-key-100"
        params_orig = {"amount": 500, "recipient": "Alice", "account_number": "1234567890"}
        params_tampered = {"amount": 9999, "recipient": "Attacker", "account_number": "1234567890"}

        # First request succeeds
        res1 = gateway_executor.execute("transfer_money", params_orig, request_id=req_id)
        assert res1["status"] == "success"

        # Replay with different params must fail with conflict
        with pytest.raises(ToolExecutionError, match="Request ID conflict"):
            gateway_executor.execute("transfer_money", params_tampered, request_id=req_id)
